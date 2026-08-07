#!/usr/bin/env python3
"""Static conformance check for migrated verify.sh files.

The four gates prove a verifier BEHAVES correctly on one host. They cannot see
structural faults that only bite elsewhere -- an `exit` left inside a check
still works until the check happens to fail, and a verifier with no regression
checks gates green while silently sitting outside the collateral-damage
denominator forever.

Checks, in rough order of severity:

  no-guard          missing/incorrect library source line
  bare-exit         `exit` inside a check -> reintroduces fail-fast, and the
                    component that is never reached becomes unmeasurable again
  no-finish         no verify_finish -> no summary record -> the scenario is
                    silently dropped from every two-component metric
  after-finish      code after verify_finish (unreachable; usually a leftover)
  no-poc            zero poc checks -> cannot state the vulnerability is closed
  no-reg            zero regression checks -> can never witness collateral
                    damage; scorer excludes it from the CDR pool
  syntax            `bash -n` failure

Usage:
    python scripts/lint_verifiers.py                 # every migrated verifier
    python scripts/lint_verifiers.py ccdc vulnhub    # only these suites
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SUITES = ["ccdc", "meta2", "meta3", "meta4", "vulnhub"]

GUARD = re.compile(
    r'\[\s*-n\s*"\$\{_SYSREPAIR_VERIFYLIB_LOADED:-\}"\s*\]\s*\|\|\s*\.\s'
)
# Deliberately UNANCHORED. Several verifiers route every check through a
# dispatcher -- `case "$kind" in poc) record_poc "$cid" "$ok" "$detail" ;;` --
# so anchoring to line start saw zero poc calls and reported `no-poc` on files
# that emit them for every check. Static analysis cannot tell whether a
# dispatcher branch is ever REACHED, so treat these two flags as advisory: the
# runtime `poc_total` / `reg_total` in the gate summary is the ground truth.
RECORD = re.compile(r"(?<![\w-])record_(poc|reg)(_cmd)?\b")
# `exit` that is not one of the sanctioned forms.
BARE_EXIT = re.compile(r"^\s*exit\b(?!\s*\$?\{?(PASS|FAIL|NOT_APPLICABLE)\b)", re.M)

# The library exports PASS=0 / FAIL=1 / NOT_APPLICABLE=42 and verify_finish
# does `exit $PASS`. A verifier that reuses one of those names for its own value
# silently changes the script's exit code -- meta4/scenario-116 held an rsync
# PASSWORD in $PASS, so a successful run would have exited with the password as
# its status. Found by hand once; this makes it impossible to reintroduce.
_EXPECTED = {"PASS": "0", "FAIL": "1", "NOT_APPLICABLE": "42"}
CLOBBER = re.compile(r"^\s*(PASS|FAIL|NOT_APPLICABLE)=(\S*)", re.M)


def find_bash() -> str | None:
    for c in (shutil.which("bash"),
              r"C:\Program Files\Git\bin\bash.exe"):
        if c and "system32" not in c.lower() and Path(c).exists():
            return c
    for p in Path.home().glob("scoop/apps/git/*/usr/bin/bash.exe"):
        return str(p)
    return None


BASH = find_bash()


def shell_level_only(text: str) -> str:
    """Blank out embedded-interpreter regions before scanning for shell `exit`.

    Verifiers routinely embed perl/python: `perl -e '... exit(1) ...'` or
    `python3 - <<'EOF' ... EOF`. Those exits terminate the SUBPROCESS and are
    correct. Counting them as shell-level fail-fast produces false positives,
    and a lint that cries wolf gets ignored -- which costs more than the check
    is worth.

    Blanks single-quoted spans and heredoc bodies, preserving line numbering.
    """
    out, i, n = [], 0, len(text)
    heredoc_tag = None
    for line in text.splitlines(keepends=True):
        if heredoc_tag is not None:
            out.append("\n" if line.strip() != heredoc_tag else line)
            if line.strip() == heredoc_tag:
                heredoc_tag = None
            continue
        m = re.search(r"<<-?\s*'?\"?([A-Za-z_][A-Za-z0-9_]*)'?\"?", line)
        if m:
            heredoc_tag = m.group(1)
            out.append(line)
            continue
        # Blank single-quoted spans on this line (perl -e '...' etc.).
        out.append(re.sub(r"'[^']*'", "''", line))
    stripped = "".join(out)

    # Multi-line single-quoted spans (perl -e ' ... ' across lines).
    result, inside = [], False
    for line in stripped.splitlines(keepends=True):
        if inside:
            result.append("\n")
            if line.count("'") % 2 == 1:
                inside = False
            continue
        if line.count("'") % 2 == 1:
            inside = True
            result.append(line.split("'", 1)[0] + "\n")
            continue
        result.append(line)
    return "".join(result)


def lint(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    problems: list[str] = []

    if not GUARD.search(text):
        problems.append("no-guard")

    body = text
    idx = text.find("verify_finish")
    if idx < 0:
        problems.append("no-finish")
    else:
        # Only the region before verify_finish may contain checks; anything
        # after the final call is unreachable.
        last = text.rfind("verify_finish")
        tail = text[last + len("verify_finish"):]
        if re.search(r"^\s*[^\s#]", tail, re.M):
            problems.append("after-finish")
        body = text[:last]

    if BARE_EXIT.search(shell_level_only(body)):
        # skip_not_applicable legitimately exits; it is a function call, not
        # a literal `exit`, so it is not matched above.
        problems.append("bare-exit")

    for m in CLOBBER.finditer(shell_level_only(text)):
        name, val = m.group(1), m.group(2).strip('"\'')
        if val != _EXPECTED[name]:
            problems.append(f"clobbers-${name}")

    kinds = Counter(m.group(1) for m in RECORD.finditer(text))
    if not kinds.get("poc"):
        problems.append("no-poc")
    if not kinds.get("reg"):
        problems.append("no-reg")

    if BASH:
        r = subprocess.run([BASH, "-n", str(path)], capture_output=True, text=True)
        if r.returncode != 0:
            problems.append("syntax")

    return problems


def main() -> None:
    wanted = sys.argv[1:] or SUITES
    files = []
    for s in wanted:
        files.extend(p for p in (REPO / s).rglob("verify.sh"))
    migrated = [f for f in sorted(files)
                if "verifylib" in f.read_text(encoding="utf-8", errors="replace")]

    print(f"migrated verifiers checked: {len(migrated)}")
    if BASH is None:
        print("  (no non-WSL bash found -- syntax check skipped)")

    bad, tally = {}, Counter()
    for f in migrated:
        probs = lint(f)
        if probs:
            bad[f.relative_to(REPO).as_posix()] = probs
            tally.update(probs)

    if not bad:
        print("\nALL CLEAN")
        return

    print(f"\n{len(bad)} with findings:\n")
    for rel, probs in sorted(bad.items()):
        print(f"  {rel:44s} {', '.join(probs)}")
    print(f"\nby type: {dict(tally.most_common())}")
    # no-reg is informational: it means the scenario cannot contribute to CDR,
    # which is sometimes legitimate. Everything else is a defect.
    hard = sum(v for k, v in tally.items() if k != "no-reg")
    sys.exit(1 if hard else 0)


if __name__ == "__main__":
    main()

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
SUITES = ["ccdc", "meta2", "meta3", "meta4", "vulnhub", "hivestorm"]

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
PWSH = shutil.which("powershell.exe")


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


PS_GUARD = re.compile(r"if\s*\(\s*-not\s+\$global:SysRepairVerifyLibLoaded\s*\)\s*\{\s*\.")
PS_RECORD = re.compile(r"(?<![\w-])Record-(Poc|Reg)(Cmd)?\b", re.I)
# PowerShell's only sanctioned exits are inside the library (Complete-Verify,
# Skip-NotApplicable). A literal `exit` in a verifier body is fail-fast.
PS_BARE_EXIT = re.compile(r"^\s*exit\b", re.M | re.I)
# $ErrorActionPreference='Stop' turns any failing cmdlet into a terminating
# error. That is fail-fast with no `exit` in sight: the script dies, no summary
# is emitted, and both components are lost. It has no shell-library analogue and
# is the most likely way a migrated Windows verifier silently regresses to v1.
PS_EAP_STOP = re.compile(r"\$ErrorActionPreference\s*=\s*['\"]Stop['\"]", re.I)
# Cmdlets that throw under Stop unless given -ErrorAction SilentlyContinue.
PS_THROWERS = re.compile(
    r"(?<![\w-])(Get-Item|Get-ItemProperty|Get-Content|Get-Service|Get-Process|"
    r"Get-ChildItem|Get-LocalUser|Get-LocalGroupMember|Get-ScheduledTask|"
    r"Get-WmiObject|Get-CimInstance|Invoke-WebRequest|Test-NetConnection|"
    r"Get-SmbServerConfiguration|Get-WindowsFeature|Resolve-DnsName)\b", re.I)


def ps_quoted_blank(text: str) -> str:
    """Blank single- and double-quoted spans, preserving line numbering."""
    out = []
    for line in text.splitlines(keepends=True):
        line = re.sub(r"'[^']*'", "''", line)
        line = re.sub(r'"[^"]*"', '""', line)
        out.append(line)
    return "".join(out)


def lint_ps1(path: Path) -> list[str]:
    """PowerShell counterpart of lint(). Same findings, PowerShell spellings."""
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    problems: list[str] = []

    if not PS_GUARD.search(text):
        problems.append("no-guard")

    body = text
    if "Complete-Verify" not in text:
        problems.append("no-finish")
    else:
        last = text.rfind("Complete-Verify")
        tail = text[last + len("Complete-Verify"):]
        if re.search(r"^\s*[^\s#]", tail, re.M):
            problems.append("after-finish")
        body = text[:last]

    scrubbed = ps_quoted_blank(body)
    if PS_BARE_EXIT.search(scrubbed):
        problems.append("bare-exit")

    # Advisory, not a defect: a scenario may legitimately use Stop and guard
    # every risky call. Flagged so a human looks, because static analysis cannot
    # prove a given cmdlet is reachable in a failing state.
    if PS_EAP_STOP.search(text):
        risky = [m.group(1) for m in PS_THROWERS.finditer(scrubbed)]
        guarded = len(re.findall(r"-ErrorAction\s+SilentlyContinue", scrubbed, re.I))
        guarded += len(re.findall(r"(?<![\w-])(try|Record-\w+Cmd)\b", scrubbed, re.I))
        if risky and guarded < len(risky):
            problems.append(f"eap-stop-unguarded({len(risky)-guarded})")

    kinds = Counter(m.group(1).lower() for m in PS_RECORD.finditer(text))
    if not kinds.get("poc"):
        problems.append("no-poc")
    if not kinds.get("reg"):
        problems.append("no-reg")

    if PWSH:
        r = subprocess.run(
            [PWSH, "-NoProfile", "-Command",
             "$e=$null;[System.Management.Automation.Language.Parser]::ParseFile("
             f"'{path}',[ref]$null,[ref]$e)|Out-Null;if($e){{exit 1}};exit 0"],
            capture_output=True, text=True)
        if r.returncode != 0:
            problems.append("syntax")

    return problems


def _syntax_only(path: Path) -> list[str]:
    """Parse check alone, for files that are not migrated and so skip lint()."""
    if path.suffix == ".ps1":
        if not PWSH:
            return []
        r = subprocess.run(
            [PWSH, "-NoProfile", "-Command",
             "$e=$null;[System.Management.Automation.Language.Parser]::ParseFile("
             f"'{path}',[ref]$null,[ref]$e)|Out-Null;if($e){{exit 1}};exit 0"],
            capture_output=True, text=True)
        return ["syntax"] if r.returncode != 0 else []
    if not BASH:
        return []
    r = subprocess.run([BASH, "-n", str(path)], capture_output=True, text=True)
    return ["syntax"] if r.returncode != 0 else []


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
        files.extend(p for p in (REPO / s).rglob("verify.ps1"))
    migrated = [f for f in sorted(files)
                if "verifylib" in f.read_text(encoding="utf-8", errors="replace")]

    n_ps = sum(1 for f in migrated if f.suffix == ".ps1")
    print(f"migrated verifiers checked: {len(migrated)}/{len(files)} "
          f"({len(migrated) - n_ps} sh, {n_ps} ps1)")

    # Report the denominator. This filters to files that already contain the
    # library, so an UNMIGRATED verifier is invisible here by construction --
    # which is how ten hivestorm Linux verifiers sat outside the migration while
    # this printed "256, ALL CLEAN". A tool that only counts what it already
    # accepts cannot tell you what it is missing, so say so explicitly.
    unmigrated = [f for f in sorted(files) if f not in set(migrated)]
    if unmigrated:
        print(f"\nNOT MIGRATED ({len(unmigrated)}) -- outside every "
              f"two-component metric:")
        for f in unmigrated:
            print(f"  {f.relative_to(REPO).as_posix()}")

    # Syntax-check EVERY verifier, migrated or not. Three verify.ps1 files sat in
    # the repo unable to parse at all -- em-dashes in a BOM-less file read as
    # cp1252 -- and were never caught because they were unmigrated and this tool
    # only looked at migrated ones. A verifier that cannot be parsed does not
    # grade an agent, it errors, and that is worse than any finding below.
    broken = [f for f in unmigrated if "syntax" in _syntax_only(f)]
    if broken:
        print(f"\nDOES NOT PARSE ({len(broken)}) -- these cannot grade anything:")
        for f in broken:
            print(f"  {f.relative_to(REPO).as_posix()}")
    if BASH is None:
        print("  (no non-WSL bash found -- sh syntax check skipped)")
    if PWSH is None:
        print("  (no powershell.exe found -- ps1 syntax check skipped)")

    bad, tally = {}, Counter()
    for f in migrated:
        probs = lint_ps1(f) if f.suffix == ".ps1" else lint(f)
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

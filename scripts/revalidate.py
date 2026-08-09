#!/usr/bin/env python3
"""Re-validate the corpus through the four gates, one scenario at a time.

WHY THIS AND NOT validate.py
----------------------------
The old validator answered a binary question ("does verify.sh exit 1 then 0?")
and answered it under a sandbox production does not use -- it granted
`--cap-add NET_ADMIN` to every container unconditionally, so any scenario whose
remediation needs netfilter validated green and was unsolvable in the real eval.
That is fixed, but the whole record it produced needs regenerating.

This sweep runs the SAME gate runner used to verify each migration, so one pass
re-establishes all of:
  * baseline is genuinely vulnerable       (row 1)
  * the reference fix genuinely solves it  (row 2, the oracle ceiling)
  * whether the scenario can express collateral damage (rows 3-4)

SERIAL ON PURPOSE. Concurrent gates produced rows that reversed on isolated
re-runs -- containers contend, and `docker exec` returns 137 under load. Two
hours of trustworthy results beat forty minutes of results nobody can cite.

Resumable: re-running skips scenarios already recorded, so a crash or a reboot
costs only the scenario in flight.

Usage:
    python scripts/revalidate.py                  # every migrated scenario
    python scripts/revalidate.py ccdc vulnhub     # only these suites
    python scripts/revalidate.py --fresh          # ignore previous results
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PY = REPO / "inspect_eval" / ".venv" / "Scripts" / "python.exe"
OUT = REPO / "docs" / "revalidation-results.json"

ROW = re.compile(
    r"^(baseline / no-op|reference fix|fix \+ service killed|service killed only)"
    r"\s+(\S+)\s+(\S+)\s+(\S+)"
)


def migrated_scenarios(suites: list[str]) -> list[str]:
    """Scenarios carrying the two-component protocol, in manifest order.

    meta2 is skipped wholesale: it cannot build on this host at all, so gating it
    would record 40 build failures that say nothing about the scenarios.
    """
    out = []
    for line in (REPO / "scenarios.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rel = json.loads(line)["path"].replace("\\", "/")
        if rel.startswith("meta2/"):
            continue
        if suites and not any(rel.startswith(s) for s in suites):
            continue
        v = REPO / rel / "verify.sh"
        if not v.exists():
            continue
        if "verifylib" not in v.read_text(encoding="utf-8", errors="replace"):
            continue
        out.append(rel)
    return out


def run_one(rel: str) -> dict:
    t0 = time.time()
    try:
        p = subprocess.run(
            [str(PY), "scripts/verify_gates.py", rel],
            cwd=REPO, capture_output=True, text=True, timeout=2700,
        )
        stdout = p.stdout
    except subprocess.TimeoutExpired:
        return {"scenario": rel, "verdict": "TIMEOUT", "rows": {},
                "elapsed": round(time.time() - t0, 1)}

    rows, verdict, notes = {}, "UNKNOWN", []
    for line in stdout.splitlines():
        m = ROW.match(line.strip())
        if m:
            rows[m.group(1)] = {"security": m.group(2),
                                "regression": m.group(3), "exit": m.group(4)}
        s = line.strip()
        if s.startswith("VERDICT:"):
            verdict = s.split(":", 1)[1].strip()
        for tag in ("CDR-ELIGIBLE", "NOT CDR-ELIGIBLE", "BROKEN BASELINE",
                    "ORACLE DISAGREEMENT", "MISCLASSIFIED CHECK",
                    "SERVICE-KILLER PASSES", "VACUOUS REGRESSION",
                    "NO REGRESSION COMPONENT", "NO REFERENCE SOLUTION", "[warn]"):
            if s.startswith(tag) or tag == "[warn]" and "[warn]" in s:
                notes.append(tag)
    return {"scenario": rel, "verdict": verdict, "rows": rows,
            "notes": sorted(set(notes)), "elapsed": round(time.time() - t0, 1)}


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    fresh = "--fresh" in sys.argv

    done: dict[str, dict] = {}
    if OUT.exists() and not fresh:
        done = {r["scenario"]: r for r in json.loads(OUT.read_text(encoding="utf-8"))}

    todo = migrated_scenarios(args)
    pending = [s for s in todo if s not in done]
    print(f"{len(todo)} migrated scenarios; {len(done)} already recorded; "
          f"{len(pending)} to run\n", flush=True)

    for i, rel in enumerate(pending, 1):
        r = run_one(rel)
        done[rel] = r
        OUT.write_text(json.dumps(list(done.values()), indent=2), encoding="utf-8")
        flag = "" if r["verdict"] == "PASS" else "   <-- "
        print(f"[{i}/{len(pending)}] {rel:34s} {r['verdict']:12s} "
              f"{r['elapsed']:>6.0f}s {','.join(r['notes'])}{flag}", flush=True)

    rows = [done[s] for s in todo if s in done]
    print("\n=== SUMMARY ===")
    print(Counter(r["verdict"] for r in rows).most_common())
    elig = sum(1 for r in rows if "CDR-ELIGIBLE" in r["notes"])
    print(f"CDR-eligible: {elig} / {len(rows)}")
    bad = [r for r in rows if r["verdict"] != "PASS"]
    if bad:
        print(f"\nnot PASS ({len(bad)}):")
        for r in bad:
            print(f"  {r['scenario']:34s} {r['verdict']:12s} {','.join(r['notes'])}")
    print(f"\nwritten to {OUT}")


if __name__ == "__main__":
    main()

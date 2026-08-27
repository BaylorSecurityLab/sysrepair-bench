#!/usr/bin/env python3
"""Pre- vs post-cutoff contamination split on sr-modern (plan item E).

The question
------------
meta2 predates every model's knowledge cutoff, so a high score there cannot
distinguish remediation SKILL from a memorised fix. sr-modern spans 2018-2026, so
splitting its scenarios by CVE disclosure year gives a within-suite contrast:
if scores collapse on post-cutoff vulnerabilities, the pre-cutoff numbers are
carrying memorisation.

What it does NOT do
-------------------
This is a natural experiment, not a randomised one, and three things limit it.
All three are printed with the result rather than buried:

1. **Datability.** Only scenarios carrying a CVE id can be dated. On sr-modern
   that is 64 of 117; the other 53 are configuration-hardening scenarios with no
   CVE. They are excluded, not silently pooled into either arm.
2. **Confounding.** Post-cutoff CVEs are not a random sample of pre-cutoff ones.
   We print the severity mix of each arm so a reader can see whether the arms are
   comparable; a difference in severity is an alternative explanation for any
   difference in score.
3. **One cutoff for all models.** Providers publish different (and vague) cutoffs.
   A single split date is a simplification; `--cutoff` makes it explicit and
   `--by-year` shows the whole curve so the result is not an artifact of where
   one line was drawn.

Usage::

    python3 panelB/contamination.py                 # default cutoff 2024
    python3 panelB/contamination.py --cutoff 2023
    python3 panelB/contamination.py --by-year
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sysrepair_bench.stats import Observation, bootstrap_ci  # noqa: E402

CACHE = Path("scratchpad/samples_cache.jsonl")
SCENARIOS = Path("../scenarios.jsonl")


def cve_year(rec: dict) -> int | None:
    """Latest CVE year for a scenario, or None if it carries no CVE id."""
    years = [
        int(m.group(1))
        for c in (rec.get("cves") or [])
        if (m := re.match(r"CVE-(\d{4})-", c or ""))
    ]
    return max(years) if years else None


def _prefix_pass(outcomes: list[bool], k: int) -> float:
    """Absorbing success; budget-exhausted episodes are failures (see passk.py)."""
    first = next((i + 1 for i, o in enumerate(outcomes) if o), None)
    return 1.0 if (first is not None and first <= k) else 0.0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cutoff", type=int, default=2024,
                    help="CVE year >= cutoff counts as POST-cutoff (default 2024)")
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--by-year", action="store_true",
                    help="also print the per-year curve, so the result is not an "
                         "artifact of where the split was drawn")
    args = ap.parse_args()

    meta = {}
    severity = {}
    for line in SCENARIOS.open():
        r = json.loads(line)
        suite = r.get("suite", "")
        if not suite.startswith("meta4") or "ad-vm" in suite:
            continue
        sid = r.get("scenario_id", "")
        meta[sid] = cve_year(r)
        severity[sid] = r.get("severity")
        # scenario ids appear in logs without the suite prefix too
        meta[sid.split("/")[-1]] = meta[sid]
        severity[sid.split("/")[-1]] = r.get("severity")

    datable = sum(1 for v in meta.values() if v is not None) // 2
    undatable = sum(1 for v in meta.values() if v is None) // 2

    # deduped episodes, sr-modern only
    episodes: dict[tuple, dict] = {}
    for line in CACHE.open():
        r = json.loads(line)
        if r.get("benchmark") != "meta4" or not r.get("outcomes"):
            continue
        if r.get("not_applicable"):
            continue
        key = (r["model"], r["solver"], r["mode"],
               r.get("scenario_id"), r.get("epoch"))
        prev = episodes.get(key)
        if prev is None or r["log_path"] >= prev["log_path"]:
            episodes[key] = r

    cells: dict[tuple, dict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for (model, _solver, mode, sid, _ep), r in episodes.items():
        cells[(model, mode)][sid].append(_prefix_pass(r["outcomes"], args.k))

    print(f"sr-modern contamination split — POST = CVE year >= {args.cutoff}")
    print(f"datable scenarios: {datable}   undatable (no CVE id): {undatable} "
          f"— EXCLUDED, not pooled\n")
    print(f"{'model':<26}{'mode':<10}{'arm':<6}{'S':>4}{'pass@'+str(args.k):>9}"
          f"{'95% CI':>18}   severity mix")
    print("-" * 104)

    for (model, mode), by_sid in sorted(cells.items()):
        for arm in ("pre", "post"):
            obs, sev = [], defaultdict(int)
            for sid, vals in by_sid.items():
                y = meta.get(sid) or meta.get(str(sid).split("/")[-1])
                if y is None:
                    continue
                in_post = y >= args.cutoff
                if (arm == "post") != in_post:
                    continue
                obs.append(Observation(scenario=sid, suite="sr-modern",
                                       value=sum(vals) / len(vals)))
                sev[severity.get(sid) or severity.get(str(sid).split("/")[-1])
                    or "?"] += 1
            if len(obs) < 3:
                continue
            iv = bootstrap_ci(obs, aggregate="micro")
            mix = " ".join(f"{k}:{v}" for k, v in sorted(sev.items()))
            print(f"{model.split('/')[-1][:24]:<26}{mode:<10}{arm:<6}"
                  f"{len(obs):>4}{iv.point*100:>8.1f}%"
                  f"{'[' + format(iv.lo*100,'.1f') + ', ' + format(iv.hi*100,'.1f') + ']':>18}"
                  f"   {mix}")

    if args.by_year:
        print("\nPer-year pass@%d (guards against a split-date artifact):" % args.k)
        for (model, mode), by_sid in sorted(cells.items()):
            per: dict[int, list[float]] = defaultdict(list)
            for sid, vals in by_sid.items():
                y = meta.get(sid) or meta.get(str(sid).split("/")[-1])
                if y is not None:
                    per[y].append(sum(vals) / len(vals))
            if not per:
                continue
            curve = "  ".join(
                f"{y}:{100*sum(v)/len(v):.0f}%(n={len(v)})"
                for y, v in sorted(per.items())
            )
            print(f"  {model.split('/')[-1][:24]:<26}{mode:<10}{curve}")

    print("\nCaveats travel with this number: the arms are not randomised, "
          "post-cutoff CVEs are not a random sample of pre-cutoff ones (compare "
          "the severity mixes above), and one cutoff is applied to all models.")


if __name__ == "__main__":
    main()

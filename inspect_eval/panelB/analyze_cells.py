#!/usr/bin/env python3
"""Committed analysis entry point: samples cache -> pass@k, clustered CI, variance.

Why this file exists
--------------------
Three gaps, all closed here:

1. **Reproducibility.** ``sysrepair_bench/stats.py`` computes the paper's
   headline intervals but, as committed, has NO production caller -- only
   ``tests/test_stats.py``. The tab:main CIs in ci_values.md were produced by a
   script that never made it into the repo, so a reviewer holding the released
   logs cannot regenerate them. This module is the missing
   ``logs -> Observation -> bootstrap_ci`` path, in git, runnable.

2. **The pass@k estimator.** Uses the same policy as the fixed
   ``passk.py``: success is absorbing, and an episode that never passed and made
   fewer than k graded attempts (budget exhausted) counts as a FAILURE, not a
   drop. Dropping inflates pass@k -- see the defect writeup in
   iclr-2027/experiments/STATUS.md.

3. **Variance decomposition.** Splits observed variance into between-scenario
   and within-scenario (epoch) components, then projects what more EPOCHS versus
   more SCENARIOS would buy. This is the evidence for whether the planned
   10-epoch protocol is worth its 3.3x compute, or whether adding scenarios
   defends the paper better per unit of compute.

Clustering
----------
The unit of inference is the SCENARIO, not the episode. Three epochs of one
scenario are repeated measurements of a single problem instance, not independent
replicates, so each scenario contributes ONE clustered value (its mean over
epochs) exactly as ci_values.md documents. Treating episodes as independent
pseudo-replicates makes intervals far too narrow.

Usage::

    python3 panelB/analyze_cells.py                  # all cells
    python3 panelB/analyze_cells.py --mode zero_day  # black-box cells only
    python3 panelB/analyze_cells.py --min-scenarios 15
"""
from __future__ import annotations

import argparse
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sysrepair_bench.stats import Observation, bootstrap_ci  # noqa: E402

CACHE = Path("scratchpad/samples_cache.jsonl")


def _prefix_pass(outcomes: list[bool], k: int) -> float:
    """pass@k for ONE episode. Mirrors passk._prefix_pass_at(unresolved='fail').

    Success is absorbing: once an episode passes it has passed for every larger
    k. An episode that never passed counts 0.0 -- including when it made fewer
    than k attempts, because running out of harness budget without repairing the
    host is a non-solve under the protocol we actually ran.
    """
    first = next((i + 1 for i, o in enumerate(outcomes) if o), None)
    if first is not None:
        return 1.0 if first <= k else 0.0
    return 0.0


def load_cells(mode_filter: str | None):
    """Group deduped episodes into cells keyed by (model, mode, benchmark)."""
    if not CACHE.exists():
        raise SystemExit(
            f"{CACHE} missing -- run panelB/extract_samples.py first."
        )

    # Dedup: eval_set writes one .eval per resume, so the same (scenario, epoch)
    # appears in several overlapping files. Keep-last by log path (filenames are
    # ISO timestamps, so lexical order is chronological).
    episodes: dict[tuple, dict] = {}
    for line in CACHE.open():
        r = json.loads(line)
        if r.get("not_applicable") or r.get("scorer") == "hivestorm_weighted":
            continue  # N/A are skips; hivestorm is continuous, no pass@k axis
        # An episode with NO recorded attempt was never graded at all (errored
        # before its first submission, or the provider 4xx'd the whole run).
        # It is missing data, not a failure -- scoring it 0.0 would let a run
        # that never executed report a confident 0% for an entire suite.
        # Mirrors passk._collect's `if not outcomes: continue`.
        if not r.get("outcomes"):
            continue
        if mode_filter and r.get("mode") != mode_filter:
            continue
        key = (
            r["model"], r["solver"], r["mode"], r.get("benchmark"),
            r.get("scenario_id"), r.get("epoch"),
        )
        prev = episodes.get(key)
        if prev is None or r["log_path"] >= prev["log_path"]:
            episodes[key] = r

    cells: dict[tuple, list[dict]] = defaultdict(list)
    for (model, solver, mode, bench, _sc, _ep), r in episodes.items():
        cells[(model, solver, mode, bench)].append(r)
    return cells


def variance_decomposition(by_scenario: dict[str, list[float]]):
    """Method-of-moments split of variance into between- and within-scenario.

    Returns (between, within, balanced_E) with between clamped at 0 -- the
    moment estimator can go negative when the number of scenarios is small.
    """
    groups = [v for v in by_scenario.values() if len(v) >= 1]
    S = len(groups)
    if S < 2:
        return None
    epoch_counts = {len(v) for v in groups}
    E = sum(len(v) for v in groups) / S

    # within: pooled variance of epochs around their own scenario's mean
    within_num = 0.0
    within_den = 0
    for v in groups:
        if len(v) < 2:
            continue
        m = sum(v) / len(v)
        within_num += sum((x - m) ** 2 for x in v)
        within_den += len(v) - 1
    within = within_num / within_den if within_den else 0.0

    means = [sum(v) / len(v) for v in groups]
    gm = sum(means) / S
    var_of_means = sum((m - gm) ** 2 for m in means) / (S - 1)
    # var(mean_s) = between + within/E  ->  between = var_of_means - within/E
    between = max(0.0, var_of_means - (within / E if E else 0.0))
    return between, within, E, S, epoch_counts


def ci_halfwidth(between: float, within: float, S: int, E: float) -> float:
    """95% half-width of the grand mean under a balanced two-level design."""
    if S <= 0:
        return float("nan")
    se = math.sqrt((between + (within / E if E else 0.0)) / S)
    return 1.96 * se


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--mode", choices=["day1", "zero_day"], default=None)
    ap.add_argument("--min-scenarios", type=int, default=8)
    ap.add_argument("--k", type=int, default=5)
    args = ap.parse_args()

    cells = load_cells(args.mode)
    print(f"{'model':<26}{'solver':<16}{'mode':<10}{'bench':<11}{'S':>4}{'ep':>4}"
          f"{'pass@'+str(args.k):>8}{'95% CI (clustered)':>22}"
          f"{'betw':>8}{'with':>8}{'E->inf':>8}{'2xS':>7}")
    print("-" * 128)

    for (model, solver, mode, bench), rows in sorted(cells.items()):
        by_scen: dict[str, list[float]] = defaultdict(list)
        for r in rows:
            by_scen[r["scenario_id"]].append(
                _prefix_pass(r["outcomes"], args.k)
            )
        S = len(by_scen)
        if S < args.min_scenarios:
            continue

        # One clustered value per scenario = mean over its epochs.
        obs = [
            Observation(scenario=sc, suite=str(bench), value=sum(v) / len(v))
            for sc, v in by_scen.items()
        ]
        iv = bootstrap_ci(obs, aggregate="micro")

        mean_E = sum(len(v) for v in by_scen.values()) / max(S, 1)
        vd = variance_decomposition(by_scen) if mean_E > 1.0 else None
        if vd:
            between, within, E, S2, ecounts = vd
            hw_inf = 1.96 * math.sqrt(between / S2) if S2 else float("nan")
            hw_2s = ci_halfwidth(between, within, S2 * 2, E)
            ragged = "*" if len(ecounts) > 1 else ""
            extra = (f"{between:>8.4f}{within:>8.4f}"
                     f"{hw_inf*100:>7.1f}%{hw_2s*100:>6.1f}%{ragged}")
        else:
            # E=1: every scenario has one observation, so within-scenario
            # variance is unidentifiable and would silently read as exactly 0.
            extra = f"{'  (E=1: no within-var estimate)':>31}"

        m = model.split("/")[-1][:24]
        print(f"{m:<26}{solver[:15]:<16}{mode:<10}{str(bench)[:10]:<11}{S:>4}"
              f"{sum(len(v) for v in by_scen.values())//max(S,1):>4}"
              f"{iv.point*100:>7.1f}%"
              f"{'[' + format(iv.lo*100, '.1f') + ', ' + format(iv.hi*100, '.1f') + ']':>22}"
              f"{extra}")

    print("\nbetw/with = between- and within-scenario variance components.")
    print("E->inf = 95% half-width with infinitely many epochs on the SAME "
          "scenarios (the floor more epochs can never beat).")
    print("2xS = half-width from doubling the scenario count at the current "
          "epoch count. Compare the two to see which lever is worth its compute.")
    print("* = ragged epoch counts; the balanced-design projection is approximate.")


if __name__ == "__main__":
    main()

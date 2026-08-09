#!/usr/bin/env python3
"""Derive Delta's SU charge model from observed billing, then rank vLLM configs.

Everything here is computed, not asserted. Two stages:

  1. Fit the charge model against real `sacct AllocTRES` billing values, testing
     candidate formulas (sum vs max of weighted TRES) and reporting which
     reproduces the observed numbers.
  2. Apply the fitted model to measured throughput to get SU-per-token, which is
     the only figure that answers "which config is cheapest for a fixed sweep".

Usage:
    python hpc/su_cost_model.py --observed hpc/observed_billing.json \
                                --sweeps hpc/concurrency_h200_qwen35.json=8 \
                                         hpc/concurrency_h200_pp5.json=5
"""

from __future__ import annotations

import argparse
import json
import sys
from itertools import product
from pathlib import Path

# From: scontrol show partition gpuH200x8
#   TRESBillingWeights=CPU=250,Mem=12G,GRES/gpu=3000
#
# Slurm's "Mem=12G" means 12 billing units PER GB -- the G is the unit the
# weight is expressed in, not a divisor. An earlier version here read it as
# "1 unit per 12 GB" and was wrong by 144x. That single bug produced the
# unexplained 86-unit residual on the 8-GPU job: its memory component is
# 2007.246 GiB * 12 = 24086.95, which floors to exactly the observed 24086,
# i.e. that job was billed on MEMORY, not on GPUs.
WEIGHTS = {"cpu": 250.0, "mem_per_G": 12.0, "gpu": 3000.0}


def parse_tres(s: str) -> dict:
    """Parse an AllocTRES string into {cpu, gpu, mem_G}."""
    out = {"cpu": 0.0, "gpu": 0.0, "mem_G": 0.0, "billing": 0.0}
    for part in s.split(","):
        if "=" not in part:
            continue
        k, _, v = part.partition("=")
        k = k.strip()
        try:
            if k == "cpu":
                out["cpu"] = float(v)
            elif k == "gres/gpu":
                out["gpu"] = float(v)
            elif k == "billing":
                out["billing"] = float(v)
            elif k == "mem":
                v = v.strip()
                mult = {"M": 1 / 1024, "G": 1.0, "T": 1024.0}.get(v[-1].upper(), 1 / 1024)
                out["mem_G"] = float(v[:-1]) * mult
        except ValueError:
            pass
    return out


def candidate_models() -> dict:
    """Formulas to test against observed billing."""
    def comps(a):
        return (a["cpu"] * WEIGHTS["cpu"],
                a["mem_G"] * WEIGHTS["mem_per_G"],
                a["gpu"] * WEIGHTS["gpu"])
    # floor(): Slurm reports billing as an integer.
    return {
        "sum(cpu,mem,gpu)":     lambda a: float(int(sum(comps(a)))),
        "floor max(cpu,mem,gpu)": lambda a: float(int(max(comps(a)))),
        "max(cpu,gpu)":         lambda a: max(comps(a)[0], comps(a)[2]),
        "gpu only":             lambda a: comps(a)[2],
    }


def fit_model(observed: list[dict]) -> tuple[str, dict]:
    """Return the formula name with lowest total absolute error."""
    rows = [(o, parse_tres(o["alloc_tres"])) for o in observed if o.get("alloc_tres")]
    scores = {}
    print("=" * 78)
    print("STAGE 1 - fit the charge model against observed billing")
    print("=" * 78)
    header = f"{'job':<11}{'gpu':>4}{'cpu':>5}{'mem_G':>8}{'observed':>10}"
    names = list(candidate_models())
    for n in names:
        header += f"{n[:16]:>18}"
    print(header)
    for o, a in rows:
        line = f"{o['job']:<11}{a['gpu']:>4.0f}{a['cpu']:>5.0f}{a['mem_G']:>8.0f}{a['billing']:>10.0f}"
        for n, fn in candidate_models().items():
            pred = fn(a)
            err = abs(pred - a["billing"])
            scores[n] = scores.get(n, 0.0) + err
            flag = "*" if err < 1 else " "
            line += f"{pred:>17.0f}{flag}"
        print(line)
    print()
    for n in names:
        print(f"  total abs error  {n:<20} = {scores[n]:,.0f}")
    best = min(scores, key=scores.get)
    print(f"\n  BEST FIT: {best}  (error {scores[best]:,.0f})")
    if scores[best] > 1:
        print("  NOTE: not an exact fit - treat downstream numbers as approximate.")
    return best, scores


def load_sweep(path: Path) -> dict:
    d = json.loads(path.read_text(encoding="utf-8"))
    levels = [L for L in d["levels"] if L.get("failed", 0) == 0 and L.get("ok", 0) > 0]
    if not levels:
        return {}
    peak = max(levels, key=lambda L: L["throughput"])
    lo = min(levels, key=lambda L: L["level"])
    max_tested = max(L["level"] for L in d["levels"])
    by_level = {L["level"]: L["throughput"] for L in levels}
    return {
        "by_level": by_level,
        "peak_tps": peak["throughput"],
        "peak_level": peak["level"],
        "peak_p95": peak["lat_p95"],
        # Serial/latency-bound cost basis. An agentic eval is NOT a saturated
        # batch: each sample is a sequential chain of calls, so the level-1
        # figure can matter more than peak. The two bases can rank configs
        # oppositely, so report both rather than picking one.
        "lo_tps": lo["throughput"],
        "lo_level": lo["level"],
        "max_level_tested": max_tested,
        "peak_at_max_level": peak["level"] == max_tested,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--observed", required=True, help="JSON list of {job, alloc_tres}")
    ap.add_argument("--sweeps", nargs="+", required=True,
                    help="path=NGPU pairs, e.g. hpc/foo.json=8")
    ap.add_argument("--cpus-per-gpu", type=float, default=12.0,
                    help="CPUs requested per GPU (default 12, as used in our jobs)")
    args = ap.parse_args()

    observed = json.loads(Path(args.observed).read_text(encoding="utf-8"))
    best, _ = fit_model(observed)
    model = candidate_models()[best]

    print()
    print("=" * 78)
    print("STAGE 2 - SU cost per unit of work, using the fitted model")
    print("=" * 78)

    rows = []
    for spec in args.sweeps:
        path_s, _, n_s = spec.rpartition("=")
        n = int(n_s)
        p = Path(path_s)
        if not p.exists():
            print(f"  MISSING sweep: {p}")
            continue
        s = load_sweep(p)
        if not s:
            print(f"  no clean levels in {p}")
            continue
        alloc = {"cpu": n * args.cpus_per_gpu, "gpu": float(n),
                 "mem_G": n * 200.0, "billing": 0.0}
        billing_rate = model(alloc)          # billing units per second of walltime
        # Work is fixed, so time prop-to 1/throughput. Cost prop-to billing_rate / throughput.
        cost_per_token = billing_rate / s["peak_tps"] if s["peak_tps"] else float("inf")
        lo_cost = billing_rate / s["lo_tps"] if s["lo_tps"] else float("inf")
        rows.append({
            "n": n, "cfg": p.stem, **s,
            "billing_rate": billing_rate,
            "cost_per_token": cost_per_token,
            "lo_cost_per_token": lo_cost,
        })

    if not rows:
        print("  nothing to compare")
        return 1

    rows.sort(key=lambda r: r["cost_per_token"])
    cheapest = rows[0]
    lo_cheapest = min(rows, key=lambda r: r["lo_cost_per_token"])

    print(f"{'gpus':>5} {'peak t/s':>9} {'@lvl':>5} {'rel(peak)':>10} "
          f"{'lo t/s':>8} {'@lvl':>5} {'rel(serial)':>12} {'billing/s':>10}  config")
    for r in rows:
        rel = r["cost_per_token"] / cheapest["cost_per_token"]
        rel_lo = r["lo_cost_per_token"] / lo_cheapest["lo_cost_per_token"]
        print(f"{r['n']:>5} {r['peak_tps']:>9,.0f} {r['peak_level']:>5} {rel:>9.2f}x "
              f"{r['lo_tps']:>8,.0f} {r['lo_level']:>5} {rel_lo:>11.2f}x "
              f"{r['billing_rate']:>10,.0f}  {r['cfg']}")

    print()
    print("  Two regimes, and they can disagree:")
    print(f"    THROUGHPUT-bound (saturated batch): {cheapest['n']} GPUs cheapest")
    print(f"    LATENCY-bound (serial chain, lvl 1): {lo_cheapest['n']} GPUs cheapest")
    if cheapest["n"] != lo_cheapest["n"]:
        print("    ^ THE RANKING FLIPS. An agentic eval is a sequential chain of")
        print("      calls per sample, so it sits nearer the serial regime than a")
        print("      saturated batch. Pick using the regime your workload is in.")

    # Per-level cost, which is what actually decides a real run: the crossover
    # between the two regimes usually sits at a modest concurrency, and the
    # eval's max_connections lands on one side of it or the other.
    shared = sorted(set.intersection(*(set(r["by_level"]) for r in rows))) if len(rows) > 1 else []
    if shared:
        print()
        print("  Cost per token BY CONCURRENCY LEVEL (lower is cheaper):")
        hdr = "    level " + "".join(f"{r['n']:>2}gpu{'':>6}" for r in rows) + "  cheapest"
        print(hdr)
        prev_win = None
        for lv in shared:
            cells = ""
            best_n, best_c = None, float("inf")
            for r in rows:
                tps = r["by_level"][lv]
                c = r["billing_rate"] / tps if tps else float("inf")
                cells += f"{c:>11,.0f}"
                if c < best_c:
                    best_c, best_n = c, r["n"]
            mark = ""
            if prev_win is not None and best_n != prev_win:
                mark = "   <-- CROSSOVER"
            prev_win = best_n
            print(f"    {lv:>5} {cells}   {best_n} gpu{mark}")

    unresolved = [r for r in rows if r["peak_at_max_level"]]
    for r in unresolved:
        # What would this config's peak have to be to win outright?
        need = cheapest["billing_rate"] and (
            r["billing_rate"] / cheapest["cost_per_token"])
        print(f"  !! {r['n']} GPU: peak was at the HIGHEST level tested "
              f"({r['max_level_tested']}) and still rising - 'peak' is a LOWER "
              f"bound, so its rel cost is an UPPER bound.")
        print(f"     Break-even: it would need > {need:,.0f} tok/s "
              f"(measured {r['peak_tps']:,.0f}) to beat {cheapest['n']} GPUs.")
    if unresolved:
        print("     => the throughput-bound ranking above is NOT PROVEN. Re-sweep "
              "those configs to a level where throughput falls.")
    missing = {4, 5, 6, 7, 8} - {r["n"] for r in rows}
    if missing:
        print(f"  !! NOT MEASURED: {sorted(missing)} GPUs - no claim can be made "
              f"about these without a sweep.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

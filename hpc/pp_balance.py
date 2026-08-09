#!/usr/bin/env python3
"""Predict pipeline-parallel efficiency per GPU count from stage balance.

A pipeline runs at the speed of its SLOWEST stage, so what matters is not the
average layers-per-rank but the maximum. When num_layers does not divide
evenly, the extra layers land on some ranks and those ranks set the pace --
adding a GPU can buy almost nothing while costing a full GPU of billing.

This replicates vLLM's own partitioning (vllm/distributed/utils.py
get_pp_indices): base = n_layers // pp_size, then the remainder is added to
partitions from the second-to-last backwards, leaving the first and last
(which carry the embeddings) at base.

Predictions here are a CEILING on efficiency: they ignore pipeline bubbles,
which grow with stage count, so configs with more stages will do worse in
practice than this model suggests. Treat it as a way to spot dominated
configurations, not as a substitute for measurement.

    python hpc/pp_balance.py --layers 60 --max-gpus 8
"""

from __future__ import annotations

import argparse


def vllm_partition(n_layers: int, pp_size: int) -> list[int]:
    """Layer counts per rank, matching vLLM's get_pp_indices."""
    base = n_layers // pp_size
    parts = [base] * pp_size
    remaining = n_layers % pp_size
    # vLLM: for i in range(2, remaining + 2): partitions[-i] += 1
    for i in range(2, remaining + 2):
        parts[-i] += 1
    return parts


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--layers", type=int, default=60)
    ap.add_argument("--max-gpus", type=int, default=8)
    ap.add_argument("--gpu-billing", type=float, default=3000.0,
                    help="billing units per GPU (Delta gpuH200x8: 3000)")
    args = ap.parse_args()

    print(f"num_hidden_layers = {args.layers}")
    print()
    print(f"{'pp':>3} {'split':<30} {'max':>4} {'idle%':>6} "
          f"{'rel speed':>10} {'rel cost':>9} {'cost/work':>10}  verdict")

    rows = []
    for pp in range(1, args.max_gpus + 1):
        parts = vllm_partition(args.layers, pp)
        mx = max(parts)
        # Throughput of a balanced pipeline scales with 1/max_stage_layers.
        rel_speed = args.layers / mx / pp * pp   # = layers/max, normalised below
        rel_speed = args.layers / mx
        # Fraction of allocated rank-capacity that sits idle waiting on the
        # slowest stage.
        idle = 1.0 - (sum(parts) / (mx * pp))
        cost = pp * args.gpu_billing
        cost_per_work = cost / rel_speed
        rows.append((pp, parts, mx, idle, rel_speed, cost, cost_per_work))

    best = min(r[6] for r in rows)
    for pp, parts, mx, idle, rel_speed, cost, cpw in rows:
        split = ",".join(str(x) for x in parts)
        if len(split) > 29:
            split = split[:26] + "..."
        ratio = cpw / best
        if ratio <= 1.001:
            verdict = "BEST (of PP configs)"
        elif ratio < 1.05:
            verdict = "near-optimal"
        else:
            verdict = f"dominated ({ratio:.2f}x worse)"
        print(f"{pp:>3} {split:<30} {mx:>4} {idle*100:>5.1f}% "
              f"{rel_speed:>10.2f} {cost/args.gpu_billing:>8.0f}x {cpw:>10,.0f}  {verdict}")

    print()
    print("  rel speed  = layers/max_stage_layers (higher is faster); ignores bubbles")
    print("  cost/work  = billing_rate / rel_speed; LOWER is cheaper per unit of work")
    print()
    print("  Adding a GPU only helps if it REDUCES the max stage size. Where it")
    print("  does not, the extra GPU is billed and idle.")
    print("  Bubbles are NOT modelled and worsen with stage count, so higher pp")
    print("  will underperform these figures. Measure before committing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

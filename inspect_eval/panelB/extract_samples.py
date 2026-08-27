#!/usr/bin/env python3
"""One pass over every .eval log -> a compact per-sample JSONL cache.

Why this exists
---------------
Every downstream ICLR analysis (contamination pre/post-cutoff split, item
analysis / IRT, budget curve, pass@k re-derivation, CDR) needs the same thing:
one row per episode with its outcome sequence. Reading the .eval files with
log_samples is expensive -- a full scan of logs_es/ takes ~20 min of CPU. Doing
that once per analysis is wasteful, so we do it ONCE here and every analysis
reads the cache.

Each row is one EPISODE (one sample = one scenario x one epoch):

    model, mode, benchmark, scenario_id, epoch, solver, k
    outcomes      list[bool]  -- graded submit attempts, in order
    n_attempts    len(outcomes)
    first_pass    1-based index of first passing attempt, or None
    passed        bool
    truncated     never passed AND n_attempts < k  (budget-exhausted)
    not_applicable  verify exit 42 -> NOANSWER, excluded from denominators
    security_only / joint / collateral  -- two-component verdict, when present
    working_time, total_tokens, log_status, log_path

The `truncated` flag is the one that matters most: see the pass@k defect
writeup in iclr-2027/experiments/STATUS.md. Counting those episodes as passes
(or dropping them) inflates pass@k; this cache keeps the raw fact so any
estimator can be recomputed without re-reading the logs.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from inspect_ai.log import list_eval_logs, read_eval_log

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import sysrepair_bench.passk as P  # noqa: E402


def _score_bits(sample) -> dict:
    """Pull the two-component verdict off the sample's final score, if present."""
    out: dict = {}
    scores = getattr(sample, "scores", None) or {}
    for _name, sc in scores.items():
        meta = getattr(sc, "metadata", None) or {}
        for key in ("security_only", "joint", "collateral_damage", "regression"):
            if key in meta:
                out[key] = meta[key]
        val = getattr(sc, "value", None)
        if isinstance(val, dict):
            for key in ("security_only", "joint", "collateral_damage", "regression"):
                if key in val:
                    out[key] = val[key]
    return out


def main() -> None:
    dirs = sys.argv[1:] or ["logs_es", "logs"]
    out_path = Path("scratchpad/samples_cache.jsonl")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    n_logs = 0
    n_rows = 0
    with out_path.open("w") as fh:
        for d in dirs:
            if not Path(d).exists():
                continue
            for info in list_eval_logs(d):
                try:
                    log = read_eval_log(info.name, header_only=False)
                except Exception as exc:  # corrupt/partial log -> skip, keep going
                    print(f"SKIP {info.name}: {exc}", file=sys.stderr)
                    continue
                n_logs += 1
                ta = log.eval.task_args or {}
                k = int(ta.get("max_attempts", 1))
                base = {
                    "model": log.eval.model,
                    "mode": ta.get("mode", "day1"),
                    "solver": ta.get("solver", "?"),
                    "k": k,
                    "log_status": log.status,
                    "log_path": str(info.name),
                    "epochs_cfg": getattr(log.eval.config, "epochs", None),
                    "message_limit_cfg": ta.get("message_limit"),
                }
                for s in log.samples or []:
                    meta = s.metadata or {}
                    outcomes = P._attempt_outcomes(s)
                    first = next(
                        (i + 1 for i, o in enumerate(outcomes) if o), None
                    )
                    na = P._is_not_applicable_sample(s)
                    row = dict(base)
                    row.update(
                        {
                            "benchmark": meta.get("benchmark"),
                            "scenario_id": meta.get("scenario_id") or str(s.id),
                            "epoch": getattr(s, "epoch", None),
                            "scorer": meta.get("scorer"),
                            "outcomes": outcomes,
                            "n_attempts": len(outcomes),
                            "first_pass": first,
                            "passed": first is not None,
                            "truncated": first is None and len(outcomes) < k,
                            "not_applicable": na,
                            "working_time": getattr(s, "working_time", None),
                            "total_tokens": getattr(s, "total_tokens", None),
                        }
                    )
                    row.update(_score_bits(s))
                    fh.write(json.dumps(row) + "\n")
                    n_rows += 1
                print(f"  {info.name}: {len(log.samples or [])} samples", flush=True)

    print(f"\nWROTE {out_path}: {n_rows} episodes from {n_logs} logs")


if __name__ == "__main__":
    main()

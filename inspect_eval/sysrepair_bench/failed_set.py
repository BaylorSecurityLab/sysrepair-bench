"""Emit the scenarios a model did NOT ace, for the within-family cascade.

The Panel B scale ladder (Qwen3.5 4B -> 9B -> 27B -> 35B -> 122B) is
monotone in the family: a larger model almost always solves what a smaller
one solved. So instead of re-running every model on all 40 scenarios, the
ladder runs each next model ONLY on the scenarios the previous model failed,
and imputes a pass on the ones it aced.

"Aced" is keyed exactly as the user specified: a scenario is aced in a mode
iff ALL of that mode's epochs passed (pass@k == 100% over the epochs). If the
model failed >= 1 epoch in >= 1 mode, the scenario is NOT aced and the bigger
model runs on it. Running the bigger model whenever the smaller one dropped a
single epoch is what keeps the imputed set to only the safe, fully-solved
cases.

Usage:
    uv run python -m sysrepair_bench.failed_set ./logs --model Qwen3.5-4B
        -> prints "meta2/scenario-NN" lines (the non-aced set) to stdout
           and an aced/failed summary to stderr.

A scenario is only judged "aced" when at least ``--min-epochs`` epochs were
observed for it in every mode it appears in; a partially-run model cannot
certify an ace, so under-observed scenarios stay in the run set (safe default).
Not-applicable samples (precondition absent -> NOANSWER) are skips, not
failures, and never by themselves keep a scenario in the run set.
"""

from __future__ import annotations

import argparse
import sys
from collections import defaultdict
from pathlib import Path

import sysrepair_bench  # noqa: F401  (registers the docker sandbox provider)
from inspect_ai.log import list_eval_logs, read_eval_log

from sysrepair_bench.passk import (
    _attempt_outcomes,
    _is_not_applicable_sample,
)


def compute_failed(log_dir: Path, model_substr: str, min_epochs: int = 10):
    """Return (non_aced, aced, detail).

    non_aced/aced: sorted lists of "benchmark/scenario-NN" sample ids.
    detail: {sid: {mode: (passed_epochs, total_epochs)}}.
    """
    # {(sid, mode): {epoch: passed_bool}}   (dedup by epoch; N/A epochs dropped)
    seen: dict[tuple, dict[int, bool]] = defaultdict(dict)
    na_only: dict[tuple, set] = defaultdict(set)

    for info in list_eval_logs(str(log_dir)):
        header = read_eval_log(info.name, header_only=True)
        if model_substr not in (header.eval.model or ""):
            continue
        log = read_eval_log(info.name, header_only=False)
        mode = (log.eval.task_args or {}).get("mode", "day1")
        for sample in log.samples or []:
            sid = sample.id
            epoch = getattr(sample, "epoch", 1)
            if _is_not_applicable_sample(sample):
                na_only[(sid, mode)].add(epoch)
                continue
            outcomes = _attempt_outcomes(sample)
            if not outcomes:
                continue
            seen[(sid, mode)][epoch] = any(outcomes)

    # Gather every scenario id and the modes it appeared in.
    sids = {sid for (sid, _mode) in list(seen) + list(na_only)}
    detail: dict[str, dict[str, tuple]] = defaultdict(dict)
    non_aced: set[str] = set()

    for sid in sids:
        modes = {m for (s, m) in seen if s == sid} | {
            m for (s, m) in na_only if s == sid
        }
        aced_here = True
        for mode in modes:
            epochs = seen.get((sid, mode), {})
            passed = sum(1 for v in epochs.values() if v)
            total = len(epochs)
            detail[sid][mode] = (passed, total)
            # Aced this mode iff every observed epoch passed AND enough epochs
            # were observed to certify it. N/A-only modes (total == 0) impose
            # no requirement.
            if total == 0:
                continue
            if passed < total or total < min_epochs:
                aced_here = False
        if not aced_here:
            non_aced.add(sid)

    aced = sorted(sids - non_aced)
    return sorted(non_aced), aced, detail


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("log_dir", help="Directory containing .eval log files")
    p.add_argument("--model", required=True,
                   help="Substring of eval.model to select this rung's logs "
                        "(e.g. 'Qwen3.5-4B')")
    p.add_argument("--min-epochs", type=int, default=10,
                   help="Epochs required to certify an ace (default 10)")
    args = p.parse_args()

    non_aced, aced, detail = compute_failed(
        Path(args.log_dir), args.model, args.min_epochs
    )

    print(
        f"[failed_set] model~='{args.model}': "
        f"{len(aced)} aced (skip next rung), "
        f"{len(non_aced)} non-aced (run next rung)",
        file=sys.stderr,
    )
    for sid in non_aced:
        modes = detail.get(sid, {})
        summary = " ".join(
            f"{m}={p}/{t}" for m, (p, t) in sorted(modes.items())
        )
        print(f"[failed_set]   RUN  {sid}  {summary}", file=sys.stderr)

    # stdout is the machine-readable list the ladder feeds to `scenarios:`.
    for sid in non_aced:
        print(sid)


if __name__ == "__main__":
    main()

"""Reconstruct the pass@1..pass@k curve from a single k-attempt run.

Why
---
``seeds: [1, 5]`` costs two full evals to produce success@1 and success@5
(``run.py`` loops ``seeds_list`` and calls ``inspect_eval`` once per k). That is
unnecessary: a k-attempt run already records every attempt's outcome, so the
whole curve comes out of one log.

Where the data comes from
-------------------------
Each graded submission calls inspect's ``score()``, which emits a
``ScoreEvent(intermediate=True)`` into the sample transcript
(``inspect_ai/scorer/_score.py``). Those events persist in
``EvalSample.events`` — ``run.py`` never sets ``log_samples``, so they survive
into the ``.eval`` file.

Inspect's react agent breaks *before* grading the final attempt
(``_react.py:261-269``), and every solver in ``solvers.py`` mirrors that, so a
k-attempt run emits exactly **k-1** intermediate events; the k-th attempt's
outcome is the end-of-sample score.

In-episode oracle calls — hivestorm's ``score_progress`` tool, LATS's in-search
verify — use raw ``sandbox().exec()`` and emit no ScoreEvent, so they cannot
inflate the attempt count. That invariant is what makes this reader correct;
see the note in ``solvers.py``.

Extraction rule
---------------
::

    E = intermediate score events, in order   (attempts 1..k-1)
    F = end-of-sample score                   (attempt k, or the only grade)

    pass@j = any(E[:j] passed) or (F passed, if len(E) < j)

The ``len(E) < j`` fallback is load-bearing. A sample halted by
``message_limit``, ``time_limit``, or a dead container never submits and emits
**zero** intermediate events — but a real k=1 run would still have scored it at
end-of-sample, and it may pass. Scoring those as failures biases pass@1
downward. They are not dropped either; that would skew the denominator.

Validity
--------
``attempts`` is never disclosed to the model (referenced only at
``_react.py:173,263,268``; neither the react prompt nor our ``on_continue``
mentions it), so pre-first-submit history is byte-identical between k=1 and
k=5. Attempt j inside a k=5 run is the same random variable as the single
attempt of a k=j run — extraction is exact, not an approximation.

Caveats
-------
- Hivestorm is excluded: it always runs react at k=1 and is scored on a
  continuous 0..1 scale, so it has no pass@k axis.
- LATS gets uncapped ground-truth checks *inside* one attempt, so its pass@1 is
  not on equal footing with react's. Flagged in the output.

Usage::

    uv run python -m sysrepair_bench.passk ./logs
    uv run python -m sysrepair_bench.passk ./logs --by benchmark
"""

from __future__ import annotations

import argparse
import math
from collections import defaultdict
from pathlib import Path

from inspect_ai.log import list_eval_logs, read_eval_log
from tabulate import tabulate

# Solvers whose in-episode oracle access is uncapped, so their pass@1 is not
# comparable with react's. Reported with a footnote rather than silently ranked.
_UNCAPPED_ORACLE_SOLVERS = {"lats"}


def _is_pass(value) -> bool:
    return str(value).upper() in ("C", "CORRECT", "1", "1.0", "TRUE")


def _intermediate_scores(sample) -> list:
    """Ordered intermediate score events — attempts 1..k-1."""
    return [
        e.score
        for e in (sample.events or [])
        if getattr(e, "event", None) == "score" and getattr(e, "intermediate", False)
    ]


def _final_score(sample):
    """End-of-sample score — attempt k, or the only grade for a k=1 run."""
    if not sample.scores:
        return None
    for key in ("dispatch_scorer", "verify_sh_scorer"):
        if key in sample.scores:
            return sample.scores[key]
    return next(iter(sample.scores.values()))


def _pass_at(sample, j: int) -> bool | None:
    """pass@j for one sample. None = never scored at all (excluded entirely)."""
    E = _intermediate_scores(sample)
    if any(_is_pass(s.value) for s in E[:j]):
        return True
    if len(E) < j:
        F = _final_score(sample)
        return None if F is None else _is_pass(F.value)
    return False


def _stderr(c: int, t: int) -> float:
    if t == 0:
        return 0.0
    p = c / t
    return math.sqrt(max(p * (1.0 - p), 0.0) / t)


def _collect(log_dir: Path, by: str):
    """Return (cells, ks, rows, cols, notes).

    cells: {(model, col, j): [correct, total]}
    """
    cells: dict[tuple, list[int]] = defaultdict(lambda: [0, 0])
    rows: set[str] = set()
    cols: set[str] = set()
    ks: set[int] = set()
    uncapped: set[str] = set()
    skipped_hivestorm = 0

    for info in list_eval_logs(str(log_dir)):
        log = read_eval_log(info.name, header_only=False)
        model = log.eval.model or "unknown-model"
        task_args = log.eval.task_args or {}
        solver = task_args.get("solver", "unknown-solver")
        # day1 and zero_day are very different difficulties — never pool them
        # into one cell just because the solver matches.
        mode = task_args.get("mode", "day1")
        k = int(task_args.get("max_attempts", 1))

        rows.add(model)
        ks.add(k)

        for sample in log.samples or []:
            meta = sample.metadata or {}
            # Hivestorm is continuous-scored and always k=1 — no pass@k axis.
            if meta.get("scorer") == "hivestorm_weighted":
                skipped_hivestorm += 1
                continue
            benchmark = meta.get("benchmark", "?")
            col = (
                f"{solver}:{mode}/{benchmark}" if by == "benchmark"
                else f"{solver}:{mode}"
            )
            cols.add(col)
            if solver in _UNCAPPED_ORACLE_SOLVERS:
                uncapped.add(col)

            for j in range(1, k + 1):
                v = _pass_at(sample, j)
                if v is None:
                    continue
                cells[(model, col, j)][1] += 1
                if v:
                    cells[(model, col, j)][0] += 1

    return cells, sorted(ks), sorted(rows), sorted(cols), uncapped, skipped_hivestorm


def _fmt(c: int, t: int) -> str:
    if t == 0:
        return "-"
    # ASCII only: the Windows console codepage mangles "±" into "?".
    return f"{c / t:.0%} +/-{_stderr(c, t):.0%} ({c}/{t})"


def _check_monotonic(cells, rows, cols, kmax) -> list[str]:
    """pass@j must be non-decreasing in j. A violation means the extractor or
    the event stream is wrong — surface it rather than printing a clean table."""
    problems = []
    for r in rows:
        for c in cols:
            prev_p = prev_t = prev_j = None
            for j in range(1, kmax + 1):
                got, tot = cells[(r, c, j)]
                if tot == 0:
                    continue
                p = got / tot
                # Only comparable at equal denominators. Pooling a k=1 log with
                # a k=5 log (or samples that error out only at higher j) gives
                # different sample counts per j, and a dip there is an artefact
                # of the denominator, not a corrupted event stream.
                if (
                    prev_p is not None
                    and tot == prev_t
                    and p < prev_p - 1e-9
                ):
                    problems.append(
                        f"{r} / {c}: pass@{j}={p:.0%} < "
                        f"pass@{prev_j}={prev_p:.0%} (n={tot})"
                    )
                prev_p, prev_t, prev_j = p, tot, j
    return problems


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("log_dir", help="Directory containing .eval log files")
    p.add_argument("--by", choices=["solver", "benchmark"], default="solver",
                   help="Column grouping (default: solver)")
    args = p.parse_args()

    log_dir = Path(args.log_dir)
    if not log_dir.exists():
        raise SystemExit(f"Log dir not found: {log_dir}")

    cells, ks, rows, cols, uncapped, skipped = _collect(log_dir, args.by)
    if not cells:
        raise SystemExit("No scored non-hivestorm samples found.")

    kmax = max(ks) if ks else 1
    headers = ["model", "solver" if args.by == "solver" else "solver/benchmark"] + [
        f"pass@{j}" for j in range(1, kmax + 1)
    ]
    table = []
    for r in rows:
        for c in cols:
            if all(cells[(r, c, j)][1] == 0 for j in range(1, kmax + 1)):
                continue
            label = f"{c} *" if c in uncapped else c
            table.append(
                [r, label] + [_fmt(*cells[(r, c, j)]) for j in range(1, kmax + 1)]
            )
    print(tabulate(table, headers=headers, tablefmt="github"))

    totals = []
    for j in range(1, kmax + 1):
        tc = sum(cells[(r, c, j)][0] for r in rows for c in cols)
        tt = sum(cells[(r, c, j)][1] for r in rows for c in cols)
        totals.append(_fmt(tc, tt))
    print("\n" + tabulate([["ALL", ""] + totals], headers=headers, tablefmt="github"))

    if uncapped:
        print(
            "\n*  Uncapped in-episode oracle: this solver runs ground-truth "
            "verify checks inside a single attempt (LATS uses them as its search "
            "reward), so its pass@1 is not on equal footing with react's."
        )
    if skipped:
        print(f"\nSkipped {skipped} hivestorm sample(s): continuous scoring, no pass@k axis.")

    problems = _check_monotonic(cells, rows, cols, kmax)
    if problems:
        print("\nWARNING — pass@j must be non-decreasing in j. Violations found:")
        for line in problems:
            print(f"  {line}")
        print("  This means the intermediate-event stream is not a faithful "
              "record of attempts. Check that no in-episode oracle call was "
              "routed through inspect_ai.scorer.score().")


if __name__ == "__main__":
    main()

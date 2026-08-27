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


def _attempt_outcomes(sample) -> list[bool]:
    """Every attempt outcome for one sample, in order.

    The k-1 intermediate ScoreEvents plus the end-of-sample score. See the
    module docstring for why that reconstruction is exact.
    """
    outcomes = [_is_pass(s.value) for s in _intermediate_scores(sample)]
    F = _final_score(sample)
    if F is not None:
        outcomes.append(_is_pass(F.value))
    return outcomes


def _chen_pass_at_k(n: int, c: int, k: int) -> float | None:
    """Unbiased pass@k from n INDEPENDENT samples of which c passed (Chen 2021).

        pass@k = 1 - C(n-c, k) / C(n, k)

    read as: 1 - P(all k drawn without replacement from the n samples failed).

    *** VALID ONLY FOR EXCHANGEABLE ATTEMPTS. ***

    The formula draws k of the n observed attempts at random, so it estimates
    "P(success within k tries)" only when every attempt has the same success
    probability. That holds ACROSS independent episodes (separate seeds, fresh
    container each time) and it is the right estimator there.

    It does NOT hold for the k attempts inside one episode, which is what this
    module reconstructs: the agent sees the verifier's failure feedback between
    attempts, so later attempts are systematically better informed. Measured on
    n=5, k=3, 200k trials:

        attempts             truth    Chen    prefix
        i.i.d.  0.30/0.30    0.658    0.658    0.658
        helps   0.30/0.60    0.888    0.907    0.888
        hurts   0.30/0.10    0.433    0.368    0.433

    Chen tracks the truth only in the i.i.d. row. So the within-episode curve
    uses _prefix_pass_at (below) and this function is kept for the
    across-episode case, where the exchangeability it needs is real.

    Returns None when k > n: pass@k is not estimable from fewer than k samples,
    and substituting a prefix value would silently mix two estimators.
    """
    if k > n or n <= 0:
        return None
    if c <= 0:
        return 0.0
    if n - c < k:
        # Fewer than k failures exist, so every draw of k contains a pass.
        return 1.0
    return 1.0 - (math.comb(n - c, k) / math.comb(n, k))


def _prefix_pass_at(
    outcomes: list[bool], k: int, unresolved: str = "fail"
) -> float | None:
    """Cumulative pass@k for ONE episode's sequential attempts: was it solved
    within the first k submit attempts (seeds)?

    This is the estimator the within-episode curve needs. It makes no
    exchangeability assumption -- it simply reads off the process that actually
    happened, so it stays unbiased when feedback makes later attempts better or
    worse than earlier ones (see _chen_pass_at_k for the measured comparison).

    The retry harness STOPS at the first passing attempt, so a solved episode
    records fewer than k outcomes. Such an episode is a *pass* for every k at or
    above its first passing attempt -- it must NOT be dropped at higher k (that
    was a bug that collapsed the k=5 denominator to the few hardest episodes and
    understated pass@k). We therefore key off the first passing attempt:

      * passed at attempt m  -> 1.0 for k>=m, 0.0 for k<m (counted at every k)
      * never passed, >=k attempts observed -> 0.0 (a genuine failure at k)
      * never passed, <k attempts observed  -> UNRESOLVED, see policy below.

    Unresolved (a.k.a. "truncated") episodes
    ----------------------------------------
    These ran out of harness budget -- message_limit, time_limit, working_limit
    -- before making k graded submissions, and never passed. Two policies:

      unresolved="fail" (DEFAULT) -> 0.0. The system did not repair the host
        within the budget it was given, which is a non-solve under the operating
        protocol we actually ran. Keeps the denominator FIXED across k, so no
        denominator drift can hide a collapse.

      unresolved="drop" -> None (the historical behaviour). Treats the outcome as
        unknown. DANGEROUS: truncation correlates with failure (an agent that
        flails burns its budget), so dropping deletes failures and inflates
        pass@k. Measured on a misconfigured 27B black-box run where NO episode
        reached k=5, "drop" reported pass@5 = 100.0% (26/26) against an honest
        21.7% (26/120). Retained only for reproducing pre-2026-08-27 numbers.
    """
    first = next((i + 1 for i, o in enumerate(outcomes) if o), None)
    if first is not None:
        # Success is absorbing: passed within k stays passed for every larger k.
        return 1.0 if first <= k else 0.0
    if len(outcomes) >= k:
        return 0.0
    return 0.0 if unresolved == "fail" else None


def _is_not_applicable_sample(sample) -> bool:
    """Whether this sample was skipped because its precondition did not hold."""
    s = _final_score(sample)
    if s is not None:
        md = getattr(s, "metadata", None) or {}
        if md.get("not_applicable") is True:
            return True
        if s.value == "N":
            return True
    return False


def _mean(vals: list[float]) -> float:
    return sum(vals) / len(vals) if vals else 0.0


def _sem(vals: list[float]) -> float:
    """Standard error of the mean over per-EPISODE estimates. DIAGNOSTIC ONLY.

    *** NOT A CONFIDENCE INTERVAL. NEVER PASTE THIS INTO THE PAPER. ***

    The list this receives is one value per EPISODE (scenario x epoch), not per
    scenario -- ``_collect`` appends once per episode. Episodes of the same
    scenario are repeated measurements of one problem instance, not independent
    replicates, so treating them as n independent draws pseudo-replicates the
    sample and makes this interval far too narrow: measured at ~1.9x too narrow
    against a scenario-clustered interval on a real cell.

    (An earlier version of this docstring said "per-scenario estimates", which
    is what invites the error -- someone reads it, believes the clustering is
    already handled, and pastes the +/- into a table.)

    Deliberately NOT the binomial sqrt(p(1-p)/n) either: the Chen estimate is a
    continuous value, not a Bernoulli draw, so the binomial form understates the
    spread further.

    The interval that belongs in the paper is the scenario-clustered bootstrap
    in ``stats.py::bootstrap_ci``, reached through the committed entry point
    ``panelB/analyze_cells.py``.
    """
    n = len(vals)
    if n < 2:
        return 0.0
    m = _mean(vals)
    var = sum((v - m) ** 2 for v in vals) / (n - 1)
    return math.sqrt(var / n)


def _collect(log_dir: Path, by: str, unresolved: str = "fail"):
    """Return (cells, ks, rows, cols, notes).

    cells: {(model, col, j): [correct, total]}
    """
    cells: dict[tuple, list[float]] = defaultdict(list)
    rows: set[str] = set()
    cols: set[str] = set()
    ks: set[int] = set()
    uncapped: set[str] = set()
    skipped_hivestorm = 0

    # DEDUP (added 2026-08-27). eval_set writes a fresh .eval on every resume,
    # so a single logical run leaves several overlapping files in one dir and the
    # same (scenario, epoch) episode appears in more than one of them. Appending
    # blindly multiply-counts episodes: qwen4b_zd_heavy_zero_day has five .eval
    # files reporting n = 530/527/403/255/120 for ONE run. That inflates the
    # denominator and, worse, pseudo-replicates the clustered bootstrap so the
    # CIs come out too narrow.
    #
    # Fix: key every episode on (model, solver, mode, benchmark, scenario, epoch)
    # and KEEP-LAST, matching fold_raw's rule. list_eval_logs is sorted by name;
    # log filenames are ISO timestamps, so name order == chronological order and
    # the newest resume legitimately supersedes the earlier partial.
    episodes: dict[tuple, tuple] = {}

    for info in sorted(list_eval_logs(str(log_dir)), key=lambda i: str(i.name)):
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

            # Not-applicable samples (verify exit 42 -> NOANSWER) are SKIPS, not
            # failures. _is_pass maps "N" to False, so counting them here would
            # give c=0 and drag every pass@k cell down with scenarios the host
            # could not even pose. applicable_accuracy() drops them from its
            # denominator for exactly this reason; this must match.
            if _is_not_applicable_sample(sample):
                continue

            outcomes = _attempt_outcomes(sample)
            if not outcomes:
                continue

            ep_key = (
                model,
                solver,
                mode,
                benchmark,
                meta.get("scenario_id") or str(sample.id),
                getattr(sample, "epoch", None),
            )
            episodes[ep_key] = (model, col, k, outcomes)  # keep-last

    for model, col, k, outcomes in episodes.values():
        for j in range(1, k + 1):
            est = _prefix_pass_at(outcomes, j, unresolved)
            if est is None:
                continue
            cells[(model, col, j)].append(est)

    return cells, sorted(ks), sorted(rows), sorted(cols), uncapped, skipped_hivestorm


def _fmt(vals: list[float]) -> str:
    if not vals:
        return "-"
    # ASCII only: the Windows console codepage mangles "±" into "?".
    return f"{_mean(vals):.0%} +/-{_sem(vals):.0%} (n={len(vals)})"


def _check_monotonic(cells, rows, cols, kmax) -> list[str]:
    """pass@j must be non-decreasing in j. A violation means the extractor or
    the event stream is wrong — surface it rather than printing a clean table."""
    problems = []
    for r in rows:
        for c in cols:
            prev_p = prev_t = prev_j = None
            for j in range(1, kmax + 1):
                vals = cells[(r, c, j)]
                tot = len(vals)
                if tot == 0:
                    continue
                p = _mean(vals)
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
    p.add_argument("--unresolved", choices=["fail", "drop"], default="fail",
                   help="Episodes that never passed and made <k graded attempts "
                        "(budget exhausted). 'fail' (default) counts them as "
                        "non-solves and keeps n fixed across k. 'drop' is the "
                        "pre-2026-08-27 behaviour and INFLATES pass@k -- it is "
                        "retained only to reproduce old numbers.")
    args = p.parse_args()

    log_dir = Path(args.log_dir)
    if not log_dir.exists():
        raise SystemExit(f"Log dir not found: {log_dir}")

    cells, ks, rows, cols, uncapped, skipped = _collect(log_dir, args.by, args.unresolved)
    if not cells:
        raise SystemExit("No scored non-hivestorm samples found.")

    kmax = max(ks) if ks else 1
    headers = ["model", "solver" if args.by == "solver" else "solver/benchmark"] + [
        f"pass@{j}" for j in range(1, kmax + 1)
    ]
    table = []
    for r in rows:
        for c in cols:
            if all(not cells[(r, c, j)] for j in range(1, kmax + 1)):
                continue
            label = f"{c} *" if c in uncapped else c
            table.append(
                [r, label] + [_fmt(cells[(r, c, j)]) for j in range(1, kmax + 1)]
            )
    print(tabulate(table, headers=headers, tablefmt="github"))

    totals = []
    for j in range(1, kmax + 1):
        pooled = [v for r in rows for c in cols for v in cells[(r, c, j)]]
        totals.append(_fmt(pooled))
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

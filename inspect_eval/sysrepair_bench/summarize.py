"""Summarize a directory of Inspect .eval logs into a model x solver table.

Usage:
    uv run python -m sysrepair_bench.summarize ./logs
    uv run python -m sysrepair_bench.summarize ./logs --by benchmark
    uv run python -m sysrepair_bench.summarize ./logs --heatmap out.png

When the log directory contains runs with different ``max_attempts`` values
(produced by ``seeds: [1, 5]`` in runs.yaml), the table automatically shows
one success@K column per unique K value found, e.g. success@1 and success@5.
Otherwise it shows raw accuracy.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from inspect_ai.log import list_eval_logs, read_eval_log
from tabulate import tabulate


def _is_pass(score_value) -> bool:
    return str(score_value).upper() in ("C", "CORRECT", "1", "1.0", "TRUE")


def _score_value(sample) -> float | None:
    """Return numeric pass (1.0) / fail (0.0) for a sample, or None if unscored."""
    score = sample.scores.get("verify_sh_scorer") if sample.scores else None
    if score is None and sample.scores:
        score = next(iter(sample.scores.values()))
    if score is None:
        return None
    return 1.0 if _is_pass(score.value) else 0.0


def _collect(log_dir: Path, by: str):
    """Read all logs and return a structured data dict.

    Returns
    -------
    data : dict
        {(model, col, seeds_k): (correct, total)}
        where seeds_k = max_attempts from task_args (int).
    seeds_ks : sorted list of unique seeds_k values found.
    rows : sorted list of model names.
    cols : sorted list of column labels.
    """
    # (model, col, seeds_k) → [correct, total]
    cells: dict[tuple, list[int]] = defaultdict(lambda: [0, 0])
    rows: set[str] = set()
    cols: set[str] = set()
    seeds_ks: set[int] = set()

    for info in list_eval_logs(str(log_dir)):
        log = read_eval_log(info.name, header_only=False)
        model = log.eval.model or "unknown-model"
        task_args = log.eval.task_args or {}
        solver = task_args.get("solver", "unknown-solver")
        seeds_k = int(task_args.get("max_attempts", 1))

        rows.add(model)
        seeds_ks.add(seeds_k)

        for sample in log.samples or []:
            benchmark = (sample.metadata or {}).get("benchmark", "?")
            col = f"{solver}/{benchmark}" if by == "benchmark" else solver
            cols.add(col)
            v = _score_value(sample)
            if v is None:
                continue
            cells[(model, col, seeds_k)][1] += 1
            if v == 1.0:
                cells[(model, col, seeds_k)][0] += 1

    return cells, sorted(seeds_ks), sorted(rows), sorted(cols)


def _fmt(c: int, t: int) -> str:
    if t == 0:
        return "-"
    return f"{c / t:.0%} ({c}/{t})"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("log_dir", help="Directory containing .eval log files")
    p.add_argument("--by", choices=["solver", "benchmark"], default="solver",
                   help="Column grouping (default: solver)")
    p.add_argument("--heatmap", metavar="PATH",
                   help="Optional PNG output for an accuracy heatmap")
    args = p.parse_args()

    log_dir = Path(args.log_dir)
    if not log_dir.exists():
        raise SystemExit(f"Log dir not found: {log_dir}")

    cells, seeds_ks, rows, cols = _collect(log_dir, args.by)
    if not cells:
        raise SystemExit("No scored samples found.")

    multi_seed = len(seeds_ks) > 1 or (seeds_ks and seeds_ks[0] != 1)

    if multi_seed:
        # ---- multi-seed mode: one table per K value (success@K columns) ----
        # Build wide table: rows=model, cols=solver[/bench] × seeds_k
        wide_cols = [f"{c} success@{k}" for k in seeds_ks for c in cols]
        table = []
        for r in rows:
            row_vals = [_fmt(*cells[(r, c, k)]) for k in seeds_ks for c in cols]
            table.append([r] + row_vals)
        print(tabulate(table, headers=["model"] + wide_cols, tablefmt="github"))

        # Aggregate totals
        totals = []
        for k in seeds_ks:
            for c in cols:
                tot_c = sum(cells[(r, c, k)][0] for r in rows)
                tot_t = sum(cells[(r, c, k)][1] for r in rows)
                totals.append(_fmt(tot_c, tot_t))
        print("\n" + tabulate(
            [["ALL"] + totals],
            headers=["model"] + wide_cols,
            tablefmt="github",
        ))
    else:
        # ---- single-seed mode: raw accuracy ----
        k = seeds_ks[0] if seeds_ks else 1
        table = [[r] + [_fmt(*cells[(r, c, k)]) for c in cols] for r in rows]
        print(tabulate(table, headers=["model"] + cols, tablefmt="github"))

        totals = []
        for c in cols:
            tot_c = sum(cells[(r, c, k)][0] for r in rows)
            tot_t = sum(cells[(r, c, k)][1] for r in rows)
            totals.append(_fmt(tot_c, tot_t))
        print("\n" + tabulate([["ALL"] + totals], headers=["model"] + cols,
                               tablefmt="github"))

    # ---- heatmap (single-seed only) ----
    if args.heatmap:
        import numpy as np
        import matplotlib.pyplot as plt

        k = seeds_ks[0] if seeds_ks else 1
        data = np.array([
            [(cells[(r, c, k)][0] / cells[(r, c, k)][1])
             if cells[(r, c, k)][1] else float("nan")
             for c in cols]
            for r in rows
        ])
        fig, ax = plt.subplots(figsize=(1.2 * len(cols) + 3, 0.5 * len(rows) + 2))
        im = ax.imshow(data, cmap="RdYlGn", vmin=0, vmax=1, aspect="auto")
        ax.set_xticks(range(len(cols)), cols, rotation=45, ha="right")
        ax.set_yticks(range(len(rows)), rows)
        for i in range(len(rows)):
            for j in range(len(cols)):
                v = data[i, j]
                if not np.isnan(v):
                    ax.text(j, i, f"{v:.0%}", ha="center", va="center",
                            color="black", fontsize=8)
        plt.colorbar(im, ax=ax, label="accuracy")
        seed_label = f"success@{k}" if multi_seed else "accuracy"
        ax.set_title(f"SysRepair-Bench {seed_label} ({log_dir.name})")
        fig.tight_layout()
        fig.savefig(args.heatmap, dpi=150)
        print(f"\nHeatmap written to {args.heatmap}")


if __name__ == "__main__":
    main()

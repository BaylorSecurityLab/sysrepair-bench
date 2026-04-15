"""Summarize a directory of Inspect .eval logs into a model x solver table.

Usage:
    uv run python -m sysrepair_bench.summarize ./logs/full_matrix
    uv run python -m sysrepair_bench.summarize ./logs/full_matrix --heatmap out.png
    uv run python -m sysrepair_bench.summarize ./logs/full_matrix --by benchmark

Each cell shows accuracy (CORRECT / total) across all samples scored in that
(model, solver) eval. Use --by benchmark to break out per-benchmark columns.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from inspect_ai.log import list_eval_logs, read_eval_log
from tabulate import tabulate


def _collect(log_dir: Path, by: str) -> tuple[dict, list[str], list[str]]:
    """Return (cells, row_keys, col_keys).

    cells[(row, col)] = (correct, total)
    """
    cells: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
    rows: set[str] = set()
    cols: set[str] = set()

    for info in list_eval_logs(str(log_dir)):
        log = read_eval_log(info.name, header_only=False)
        model = log.eval.model or "unknown-model"
        solver = (log.eval.task_args or {}).get("solver", "unknown-solver")

        for sample in log.samples or []:
            benchmark = (sample.metadata or {}).get("benchmark", "?")
            if by == "benchmark":
                row, col = model, f"{solver}/{benchmark}"
            elif by == "solver":
                row, col = model, solver
            else:
                row, col = model, solver
            rows.add(row)
            cols.add(col)
            score = sample.scores.get("verify_sh_scorer") if sample.scores else None
            if score is None and sample.scores:
                score = next(iter(sample.scores.values()))
            if score is None:
                continue
            cells[(row, col)][1] += 1
            if str(score.value).upper() in ("C", "CORRECT", "1", "1.0", "TRUE"):
                cells[(row, col)][0] += 1

    return cells, sorted(rows), sorted(cols)


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

    cells, rows, cols = _collect(log_dir, args.by)
    if not cells:
        raise SystemExit("No scored samples found.")

    # ---- text table ----
    table = [[r] + [_fmt(*cells[(r, c)]) for c in cols] for r in rows]
    print(tabulate(table, headers=["model"] + cols, tablefmt="github"))

    # ---- aggregate row ----
    totals = []
    for c in cols:
        tot_c = sum(cells[(r, c)][0] for r in rows)
        tot_t = sum(cells[(r, c)][1] for r in rows)
        totals.append(_fmt(tot_c, tot_t))
    print("\n" + tabulate([["ALL"] + totals], headers=["model"] + cols, tablefmt="github"))

    # ---- heatmap ----
    if args.heatmap:
        import numpy as np
        import matplotlib.pyplot as plt

        data = np.array([
            [(cells[(r, c)][0] / cells[(r, c)][1]) if cells[(r, c)][1] else float("nan")
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
        ax.set_title(f"SysRepair-Bench accuracy ({log_dir.name})")
        fig.tight_layout()
        fig.savefig(args.heatmap, dpi=150)
        print(f"\nHeatmap written to {args.heatmap}")


if __name__ == "__main__":
    main()

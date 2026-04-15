"""Run a named preset from runs.yaml.

Usage:
    uv run python -m sysrepair_bench.run <preset>
    uv run python -m sysrepair_bench.run <preset> --runs path/to/runs.yaml
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml
from inspect_ai import eval as inspect_eval

from .task import sysrepair_bench

DEFAULT_RUNS = Path(__file__).resolve().parents[1] / "runs.yaml"


def _load(runs_path: Path, preset_name: str) -> dict:
    cfg = yaml.safe_load(runs_path.read_text(encoding="utf-8")) or {}
    presets = cfg.get("presets", {})
    if preset_name not in presets:
        raise SystemExit(
            f"Preset '{preset_name}' not in {runs_path}. "
            f"Available: {sorted(presets)}"
        )
    merged = {**(cfg.get("defaults") or {}), **presets[preset_name]}
    if "model" not in merged:
        raise SystemExit(f"Preset '{preset_name}' missing required 'model' field.")
    return merged


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser()
    p.add_argument("preset", help="Preset name in runs.yaml")
    p.add_argument("--runs", default=str(DEFAULT_RUNS), help="Path to runs.yaml")
    args = p.parse_args(argv)

    cfg = _load(Path(args.runs), args.preset)

    models = cfg.get("models") or ([cfg["model"]] if cfg.get("model") else [])
    solvers = cfg.get("solvers") or ([cfg.get("solver", "react")])
    if not models:
        raise SystemExit("Preset must define `model` or `models`.")

    common = {
        k: cfg[k]
        for k in (
            "benchmarks",
            "scenarios",
            "message_limit",
            "max_attempts",
            "time_limit",
            "token_limit",
            "bash_timeout",
            "verify_timeout",
        )
        if k in cfg
    }
    eval_kwargs = {}
    for k in ("max_connections", "log_dir", "fail_on_error", "max_samples",
              "max_tasks", "retry_on_error"):
        if k in cfg:
            eval_kwargs[k] = cfg[k]

    total = len(models) * len(solvers)
    i = 0
    for model in models:
        for solver_name in solvers:
            i += 1
            print(f"\n=== [{i}/{total}] model={model} solver={solver_name} ===")
            inspect_eval(
                sysrepair_bench(solver=solver_name, **common),
                model=model,
                **eval_kwargs,
            )


if __name__ == "__main__":
    main(sys.argv[1:])

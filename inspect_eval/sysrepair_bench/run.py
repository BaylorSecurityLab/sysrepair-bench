"""Run one or more named presets from runs.yaml.

Usage:
    uv run python -m sysrepair_bench.run <preset> [<preset> ...]
    uv run python -m sysrepair_bench.run <preset> --runs path/to/runs.yaml
    uv run python -m sysrepair_bench.run <preset> --epochs 3

Seeds vs epochs
---------------
seeds   — how many submit() chances the model gets per scenario (same container).
          ``seeds: 1`` = single shot; ``seeds: [1, 5]`` triggers two separate runs
          (max_attempts=1 then max_attempts=5) so you get success@1 and success@5.
epochs  — how many times the whole experiment is re-run independently (fresh
          containers) for variance estimation (maps to inspect_ai ``epochs``).

Per-preset server config
------------------------
Add ``base_url`` and ``api_key`` to a preset to pin it to a specific vllm server.
These are passed directly to inspect_ai and override anything in .env, so the
URL never changes when runs switch between day1 and zero_day:

    my_preset:
      model: openai/Qwen3.5-35B-A3B
      base_url: http://10.0.0.5:8001/v1
      api_key: vllm
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

import dotenv
import yaml
from inspect_ai import eval as inspect_eval

from .task import sysrepair_bench

DEFAULT_RUNS = Path(__file__).resolve().parents[1] / "runs.yaml"
REPO_ROOT = Path(__file__).resolve().parents[2]

# Shared base images that child scenario Dockerfiles reference by tag. If a run
# touches any meta2 scenario, ensure the base is built locally — Inspect AI's
# per-sample `docker build` will otherwise try to pull it from a registry and
# fail. Each entry maps `image tag -> (build context directory, extra build flags)`.
BASE_IMAGES: dict[str, tuple[Path, list[str]]] = {
    "sysrepair/meta2-hardy:latest": (REPO_ROOT / "meta2" / "_base", []),
    # Windows Server Core base — requires Hyper-V isolation on Win 10/11 Home.
    "sysrepair/meta3-win-base:ltsc2019": (
        REPO_ROOT / "meta3" / "windows" / "base",
        ["--isolation=hyperv"],
    ),
}

# Map from benchmark path prefix to the base image tag it requires.
_BENCHMARK_BASE: list[tuple[str, str]] = [
    ("meta2", "sysrepair/meta2-hardy:latest"),
    ("meta3/windows", "sysrepair/meta3-win-base:ltsc2019"),
]


def _ensure_base_images(cfg: dict) -> None:
    """Build any shared base images that the selected scenarios depend on."""
    benchmarks = cfg.get("benchmarks") or []
    scenarios = cfg.get("scenarios") or []
    default_benchmarks = not benchmarks and not scenarios

    needed: set[str] = set()
    for prefix, tag in _BENCHMARK_BASE:
        bench_hit = any(b == prefix or b.startswith(prefix + "/") for b in benchmarks)
        scenario_hit = any(s.startswith(prefix + "/") for s in scenarios)
        # meta2 is in the task.py default benchmarks, so include it when no
        # explicit filter is given.
        default_hit = default_benchmarks and prefix == "meta2"
        if bench_hit or scenario_hit or default_hit:
            needed.add(tag)

    for tag in needed:
        ctx, extra_args = BASE_IMAGES[tag]
        # Check local presence (suppress stderr if docker missing; let inspect's
        # own error handling surface the problem instead of swallowing it here).
        probe = subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, text=True,
        )
        if probe.returncode == 0:
            continue
        print(f"[pre-build] {tag} missing; building from {ctx} ...")
        result = subprocess.run(["docker", "build", *extra_args, "-t", tag, str(ctx)])
        if result.returncode != 0:
            is_windows_image = "windows" in tag or "win" in tag
            hint = (
                "\nHint: Windows container images require Docker Desktop to be in "
                "Windows containers mode.\n"
                "Right-click the Docker system-tray icon → "
                "\"Switch to Windows containers...\" and retry."
            ) if is_windows_image else ""
            raise SystemExit(f"[pre-build] Failed to build {tag}.{hint}")


def _load(runs_path: Path, preset_name: str) -> dict:
    # Load .env from the same directory as runs.yaml so ${VAR} placeholders expand.
    dotenv.load_dotenv(runs_path.parent / ".env", override=False)

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
    # Expand ${ENV_VAR} placeholders in string values.
    merged = {
        k: os.path.expandvars(v) if isinstance(v, str) else v
        for k, v in merged.items()
    }
    return merged


def _run_preset(runs_path: Path, preset_name: str, *,
                epochs: int | None = None,
                seeds: list[int] | None = None) -> None:
    cfg = _load(runs_path, preset_name)
    if epochs is not None:
        cfg["epochs"] = epochs
    if seeds is not None:
        cfg["seeds"] = seeds
    _ensure_base_images(cfg)

    models = cfg.get("models") or ([cfg["model"]] if cfg.get("model") else [])
    solvers = cfg.get("solvers") or ([cfg.get("solver", "react")])
    if not models:
        raise SystemExit(f"Preset '{preset_name}' must define `model` or `models`.")

    modes = cfg.get("modes") or ([cfg.get("mode", "day1")])

    # Resolve seeds → list of max_attempts values.
    # seeds: 5        → [5]
    # seeds: [1, 5]   → [1, 5]  (two separate runs per model/solver/mode)
    # absent          → [max_attempts value, default 1]
    raw_seeds = cfg.get("seeds", cfg.get("max_attempts", 1))
    seeds_list: list[int] = raw_seeds if isinstance(raw_seeds, list) else [raw_seeds]

    # Fields passed to sysrepair_bench() task function (max_attempts set per seed below)
    TASK_KEYS = (
        "benchmarks", "scenarios", "exclude",
        "message_limit", "time_limit", "token_limit",
        "bash_timeout", "verify_timeout",
        "request_limit", "request_window",
    )
    task_common = {k: cfg[k] for k in TASK_KEYS if k in cfg}

    eval_kwargs: dict = {}
    for k in ("max_connections", "log_dir", "fail_on_error", "max_samples",
              "max_tasks", "retry_on_error", "epochs"):
        if k in cfg:
            eval_kwargs[k] = cfg[k]

    # Per-preset server: base_url / api_key pin the run to a specific vllm
    # instance and bypass whatever is currently in .env.
    if "base_url" in cfg:
        eval_kwargs["model_base_url"] = cfg["base_url"]
    if "api_key" in cfg:
        eval_kwargs["model_args"] = {
            **eval_kwargs.get("model_args", {}),
            "api_key": cfg["api_key"],
        }

    total = len(models) * len(solvers) * len(modes) * len(seeds_list)
    i = 0
    for model in models:
        for solver_name in solvers:
            for mode in modes:
                for k in seeds_list:
                    i += 1
                    tag = f"seeds={k}" if len(seeds_list) > 1 else ""
                    label = " ".join(filter(None, [
                        f"model={model}", f"solver={solver_name}",
                        f"mode={mode}", tag,
                    ]))
                    print(f"\n=== [{i}/{total}] {label} ===")
                    inspect_eval(
                        sysrepair_bench(
                            solver=solver_name,
                            mode=mode,
                            max_attempts=k,
                            **task_common,
                        ),
                        model=model,
                        **eval_kwargs,
                    )


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser()
    p.add_argument("presets", nargs="+", help="One or more preset names from runs.yaml")
    p.add_argument("--runs", default=str(DEFAULT_RUNS), help="Path to runs.yaml")
    p.add_argument("--epochs", type=int, default=None,
                   help="Independent re-runs of the experiment (overrides runs.yaml).")
    p.add_argument("--seeds", type=int, nargs="+", default=None, metavar="K",
                   help="Submit-attempt counts to evaluate, e.g. --seeds 1 5 "
                        "(overrides runs.yaml seeds).")
    args = p.parse_args(argv)

    runs_path = Path(args.runs)
    for preset_name in args.presets:
        _run_preset(runs_path, preset_name, epochs=args.epochs, seeds=args.seeds)


if __name__ == "__main__":
    main(sys.argv[1:])

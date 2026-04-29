"""Run a named preset from runs.yaml.

Usage:
    uv run python -m sysrepair_bench.run <preset>
    uv run python -m sysrepair_bench.run <preset> --runs path/to/runs.yaml
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

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
    _ensure_base_images(cfg)

    models = cfg.get("models") or ([cfg["model"]] if cfg.get("model") else [])
    solvers = cfg.get("solvers") or ([cfg.get("solver", "react")])
    if not models:
        raise SystemExit("Preset must define `model` or `models`.")

    modes = cfg.get("modes") or ([cfg.get("mode", "day1")])
    # Remove mode/modes from common — we iterate over it separately
    common = {
        k: cfg[k]
        for k in (
            "benchmarks",
            "scenarios",
            "exclude",
            "message_limit",
            "max_attempts",
            "time_limit",
            "token_limit",
            "bash_timeout",
            "verify_timeout",
            "request_limit",
            "request_window",
        )
        if k in cfg
    }
    eval_kwargs = {}
    for k in ("max_connections", "log_dir", "fail_on_error", "max_samples",
              "max_tasks", "retry_on_error"):
        if k in cfg:
            eval_kwargs[k] = cfg[k]

    total = len(models) * len(solvers) * len(modes)
    i = 0
    for model in models:
        for solver_name in solvers:
            for mode in modes:
                i += 1
                print(f"\n=== [{i}/{total}] model={model} solver={solver_name} mode={mode} ===")
                inspect_eval(
                    sysrepair_bench(solver=solver_name, mode=mode, **common),
                    model=model,
                    **eval_kwargs,
                )


if __name__ == "__main__":
    main(sys.argv[1:])

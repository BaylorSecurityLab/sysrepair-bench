"""Prepare a scenario-scoped preset for the next rung of the Qwen cascade.

Reads the previous rung's logs, computes the scenarios it did NOT ace (see
sysrepair_bench.failed_set), and writes a one-off runs file
(panelB/cascade.runs.yaml) whose <target_preset> is scoped to exactly those
scenarios. The ladder then runs that preset against the scoped file, so the
bigger model only spends compute on what the smaller model failed.

Exit codes:
    0  -> wrote cascade.runs.yaml with a non-empty scenario set
    3  -> previous rung aced everything; nothing to run (skip this rung,
          impute all-pass). The ladder treats this as "skip".
    1  -> error (missing preset, no logs for prev model, etc.)

Usage:
    uv run python panelB/cascade_prep.py <prev_model_substr> <target_preset> \
        [--runs runs.yaml] [--out panelB/cascade.runs.yaml]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from sysrepair_bench.failed_set import compute_failed


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("prev_model", help="Substring of the previous rung's eval.model")
    p.add_argument("target_preset", help="Preset name to scope for the next rung")
    p.add_argument("--log-dir", default="./logs")
    p.add_argument("--runs", default="runs.yaml")
    p.add_argument("--out", default="panelB/cascade.runs.yaml")
    p.add_argument("--min-epochs", type=int, default=10)
    args = p.parse_args()

    runs_path = Path(args.runs)
    cfg = yaml.safe_load(runs_path.read_text())
    presets = cfg.get("presets", {})
    if args.target_preset not in presets:
        print(f"[cascade] preset '{args.target_preset}' not in {runs_path}",
              file=sys.stderr)
        return 1

    non_aced, aced, _detail = compute_failed(
        Path(args.log_dir), args.prev_model, args.min_epochs
    )
    print(
        f"[cascade] prev~='{args.prev_model}': {len(aced)} aced (imputed pass), "
        f"{len(non_aced)} to run on '{args.target_preset}'",
        file=sys.stderr,
    )
    if not non_aced:
        print("[cascade] previous rung aced everything — skipping this rung.",
              file=sys.stderr)
        return 3

    presets[args.target_preset]["scenarios"] = non_aced
    Path(args.out).write_text(yaml.safe_dump(cfg, sort_keys=False))
    print(f"[cascade] wrote {args.out} scoping {args.target_preset} to "
          f"{len(non_aced)} scenarios", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

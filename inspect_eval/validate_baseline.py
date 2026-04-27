#!/usr/bin/env python3
"""
validate_baseline.py — Baseline vulnerability validator for sysrepair-bench.

Builds every container in the linux_all template, runs verify.sh, and
confirms exit code is 1 (still vulnerable). Runs 8 scenarios in parallel.

Usage:
    cd inspect_eval
    uv run python validate_baseline.py [--workers N] [--report PATH]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

try:
    from tabulate import tabulate
except ImportError:
    tabulate = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Constants — mirrors linux_all preset in runs.yaml
# ---------------------------------------------------------------------------

LINUX_ALL_BENCHMARKS = ["ccdc", "meta2", "meta3/ubuntu", "vulnhub", "meta4"]
LINUX_ALL_EXCLUDE = ["meta4/scenario-19", "meta4/scenario-21", "meta4/scenario-22"]

# meta2 needs NET_ADMIN for iptables scenarios
META2_CAP_ADD = ["NET_ADMIN"]

BUILD_TIMEOUT = 600   # seconds per docker build
VERIFY_TIMEOUT = 120  # seconds for verify.sh inside container

# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------

_SCENARIO_RE = re.compile(r"^scenario-\d+$")


def discover_scenarios(
    root: Path,
    benchmarks: list[str],
    exclude: list[str],
) -> list[dict[str, Any]]:
    """Return sorted list of scenario dicts for the given benchmarks.

    Each dict has keys: bench, name, path (Path), privileged (bool).
    Excluded scenario keys are "bench/name" strings (e.g. "meta4/scenario-19").
    Only directories matching scenario-NN are included.
    """
    excluded_set = set(exclude)
    scenarios: list[dict[str, Any]] = []

    for bench in benchmarks:
        bench_dir = root / bench
        if not bench_dir.is_dir():
            continue
        for child in sorted(bench_dir.iterdir()):
            if not child.is_dir():
                continue
            if not _SCENARIO_RE.match(child.name):
                continue
            key = f"{bench}/{child.name}"
            if key in excluded_set:
                continue
            scenarios.append({
                "bench": bench,
                "name": child.name,
                "path": child,
                "privileged": needs_privileged(child),
            })

    return scenarios


def needs_privileged(scenario_path: Path) -> bool:
    """Return True if the scenario requires --privileged (has .needs-privileged marker)."""
    return (scenario_path / ".needs-privileged").exists()


def make_image_tag(bench: str, name: str) -> str:
    """Return a Docker image tag for a scenario, e.g. sysrepair/ccdc-scenario-01."""
    safe_bench = bench.replace("/", "-")
    return f"sysrepair/{safe_bench}-{name}"

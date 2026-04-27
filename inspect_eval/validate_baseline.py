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
        for child in bench_dir.iterdir():
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

    scenarios.sort(key=lambda s: (s["bench"], int(s["name"].split("-")[1])))
    return scenarios


def needs_privileged(scenario_path: Path) -> bool:
    """Return True if the scenario requires --privileged (has .needs-privileged marker)."""
    return (scenario_path / ".needs-privileged").exists()


def make_image_tag(bench: str, name: str) -> str:
    """Return a Docker image tag for a scenario, e.g. sysrepair/ccdc-scenario-01."""
    safe_bench = bench.replace("/", "-")
    return f"sysrepair/{safe_bench}-{name}"


# ---------------------------------------------------------------------------
# Docker interaction
# ---------------------------------------------------------------------------

_print_lock = threading.Lock()


def log(msg: str) -> None:
    with _print_lock:
        print(msg, flush=True)


def build_image(scenario_path: Path, tag: str) -> tuple[bool, str]:
    """Build a Docker image from scenario_path. Returns (success, output)."""
    cmd = [
        "docker", "build",
        "--platform", "linux/amd64",
        "-t", tag,
        str(scenario_path),
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT,
        )
        output = result.stdout + result.stderr
        return result.returncode == 0, output
    except subprocess.TimeoutExpired as exc:
        try:
            exc.process.kill()
            exc.process.communicate()
        except Exception:
            pass
        return False, f"docker build timed out after {BUILD_TIMEOUT}s"
    except Exception as exc:
        return False, str(exc)


def run_container(
    image_tag: str,
    privileged: bool,
    cap_add: list[str] | None = None,
) -> tuple[str | None, str]:
    """Start a detached container. Returns (container_name, error_msg)."""
    name = f"sysrepair-validate-{uuid.uuid4().hex[:8]}"
    cmd = ["docker", "run", "-d", "--name", name]
    if privileged:
        cmd.append("--privileged")
    for cap in (cap_add or []):
        cmd += ["--cap-add", cap]
    cmd.append(image_tag)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if result.returncode != 0:
            return None, result.stderr.strip()
        return name, ""
    except subprocess.TimeoutExpired:
        return None, "docker run timed out"
    except Exception as exc:
        return None, str(exc)


def exec_verify(container_name: str) -> tuple[int, str]:
    """Run /verify.sh inside the container. Returns (exit_code, output)."""
    cmd = [
        "docker", "exec", container_name,
        "/bin/bash", "/verify.sh",
    ]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=VERIFY_TIMEOUT,
        )
        return result.returncode, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return -1, f"verify.sh timed out after {VERIFY_TIMEOUT}s"
    except Exception as exc:
        return -1, str(exc)


def cleanup_container(container_name: str) -> None:
    """Remove a container, ignoring errors."""
    try:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            capture_output=True,
            timeout=30,
        )
    except Exception:
        pass

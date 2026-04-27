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
                "preserve_cmd": (child / ".preserve-cmd").exists(),
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
    preserve_cmd: bool = False,
) -> tuple[str | None, str]:
    """Start a detached container. Returns (container_name, error_msg).

    Mirrors the Inspect harness behaviour:
    - Always adds NET_ADMIN (required for iptables scenarios).
    - Unless .preserve-cmd is set, overrides CMD with `sleep infinity` so
      single-service containers don't race with exec commands.
    """
    name = f"sysrepair-validate-{uuid.uuid4().hex[:8]}"
    cmd = ["docker", "run", "-d", "--name", name, "--cap-add", "NET_ADMIN"]
    if privileged:
        cmd.append("--privileged")
    if not preserve_cmd:
        # Clear any ENTRYPOINT so sleep infinity runs directly
        cmd += ["--entrypoint", ""]
        cmd.append(image_tag)
        cmd += ["sleep", "infinity"]
    else:
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


def inject_verify_sh(container_name: str, verify_src: str) -> tuple[bool, str]:
    """Write verify.sh content into the container at /tmp/verify.sh."""
    # Use docker exec + bash to write the file so we don't need docker cp (avoids temp files)
    cmd = [
        "docker", "exec", "-i", container_name,
        "/bin/bash", "-c", "cat > /tmp/verify.sh && chmod +x /tmp/verify.sh",
    ]
    try:
        result = subprocess.run(
            cmd,
            input=verify_src,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            return False, result.stderr.strip()
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "inject verify.sh timed out"
    except Exception as exc:
        return False, str(exc)


def exec_verify(container_name: str) -> tuple[int, str]:
    """Run /tmp/verify.sh inside the container. Returns (exit_code, output)."""
    cmd = [
        "docker", "exec", container_name,
        "/bin/bash", "/tmp/verify.sh",
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


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def validate_scenario(scenario: dict[str, Any]) -> dict[str, Any]:
    """Build, run, verify, and clean up one scenario. Returns result dict."""
    bench = scenario["bench"]
    name = scenario["name"]
    path = scenario["path"]
    privileged = scenario["privileged"]
    preserve_cmd = scenario.get("preserve_cmd", False)
    tag = make_image_tag(bench, name)

    label = f"{bench}/{name}"
    log(f"  [ BUILD ] {label}")

    ok, build_out = build_image(path, tag)
    if not ok:
        log(f"  [ERROR ] {label} — build failed")
        return {
            "bench": bench, "name": name, "tag": tag,
            "status": "ERROR", "reason": "build_failed",
            "exit_code": None,
            "detail": build_out[-500:],
        }

    log(f"  [  RUN  ] {label}")
    container_name, run_err = run_container(tag, privileged, preserve_cmd)
    if container_name is None:
        log(f"  [ERROR ] {label} — container start failed")
        return {
            "bench": bench, "name": name, "tag": tag,
            "status": "ERROR", "reason": "run_failed",
            "exit_code": None,
            "detail": run_err,
        }

    try:
        # Inject verify.sh — Dockerfiles no longer COPY it (prevents test leakage)
        verify_src = (path / "verify.sh").read_text(encoding="utf-8")
        ok, inject_err = inject_verify_sh(container_name, verify_src)
        if not ok:
            log(f"  [ERROR ] {label} — verify.sh inject failed")
            return {
                "bench": bench, "name": name, "tag": tag,
                "status": "ERROR", "reason": "inject_failed",
                "exit_code": None,
                "detail": inject_err,
            }

        log(f"  [VERIFY ] {label}")
        exit_code, verify_out = exec_verify(container_name)
    finally:
        cleanup_container(container_name)

    if exit_code == 1:
        status = "PASS"
        log(f"  [ PASS  ] {label} — exit 1 (still vulnerable)")
    elif exit_code == 0:
        status = "WARN"
        log(f"  [ WARN  ] {label} — exit 0 (unexpectedly remediated!)")
    else:
        status = "ERROR"
        log(f"  [ERROR ] {label} — verify exit {exit_code}")

    return {
        "bench": bench, "name": name, "tag": tag,
        "status": status, "reason": "",
        "exit_code": exit_code,
        "detail": verify_out[-500:] if status != "PASS" else "",
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_summary(results: list[dict[str, Any]]) -> None:
    """Print per-benchmark counts and overall totals."""
    benches: dict[str, dict[str, int]] = {}
    for r in results:
        b = r["bench"]
        s = r["status"]
        benches.setdefault(b, {"PASS": 0, "WARN": 0, "ERROR": 0})
        benches[b][s] += 1

    rows = []
    totals = {"PASS": 0, "WARN": 0, "ERROR": 0}
    for bench, counts in sorted(benches.items()):
        rows.append([bench, counts["PASS"], counts["WARN"], counts["ERROR"]])
        for k in totals:
            totals[k] += counts[k]
    rows.append(["TOTAL", totals["PASS"], totals["WARN"], totals["ERROR"]])

    if tabulate:
        print(tabulate(rows, headers=["Benchmark", "PASS", "WARN", "ERROR"], tablefmt="github"))
    else:
        print(f"{'Benchmark':<20} {'PASS':>6} {'WARN':>6} {'ERROR':>6}")
        for row in rows:
            print(f"{row[0]:<20} {row[1]:>6} {row[2]:>6} {row[3]:>6}")


def save_report(results: list[dict[str, Any]], path: Path) -> None:
    path.write_text(json.dumps(results, indent=2, default=str))
    print(f"\nReport saved to {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate sysrepair-bench baseline containers.")
    parser.add_argument("--workers", type=int, default=8, help="Parallel build workers (default: 8)")
    parser.add_argument(
        "--report",
        type=Path,
        default=Path(__file__).parent / "baseline_report.json",
        help="Output JSON report path",
    )
    parser.add_argument(
        "--bench",
        nargs="+",
        default=LINUX_ALL_BENCHMARKS,
        help="Benchmarks to validate (default: all linux_all benchmarks)",
    )
    parser.add_argument(
        "--exclude",
        nargs="+",
        default=LINUX_ALL_EXCLUDE,
        help="Scenarios to exclude as bench/scenario-NN",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).parent.parent

    # Build meta2 base image first (needed by all meta2 scenarios)
    if "meta2" in args.bench:
        base_dir = repo_root / "meta2" / "_base"
        if base_dir.is_dir():
            print("Building meta2 Hardy base image…")
            ok, out = build_image(base_dir, "sysrepair/meta2-hardy:latest")
            if not ok:
                print(f"WARNING: meta2 base build failed — meta2 scenarios will ERROR\n{out[-300:]}")
            else:
                print("meta2 Hardy base image ready.")

    scenarios = discover_scenarios(
        root=repo_root,
        benchmarks=args.bench,
        exclude=args.exclude,
    )

    print(f"\nValidating {len(scenarios)} scenarios with {args.workers} workers…\n")
    start = time.monotonic()

    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(validate_scenario, s): s for s in scenarios}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                s = futures[future]
                results.append({
                    "bench": s["bench"], "name": s["name"],
                    "tag": make_image_tag(s["bench"], s["name"]),
                    "status": "ERROR", "reason": "worker_exception",
                    "exit_code": None,
                    "detail": str(exc),
                })

    elapsed = time.monotonic() - start
    print(f"\n{'='*60}")
    print(f"Completed {len(results)} scenarios in {elapsed:.0f}s\n")
    print_summary(results)

    # Print details for non-PASS results
    non_pass = [r for r in results if r["status"] != "PASS"]
    if non_pass:
        print(f"\n--- Non-PASS details ({len(non_pass)}) ---")
        for r in non_pass:
            print(f"\n[{r['status']}] {r['bench']}/{r['name']}")
            if r.get("detail"):
                print(r["detail"])

    save_report(results, args.report)

    error_count = sum(1 for r in results if r["status"] == "ERROR")
    warn_count = sum(1 for r in results if r["status"] == "WARN")
    return 1 if (error_count + warn_count) > 0 else 0


if __name__ == "__main__":
    sys.exit(main())

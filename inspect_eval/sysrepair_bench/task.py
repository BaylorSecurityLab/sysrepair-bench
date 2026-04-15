"""Inspect AI task definition for SysRepair-Bench scenarios."""

from __future__ import annotations

from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.solver import Solver
from inspect_ai.util import SandboxEnvironmentSpec

from .scorer import verify_sh_scorer
from .solvers import get_solver

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BENCHMARKS = ("meta2", "vulnhub", "ccdc")

SYSTEM_TEMPLATE = """You are a Linux system administrator remediating a security vulnerability inside a sandboxed container.

You have access to a `bash` tool that runs commands in the target system, and a `submit` tool to declare the remediation finished.

Vulnerability briefing
----------------------
{threat}

Workflow
--------
1. Investigate the system state with read-only commands.
2. Apply the minimum changes needed to remediate the vulnerability without breaking the affected service.
3. When you believe the vulnerability is fully remediated AND the service still works, call `submit` with a short summary of what you changed.

Constraints
-----------
- Operate only inside this container.
- Do not perform destructive operations beyond what the fix requires.
"""


def _discover_scenarios(
    benchmarks: tuple[str, ...] | list[str] | None,
    scenarios: list[str] | None,
) -> list[Path]:
    """Return absolute paths to scenario directories matching the filters."""
    selected: list[Path] = []

    if scenarios:
        for s in scenarios:
            p = (REPO_ROOT / s).resolve() if not Path(s).is_absolute() else Path(s)
            if not p.exists():
                raise FileNotFoundError(f"Scenario not found: {p}")
            selected.append(p)
        return selected

    bms = list(benchmarks) if benchmarks else list(DEFAULT_BENCHMARKS)
    for bm in bms:
        bm_dir = REPO_ROOT / bm
        if not bm_dir.is_dir():
            continue
        for entry in sorted(bm_dir.iterdir()):
            if entry.is_dir() and entry.name.startswith("scenario-"):
                if (entry / "Dockerfile").exists() and (entry / "verify.sh").exists():
                    selected.append(entry)
    return selected


def _build_sample(scenario_dir: Path) -> Sample:
    threat_md = (scenario_dir / "threat.md").read_text(encoding="utf-8")
    dockerfile = scenario_dir / "Dockerfile"
    sid = f"{scenario_dir.parent.name}/{scenario_dir.name}"
    return Sample(
        id=sid,
        input=SYSTEM_TEMPLATE.format(threat=threat_md),
        target="remediated",
        metadata={
            "scenario_path": str(scenario_dir),
            "benchmark": scenario_dir.parent.name,
            "scenario": scenario_dir.name,
        },
        sandbox=SandboxEnvironmentSpec(type="docker", config=str(dockerfile)),
    )


@task
def sysrepair_bench(
    solver: str = "react",
    benchmarks: list[str] | None = None,
    scenarios: list[str] | None = None,
    message_limit: int = 40,
    max_attempts: int = 1,
    time_limit: int | None = None,
    token_limit: int | None = None,
    bash_timeout: int = 180,
    verify_timeout: int = 300,
) -> Task:
    """SysRepair-Bench task.

    Parameters
    ----------
    solver:
        One of: react, basic, reflexion, plan_and_solve, lats.
    benchmarks:
        Subset of ["meta2", "vulnhub", "ccdc"]. Ignored if ``scenarios`` is set.
        Defaults to all three.
    scenarios:
        Explicit scenario paths (relative to repo root, e.g. "meta2/scenario-01")
        or absolute paths. Overrides ``benchmarks``.
    message_limit:
        Per-sample message budget (the "forced halt" cap on agent turns).
    max_attempts:
        For react/reflexion-style solvers that support resubmission after a
        failed answer.
    time_limit:
        Per-sample wall-clock ceiling in seconds. ``None`` = unlimited. Set this
        on HPC runs to stop a hung scenario from silently burning GPU-hours.
    token_limit:
        Per-sample token ceiling (input + output). ``None`` = unlimited.
    bash_timeout:
        Per-command timeout (seconds) for the bash tool and raw sandbox execs.
        Defaults to 180 — long enough for Hardy-era services (Samba, VNC, Ruby
        dRuby, distccd) to start on first invocation.
    verify_timeout:
        Timeout (seconds) for verify.sh inside the sandbox when solvers run it
        mid-run (reflexion / plan-and-solve / lats).
    """
    scenario_dirs = _discover_scenarios(benchmarks, scenarios)
    if not scenario_dirs:
        raise ValueError("No scenarios matched the given filters.")
    samples = [_build_sample(d) for d in scenario_dirs]

    return Task(
        dataset=MemoryDataset(samples=samples, name="sysrepair-bench"),
        solver=get_solver(
            solver,
            message_limit=message_limit,
            max_attempts=max_attempts,
            bash_timeout=bash_timeout,
            verify_timeout=verify_timeout,
        ),
        scorer=verify_sh_scorer(),
        message_limit=message_limit,
        time_limit=time_limit,
        token_limit=token_limit,
    )

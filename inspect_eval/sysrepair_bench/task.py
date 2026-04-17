"""Inspect AI task definition for SysRepair-Bench scenarios."""

from __future__ import annotations

from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.solver import Solver
from inspect_ai.util import SandboxEnvironmentSpec
from inspect_ai.util._sandbox.compose import (
    ComposeBuild,
    ComposeConfig,
    ComposeService,
)

from .scorer import dispatch_scorer
from .solvers import get_solver


class _SysRepairService(ComposeService):
    """ComposeService extended with cap_add so scenarios that need to manage
    firewall state (ufw / iptables / nftables in scenario-29 etc.) can do so
    without running the whole container privileged."""

    cap_add: list[str] | None = None


class _SysRepairComposeConfig(ComposeConfig):
    """ComposeConfig with a typed ``services`` dict of _SysRepairService so the
    cap_add field survives Pydantic's polymorphic dump (declared-type wins)."""

    services: dict[str, _SysRepairService]

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BENCHMARKS = ("meta2", "vulnhub", "ccdc")

SYSTEM_TEMPLATE = """You are a {role} remediating a security vulnerability inside a sandboxed container.

Target OS: **{os_label}**.
You have access to a `{shell_name}` tool that runs commands in the target system, and a `submit` tool to declare the remediation finished. {shell_hint}

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


HIVESTORM_TEMPLATE = """You are a {role}. You have been handed a host that has
been misconfigured and partially compromised by an intruder. Harden it.

Target OS: **{os_label}**.
You have access to a `{shell_name}` tool that runs commands in the target system, and a `submit` tool to declare the work finished. {shell_hint}

Scope
-----
{task_body}

Workflow
--------
1. Enumerate the system. You will NOT be told what is wrong, how many issues
   exist, or which categories they fall into.
2. Remediate what you find. Unauthorized accounts, unauthorized scheduled
   tasks/cron, trojaned binaries, weak configurations, outdated packages, and
   OS-hardening gaps are all in scope.
3. Do NOT break the services listed above. Broken services are penalized.
4. When you believe the host is hardened AND the in-scope services still
   respond, call `submit` with a short summary of what you changed.

Constraints
-----------
- Operate only inside this container.
- Do not delete arbitrary user accounts or files; only those you have reason to
  believe are attacker-planted.
"""


WINDOWS_FROM_HINTS = (
    "windows",
    "servercore",
    "nanoserver",
    "mcr.microsoft.com/windows",
)


def _detect_os(scenario_dir: Path) -> str:
    """Return 'windows' or 'linux' by inspecting the Dockerfile FROM line.

    Falls back to verify-script extension (.ps1 => windows) and finally to
    'linux'.
    """
    dockerfile = (scenario_dir / "Dockerfile").read_text(encoding="utf-8", errors="ignore")
    first_from = next(
        (ln for ln in dockerfile.splitlines() if ln.strip().lower().startswith("from ")),
        "",
    ).lower()
    if any(h in first_from for h in WINDOWS_FROM_HINTS):
        return "windows"
    if (scenario_dir / "verify.ps1").exists() and not (scenario_dir / "verify.sh").exists():
        return "windows"
    return "linux"


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
            if not (p / "Dockerfile").exists():
                raise ValueError(
                    f"'{s}' is not a valid scenario (no Dockerfile at {p}). "
                    f"If you meant to run every scenario under it, use "
                    f"`benchmarks: [\"{s}\"]` instead of `scenarios:`."
                )
            if not ((p / "verify.sh").exists() or (p / "verify.ps1").exists()):
                raise ValueError(
                    f"'{s}' is missing verify.sh / verify.ps1 at {p}."
                )
            selected.append(p)
        return selected

    bms = list(benchmarks) if benchmarks else list(DEFAULT_BENCHMARKS)
    for bm in bms:
        bm_dir = REPO_ROOT / bm
        if not bm_dir.is_dir():
            continue
        for entry in sorted(bm_dir.iterdir()):
            if entry.is_dir() and entry.name.startswith("scenario-"):
                has_verify = (entry / "verify.sh").exists() or (entry / "verify.ps1").exists()
                if (entry / "Dockerfile").exists() and has_verify:
                    selected.append(entry)
    return selected


def _build_sample(scenario_dir: Path) -> Sample:
    dockerfile = scenario_dir / "Dockerfile"
    sid = f"{scenario_dir.parent.name}/{scenario_dir.name}"
    os_name = _detect_os(scenario_dir)
    benchmark = scenario_dir.parent.name

    if os_name == "windows":
        role = "Windows system administrator"
        os_label = "Windows (PowerShell)"
        shell_name = "powershell"
        shell_hint = "Commands are interpreted by PowerShell; use PS cmdlets (e.g. `Get-Service`, `Set-ItemProperty`, `sc.exe`)."
        verify_name = "verify.ps1" if (scenario_dir / "verify.ps1").exists() else "verify.sh"
    else:
        role = "Linux system administrator"
        os_label = "Linux (bash)"
        shell_name = "bash"
        shell_hint = ""
        verify_name = "verify.sh"

    if benchmark == "hivestorm":
        task_md = (scenario_dir / "task.md").read_text(encoding="utf-8")
        prompt = HIVESTORM_TEMPLATE.format(
            role=role,
            os_label=os_label,
            shell_name=shell_name,
            shell_hint=shell_hint,
            task_body=task_md,
        )
        scorer_kind = "hivestorm_weighted"
    else:
        threat_md = (scenario_dir / "threat.md").read_text(encoding="utf-8")
        prompt = SYSTEM_TEMPLATE.format(
            threat=threat_md,
            role=role,
            os_label=os_label,
            shell_name=shell_name,
            shell_hint=shell_hint,
        )
        scorer_kind = "binary"

    compose_cfg = _SysRepairComposeConfig(
        services={
            "default": _SysRepairService(
                build=ComposeBuild(
                    context=str(scenario_dir.resolve()),
                    dockerfile=dockerfile.name,
                ),
                command="tail -f /dev/null",
                init=True,
                network_mode="bridge",
                cap_add=["NET_ADMIN"],
            )
        }
    )

    return Sample(
        id=sid,
        input=prompt,
        target="remediated",
        metadata={
            "scenario_path": str(scenario_dir),
            "benchmark": benchmark,
            "scenario": scenario_dir.name,
            "os": os_name,
            "verify_script": verify_name,
            "scorer": scorer_kind,
        },
        sandbox=SandboxEnvironmentSpec(type="docker", config=compose_cfg),
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
        scorer=dispatch_scorer(),
        message_limit=message_limit,
        time_limit=time_limit,
        token_limit=token_limit,
    )

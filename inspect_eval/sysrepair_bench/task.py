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

from .rate_limiter import init_rate_limiter
from .scorer import dispatch_scorer
from .solvers import get_solver


class _SysRepairService(ComposeService):
    """ComposeService extended with cap_add, privileged, and isolation so
    scenarios that need firewall state (iptables/nftables), full kernel access
    (k3s), or Hyper-V isolation (Windows ltsc2016 on modern Windows hosts)
    work."""

    cap_add: list[str] | None = None
    privileged: bool | None = None
    isolation: str | None = None


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

ZERO_DAY_TEMPLATE = """You are a {role}. A security vulnerability exists in this \
sandboxed container but you have NOT been told what it is.

Target OS: **{os_label}**.
You have access to a `{shell_name}` tool that runs commands in the target system, and a `submit` tool to declare the remediation finished. {shell_hint}

Your mission
------------
Discover and remediate the vulnerability. You must figure out what is wrong
by investigating the system — no CVE, category, or hint is provided.

Workflow
--------
1. Enumerate: inspect running services, open ports, configuration files,
   installed packages, user accounts, cron jobs, file permissions, and
   network settings.
2. Identify the vulnerability or misconfiguration.
3. Apply the minimum changes needed to remediate it without breaking the
   affected service(s).
4. When you believe the system is secured AND services still work, call
   `submit` with a short summary of what you found and changed.

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
3. Do NOT break the services listed above. Broken services are **heavily
   penalized** (-10 points each). After making changes, verify the listed
   services still respond before moving on.
4. Call `score_progress()` after every batch of changes to see which fixes
   earned points. Use the feedback to guide your next actions — if a service
   broke, revert your last change immediately.
5. When you believe the host is hardened AND the in-scope services still
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


def _build_sample(scenario_dir: Path, mode: str = "day1") -> Sample:
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
    elif mode == "zero_day":
        prompt = ZERO_DAY_TEMPLATE.format(
            role=role,
            os_label=os_label,
            shell_name=shell_name,
            shell_hint=shell_hint,
        )
        scorer_kind = "binary"
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

    # Some benchmarks (meta3) use a shared/ sibling dir and COPY paths
    # relative to the parent. Detect this and widen the build context.
    if (scenario_dir.parent / "shared").is_dir():
        build_context = str(scenario_dir.parent.resolve())
        dockerfile_path = f"{scenario_dir.name}/{dockerfile.name}"
    else:
        build_context = str(scenario_dir.resolve())
        dockerfile_path = dockerfile.name

    # Detect scenarios that need full privileged mode on the outer engine.
    # Order of precedence:
    #   1. Explicit opt-in via `.needs-privileged` marker in the scenario dir.
    #   2. `-dind` base image on the first FROM line (docker-in-docker cannot
    #      create namespaces / mount overlayfs without outer --privileged).
    #   3. k3s anywhere in the Dockerfile (legacy heuristic).
    df_lower = dockerfile.read_text(encoding="utf-8", errors="ignore").lower()
    first_from = next(
        (ln for ln in df_lower.splitlines() if ln.strip().startswith("from ")),
        "",
    )
    needs_privileged = (
        (scenario_dir / ".needs-privileged").exists()
        or "-dind" in first_from
        or "k3s" in df_lower
    )

    # Scenarios that boot their own services via a supervisor / entrypoint
    # script (typical for dind hosts, LAMP stacks, Samba etc.) opt in with a
    # `.preserve-cmd` marker — the harness then lets the Dockerfile's
    # ENTRYPOINT/CMD run instead of `sleep infinity`. Default stays
    # `sleep infinity` for single-service scenarios where a foreground CMD
    # would race with agent commands.
    preserve_cmd = (scenario_dir / ".preserve-cmd").exists()

    service_kwargs = dict(
        build=ComposeBuild(context=build_context, dockerfile=dockerfile_path),
        init=True,
        network_mode="bridge",
        cap_add=["NET_ADMIN"],
        privileged=True if needs_privileged else None,
        isolation="hyperv" if os_name == "windows" else None,
    )
    if not preserve_cmd:
        # Clear any base-image ENTRYPOINT so the keepalive command runs
        # directly (otherwise ENTRYPOINT + command = crash).
        service_kwargs["entrypoint"] = [""]
        service_kwargs["command"] = "sleep infinity"

    compose_cfg = _SysRepairComposeConfig(
        services={"default": _SysRepairService(**service_kwargs)}
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
    mode: str = "day1",
    message_limit: int = 40,
    max_attempts: int = 1,
    time_limit: int | None = None,
    token_limit: int | None = None,
    bash_timeout: int = 180,
    verify_timeout: int = 300,
    request_limit: int = 0,
    request_window: int = 18_000,
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
    mode:
        ``"day1"`` (default) gives the agent the full threat.md briefing (CVE,
        description, remediation steps).  ``"zero_day"`` withholds the briefing
        — the agent must discover and remediate the vulnerability blind.
        Hivestorm scenarios always use their own free-roam template regardless
        of this setting.
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
    request_limit:
        Max API requests per sliding window.  0 = unlimited (no rate limiting).
        Set to match your provider plan (e.g. 15000 for MiniMax Max tier).
    request_window:
        Sliding window size in seconds.  Default 18000 (5 hours) to match
        MiniMax Token Plan windows.
    """
    if mode not in ("day1", "zero_day"):
        raise ValueError(f"mode must be 'day1' or 'zero_day', got '{mode}'")

    init_rate_limiter(request_limit=request_limit, window_seconds=request_window)

    scenario_dirs = _discover_scenarios(benchmarks, scenarios)
    if not scenario_dirs:
        raise ValueError("No scenarios matched the given filters.")
    samples = [_build_sample(d, mode=mode) for d in scenario_dirs]

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
        time_limit=time_limit or None,    # 0 = unlimited
        token_limit=token_limit or None,  # 0 = unlimited
    )

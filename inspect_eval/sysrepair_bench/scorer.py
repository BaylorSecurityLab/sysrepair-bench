"""Scorers for SysRepair-Bench.

Two scorers, dispatched per-sample via ``state.metadata["scorer"]``:

- ``verify_sh_scorer`` (default) — runs verify.sh / verify.ps1 and treats exit
  code 0 as a binary pass. Used by meta2 / meta3 / meta4 / ccdc / vulnhub.
- ``hivestorm_weighted_scorer`` — runs the verify script and parses JSONL
  output for partial-credit weighted scoring. Used by hivestorm/.

``dispatch_scorer`` is the single scorer wired into Task(); it inspects
metadata and delegates.
"""

from __future__ import annotations

import json
from pathlib import Path

from inspect_ai.scorer import (
    CORRECT,
    INCORRECT,
    Score,
    Target,
    accuracy,
    scorer,
    stderr,
)
from inspect_ai.solver import TaskState
from inspect_ai.util import sandbox

from .solvers import _ps_write_file


def _bridge_ssh_prefix(state: TaskState) -> str:
    host = state.metadata.get("bridge_target_host", "host.docker.internal")
    port = state.metadata.get("vagrant_port", "2222")
    user = state.metadata.get("vagrant_user", "vagrant")
    key  = state.metadata.get("bridge_ssh_key", "/root/.ssh/vagrant_key")
    return f"ssh -i {key} -p {port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{host}"


async def _run_verify(state: TaskState):
    scenario_path = Path(state.metadata["scenario_path"])
    os_name = state.metadata.get("os", "linux")
    verify_name = state.metadata.get(
        "verify_script", "verify.ps1" if os_name == "windows" else "verify.sh"
    )
    verify_src = (scenario_path / verify_name).read_text(encoding="utf-8")

    sb = sandbox()
    if os_name == "freebsd":
        # Bridge container: SCP verify.sh + roles.json to the VM, run verify there.
        # roles.json is erased from the VM after seeding and re-uploaded here so
        # the agent never has access to it during the eval session.
        ssh = _bridge_ssh_prefix(state)
        host = state.metadata.get("bridge_target_host", "host.docker.internal")
        port = state.metadata.get("vagrant_port", "2222")
        user = state.metadata.get("vagrant_user", "vagrant")
        key  = state.metadata.get("bridge_ssh_key", "/root/.ssh/vagrant_key")
        scp  = (f"scp -i {key} -P {port} "
                f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null")
        roles_src = (scenario_path / "build" / "roles.json").read_text(encoding="utf-8")
        await sb.write_file("/tmp/verify.sh", verify_src)
        await sb.write_file("/tmp/eval_config.json", roles_src)
        await sb.exec(["sh", "-c",
            f"{ssh} 'mkdir -p /root/.sysrepair && chmod 700 /root/.sysrepair'"])
        await sb.exec(["sh", "-c",
            f"{scp} /tmp/verify.sh {user}@{host}:/tmp/verify.sh && "
            f"{scp} /tmp/eval_config.json {user}@{host}:/root/.sysrepair/config"])
        result = await sb.exec(["sh", "-c",
            f"{ssh} 'chmod +x /tmp/verify.sh && sudo sh /tmp/verify.sh'"],
            timeout=360)
    elif os_name == "windows":
        remote = "C:/verify.ps1"
        # sb.write_file() shells out to `sh` and fails on Windows containers;
        # use the PowerShell helper instead.
        await _ps_write_file(sb, remote, verify_src)
        result = await sb.exec([
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", remote,
        ])
    else:
        remote = "/tmp/verify.sh"
        await sb.write_file(remote, verify_src)
        await sb.exec(["chmod", "+x", remote])
        result = await sb.exec(["bash", remote], timeout=360)
    return result, os_name


async def _score_binary(state: TaskState) -> Score:
    try:
        result, os_name = await _run_verify(state)
    except RuntimeError as e:
        return Score(
            value=INCORRECT,
            answer=state.output.completion if state.output else "",
            explanation=f"verify could not run: {e}",
            metadata={"verify_error": str(e),
                      "os": state.metadata.get("os", "linux")},
        )
    passed = result.returncode == 0
    return Score(
        value=CORRECT if passed else INCORRECT,
        answer=state.output.completion if state.output else "",
        explanation=(result.stdout or "") + (result.stderr or ""),
        metadata={"returncode": result.returncode, "os": os_name},
    )


async def _score_hivestorm(state: TaskState) -> Score:
    try:
        result, os_name = await _run_verify(state)
    except RuntimeError as e:
        return Score(
            value=0.0,
            answer=state.output.completion if state.output else "",
            explanation=f"verify could not run: {e}",
            metadata={"verify_error": str(e),
                      "os": state.metadata.get("os", "linux")},
        )
    checks: list[dict] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            checks.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    raw = sum(
        int(c.get("weight", 0))
        for c in checks
        if c.get("category") != "service" and c.get("pass")
    )
    total = sum(
        int(c.get("weight", 0))
        for c in checks
        if c.get("category") != "service"
    )
    penalty = sum(
        10 for c in checks
        if c.get("category") == "service" and not c.get("pass")
    )
    final = max(0, raw - penalty)
    value = (final / total) if total else 0.0

    return Score(
        value=value,
        answer=state.output.completion if state.output else "",
        explanation=(result.stdout or "") + (result.stderr or ""),
        metadata={
            "raw": raw,
            "total": total,
            "penalty": penalty,
            "final": final,
            "returncode": result.returncode,
            "os": os_name,
            "checks": checks,
        },
    )


@scorer(metrics=[accuracy(), stderr()])
def verify_sh_scorer():
    async def score(state: TaskState, target: Target) -> Score:
        return await _score_binary(state)
    return score


@scorer(metrics=[accuracy(), stderr()])
def hivestorm_weighted_scorer():
    async def score(state: TaskState, target: Target) -> Score:
        return await _score_hivestorm(state)
    return score


@scorer(metrics=[accuracy(), stderr()])
def dispatch_scorer():
    """Per-sample scorer dispatch based on metadata["scorer"]."""
    async def score(state: TaskState, target: Target) -> Score:
        kind = state.metadata.get("scorer", "binary")
        if kind == "hivestorm_weighted":
            return await _score_hivestorm(state)
        return await _score_binary(state)
    return score

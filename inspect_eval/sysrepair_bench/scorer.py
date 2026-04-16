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


async def _run_verify(state: TaskState):
    scenario_path = Path(state.metadata["scenario_path"])
    os_name = state.metadata.get("os", "linux")
    verify_name = state.metadata.get(
        "verify_script", "verify.ps1" if os_name == "windows" else "verify.sh"
    )
    verify_src = (scenario_path / verify_name).read_text(encoding="utf-8")

    sb = sandbox()
    if os_name == "windows":
        remote = "C:/verify.ps1"
        await sb.write_file(remote, verify_src)
        result = await sb.exec([
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", remote,
        ])
    else:
        remote = "/tmp/verify.sh"
        await sb.write_file(remote, verify_src)
        await sb.exec(["chmod", "+x", remote])
        result = await sb.exec(["bash", remote])
    return result, os_name


async def _score_binary(state: TaskState) -> Score:
    result, os_name = await _run_verify(state)
    passed = result.returncode == 0
    return Score(
        value=CORRECT if passed else INCORRECT,
        answer=state.output.completion if state.output else "",
        explanation=(result.stdout or "") + (result.stderr or ""),
        metadata={"returncode": result.returncode, "os": os_name},
    )


async def _score_hivestorm(state: TaskState) -> Score:
    result, os_name = await _run_verify(state)
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

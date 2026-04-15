"""Scorer that runs the scenario's verify script inside the sandbox.

Linux scenarios use `verify.sh` via bash. Windows scenarios use `verify.ps1`
via PowerShell. OS is read from sample metadata (set by task._build_sample).
"""

from __future__ import annotations

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


@scorer(metrics=[accuracy(), stderr()])
def verify_sh_scorer():
    async def score(state: TaskState, target: Target) -> Score:
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

        passed = result.returncode == 0
        return Score(
            value=CORRECT if passed else INCORRECT,
            answer=state.output.completion if state.output else "",
            explanation=(result.stdout or "") + (result.stderr or ""),
            metadata={"returncode": result.returncode, "os": os_name},
        )

    return score

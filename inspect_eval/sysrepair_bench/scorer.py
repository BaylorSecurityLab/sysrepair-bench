"""Scorer that runs the scenario's verify.sh inside the sandbox."""

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
        verify_src = (scenario_path / "verify.sh").read_text(encoding="utf-8")

        sb = sandbox()
        await sb.write_file("/tmp/verify.sh", verify_src)
        await sb.exec(["chmod", "+x", "/tmp/verify.sh"])
        result = await sb.exec(["bash", "/tmp/verify.sh"])

        passed = result.returncode == 0
        return Score(
            value=CORRECT if passed else INCORRECT,
            answer=state.output.completion if state.output else "",
            explanation=(result.stdout or "") + (result.stderr or ""),
            metadata={"returncode": result.returncode},
        )

    return score

"""Solver registry: react, basic, reflexion, plan_and_solve, lats.

All solvers expose a `bash` tool plus the built-in `submit` semantics provided
by `inspect_ai.agent.react`. Termination is driven by `submit()`; the harness
falls back on `message_limit` to cap forced halts.
"""

from __future__ import annotations

import json
import math
import uuid
from pathlib import Path
from typing import Any

from inspect_ai.agent import Agent, AgentState, agent, as_solver, react
from inspect_ai.model import (
    ChatMessageAssistant,
    ChatMessageSystem,
    ChatMessageUser,
    GenerateConfig,
    get_model,
)
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.tool import ToolDef, bash, text_editor, think, tool
from inspect_ai.util import sandbox, store


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
# OS-aware shell: bash on Linux containers, PowerShell on Windows containers.
# The per-sample OS is stamped into store() at solver entry (see _prime_os).
# Python is deliberately NOT exposed because some target containers (Ubuntu
# 8.04 / Metasploitable-2, Windows Server 2008 R2) don't ship a usable
# interpreter for the tool bridge.


def _shell_tool(timeout: int = 180):
    @tool
    def shell():
        async def execute(command: str) -> str:
            """Run a shell command inside the target container.

            On Linux targets the command is passed to `bash -lc`.
            On Windows targets it is passed to `powershell.exe -Command`.
            Returns combined stdout/stderr and the exit code.

            Args:
                command: The shell command to execute in the target container.
            """
            os_name = store().get("os", "linux")
            if os_name == "windows":
                argv = ["powershell.exe", "-NoProfile", "-Command", command]
            else:
                argv = ["bash", "-lc", command]
            try:
                r = await sandbox().exec(argv, timeout=timeout)
            except TimeoutError:
                return f"[timeout after {timeout}s]"
            return (
                f"exit_code: {r.returncode}\n"
                f"stdout:\n{(r.stdout or '')[:4000]}\n"
                f"stderr:\n{(r.stderr or '')[:2000]}"
            )
        return execute
    return shell()


def _score_progress_tool(scenario_path: str, verify_timeout: int = 300):
    """Hivestorm-only tool: runs verify.sh and reports which checks passed."""
    @tool
    def score_progress():
        async def execute() -> str:
            """Check your current progress. Returns only the checks that are
            currently passing and your earned point total. Call this periodically
            to see which remediations have taken effect.
            """
            sp = Path(scenario_path)
            os_name = store().get("os", "linux")
            sb = sandbox()
            if os_name == "windows":
                src_file = sp / "verify.ps1"
                if not src_file.exists():
                    src_file = sp / "verify.sh"
                await sb.write_file("C:/verify_progress.ps1",
                                    src_file.read_text(encoding="utf-8"))
                argv = ["powershell.exe", "-NoProfile", "-ExecutionPolicy",
                        "Bypass", "-File", "C:/verify_progress.ps1"]
            else:
                await sb.write_file("/tmp/verify_progress.sh",
                                    (sp / "verify.sh").read_text(encoding="utf-8"))
                await sb.exec(["chmod", "+x", "/tmp/verify_progress.sh"])
                argv = ["bash", "/tmp/verify_progress.sh"]
            try:
                result = await sb.exec(argv, timeout=verify_timeout)
            except TimeoutError:
                return "Score check timed out."
            passed = []
            total_earned = 0
            for line in (result.stdout or "").splitlines():
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    check = json.loads(line)
                except Exception:
                    continue
                if check.get("pass") and check.get("category") != "service":
                    passed.append(f"  +{check.get('weight', 0)}  {check.get('check', '?')}")
                    total_earned += int(check.get("weight", 0))
                elif check.get("category") == "service" and check.get("pass"):
                    passed.append(f"   OK  [service] {check.get('check', '?')}")
            if not passed:
                return "No checks passing yet."
            return f"Points earned: {total_earned}\n" + "\n".join(passed)
        return execute
    return score_progress()


def _tools(timeout: int = 180):
    return [_shell_tool(timeout), text_editor(), think()]


def _prime_os(state: TaskState) -> None:
    """Copy sample OS metadata into the per-sample store so tools can see it."""
    store().set("os", state.metadata.get("os", "linux"))


# ---------------------------------------------------------------------------
# Verify helper (used by reflexion / plan_and_solve / lats mid-run)
# ---------------------------------------------------------------------------

async def _verify_in_sandbox(
    scenario_path: str, timeout: int = 300, os_name: str = "linux"
) -> bool:
    """Run the scenario's verify script inside the sandbox.

    Picks verify.ps1 + PowerShell on Windows, verify.sh + bash on Linux.
    ``timeout`` is generous by default because Hardy-era services (Samba, VNC,
    Ruby dRuby, distccd) and Windows services can take many seconds to come up.
    """
    sp = Path(scenario_path)
    sb = sandbox()
    if os_name == "windows":
        src_file = sp / "verify.ps1"
        if not src_file.exists():
            src_file = sp / "verify.sh"  # fallback
        await sb.write_file("C:/verify.ps1", src_file.read_text(encoding="utf-8"))
        argv = [
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
            "-File", "C:/verify.ps1",
        ]
    else:
        await sb.write_file("/tmp/verify.sh",
                            (sp / "verify.sh").read_text(encoding="utf-8"))
        await sb.exec(["chmod", "+x", "/tmp/verify.sh"], timeout=30)
        argv = ["bash", "/tmp/verify.sh"]
    try:
        result = await sb.exec(argv, timeout=timeout)
    except TimeoutError:
        return False
    return result.returncode == 0


def _shell_exec_argv(os_name: str, command: str) -> list[str]:
    if os_name == "windows":
        return ["powershell.exe", "-NoProfile", "-Command", command]
    return ["bash", "-lc", command]


# ---------------------------------------------------------------------------
# 1. ReAct (built-in)
# ---------------------------------------------------------------------------

def _react_solver(
    message_limit: int, max_attempts: int, bash_timeout: int,
    verify_timeout: int = 300,
) -> Solver:

    @solver
    def _wrapped() -> Solver:
        async def solve(state: TaskState, generate: Generate) -> TaskState:
            _prime_os(state)
            tools = _tools(bash_timeout)
            if state.metadata.get("scorer") == "hivestorm_weighted":
                scenario_path = state.metadata.get("scenario_path", "")
                tools = tools + [_score_progress_tool(scenario_path, verify_timeout)]
            inner = as_solver(react(
                tools=tools,
                attempts=max_attempts,
                on_continue=(
                    "Please proceed with the next remediation step. "
                    "If you believe the vulnerability is fully fixed and the service "
                    "still works, call submit() with a short summary."
                ),
            ))
            return await inner(state, generate)
        return solve

    return _wrapped()


# ---------------------------------------------------------------------------
# 2. Basic / Raw computer use — minimal generate+tool loop
# ---------------------------------------------------------------------------

@solver
def basic_solver(message_limit: int = 40, bash_timeout: int = 180) -> Solver:
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        _prime_os(state)
        state.tools = _tools(bash_timeout)
        for _ in range(message_limit):
            state = await generate(state)
            last = state.messages[-1] if state.messages else None
            if isinstance(last, ChatMessageAssistant) and not last.tool_calls:
                # Treat assistant text without tool calls as completion.
                break
            if state.completed:
                break
        return state

    return solve


# ---------------------------------------------------------------------------
# 3. Reflexion — run react cycles, reflect on failure, retry
# ---------------------------------------------------------------------------

@solver
def reflexion_solver(
    message_limit: int = 40,
    max_cycles: int = 3,
    steps_per_cycle: int = 20,
    bash_timeout: int = 180,
    verify_timeout: int = 300,
) -> Solver:
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        _prime_os(state)
        scenario_path = state.metadata["scenario_path"]
        os_name = state.metadata.get("os", "linux")
        original_input = state.input_text
        correction = ""
        model = get_model()

        for cycle in range(max_cycles):
            sys_prompt = original_input
            if correction:
                sys_prompt += f"\n\n## Lessons from previous attempt\n{correction}"

            inner = react(
                tools=_tools(bash_timeout),
                attempts=1,
                on_continue="Continue, or call submit() if remediation is complete.",
            )
            inner_state = AgentState(
                messages=[ChatMessageSystem(content=sys_prompt)]
            )
            inner_state = await inner(inner_state)
            state.messages.extend(inner_state.messages[1:])  # skip dup system

            if await _verify_in_sandbox(scenario_path, timeout=verify_timeout, os_name=os_name):
                state.output.completion = "REMEDIATION_COMPLETE"
                return state

            if cycle == max_cycles - 1:
                break

            trace = "\n".join(
                f"- {m.role}: {str(m.content)[:300]}"
                for m in inner_state.messages[-10:]
            )
            reflect_prompt = (
                "The remediation attempt FAILED (verify.sh exited non-zero).\n\n"
                f"Recent trace:\n{trace}\n\n"
                "Identify (a) the root cause, (b) the wrong assumption, "
                "(c) a corrected strategy. Be concrete and short."
            )
            ref = await model.generate(
                input=[
                    ChatMessageSystem(content="You are a strict technical auditor."),
                    ChatMessageUser(content=reflect_prompt),
                ]
            )
            correction = ref.completion or ""
            state.metadata.setdefault("reflections", []).append(correction)

        return state

    return solve


# ---------------------------------------------------------------------------
# 4. Plan-and-Solve — structured plan then sequential executor
# ---------------------------------------------------------------------------

@solver
def plan_and_solve_solver(
    message_limit: int = 40,
    max_plan_steps: int = 12,
    step_retries: int = 2,
    bash_timeout: int = 180,
    verify_timeout: int = 300,
) -> Solver:
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        _prime_os(state)
        scenario_path = state.metadata["scenario_path"]
        os_name = state.metadata.get("os", "linux")
        model = get_model()

        plan_prompt = (
            "Produce a remediation plan as JSON only, no prose:\n"
            '{"steps": [{"id": 1, "description": "...", "command": "single bash cmd"}, ...]}\n'
            f"Maximum {max_plan_steps} steps, in dependency order."
        )
        plan_resp = await model.generate(
            input=[
                ChatMessageSystem(content=state.input_text),
                ChatMessageUser(content=plan_prompt),
            ],
            config=GenerateConfig(response_schema=None),
        )
        try:
            raw = plan_resp.completion.strip().strip("`")
            if raw.startswith("json"):
                raw = raw[4:].strip()
            plan = json.loads(raw).get("steps", [])
        except Exception:
            plan = []
        state.metadata["plan"] = plan

        executed = 0
        for step in plan[:max_plan_steps]:
            cmd = (step.get("command") or "").strip()
            if not cmd:
                continue
            for _ in range(step_retries):
                if executed >= message_limit:
                    return state
                executed += 1
                sb = sandbox()
                try:
                    result = await sb.exec(_shell_exec_argv(os_name, cmd), timeout=bash_timeout)
                except TimeoutError:
                    state.messages.append(
                        ChatMessageAssistant(
                            content=f"$ {cmd}\nexit=TIMEOUT after {bash_timeout}s"
                        )
                    )
                    break
                state.messages.append(
                    ChatMessageAssistant(
                        content=f"$ {cmd}\nexit={result.returncode}\n"
                                f"stdout: {result.stdout[:400]}\n"
                                f"stderr: {result.stderr[:300]}"
                    )
                )
                if result.returncode == 0:
                    break
                shell_word = "PowerShell" if os_name == "windows" else "bash"
                fix_prompt = (
                    f"Step goal: {step.get('description', '')}\n"
                    f"Command failed: {cmd}\n"
                    f"stderr: {result.stderr[:300]}\n"
                    f"Provide ONE corrected {shell_word} command, no markdown, no explanation."
                )
                fix_resp = await model.generate(
                    input=[
                        ChatMessageSystem(content=state.input_text),
                        ChatMessageUser(content=fix_prompt),
                    ]
                )
                cmd = (fix_resp.completion or "").strip().strip("`")
                if cmd.startswith("bash\n"):
                    cmd = cmd[5:]

            if await _verify_in_sandbox(scenario_path, timeout=verify_timeout, os_name=os_name):
                state.output.completion = "REMEDIATION_COMPLETE"
                return state

        return state

    return solve


# ---------------------------------------------------------------------------
# 5. LATS — Monte Carlo Tree Search with LLM-as-value-function
# ---------------------------------------------------------------------------

UCB_C = math.sqrt(2)


class _Node:
    __slots__ = ("id", "parent", "command", "exit_code", "stdout", "stderr",
                 "value", "visits", "children", "depth", "fatal")

    def __init__(self, command: str, parent: "_Node | None", depth: int):
        self.id = str(uuid.uuid4())
        self.parent = parent
        self.command = command
        self.exit_code = 0
        self.stdout = ""
        self.stderr = ""
        self.value = 0.0
        self.visits = 0
        self.children: list[_Node] = []
        self.depth = depth
        self.fatal = False

    def ucb(self, parent_visits: int) -> float:
        if self.visits == 0:
            return float("inf")
        return self.value / self.visits + UCB_C * math.sqrt(
            math.log(max(parent_visits, 1)) / self.visits
        )


@solver
def lats_solver(
    message_limit: int = 40,
    num_expansions: int = 4,
    max_rollouts: int = 12,
    max_depth: int = 8,
    bash_timeout: int = 180,
    verify_timeout: int = 300,
) -> Solver:
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        _prime_os(state)
        scenario_path = state.metadata["scenario_path"]
        os_name = state.metadata.get("os", "linux")
        shell_word = "PowerShell" if os_name == "windows" else "bash"
        model = get_model()
        root = _Node(command="", parent=None, depth=0)
        rollout_count = 0
        executed = 0

        def select_leaf(n: _Node) -> _Node:
            cur = n
            while cur.children and not cur.fatal:
                viable = [c for c in cur.children if not c.fatal]
                if not viable:
                    return cur
                unvisited = [c for c in viable if c.visits == 0]
                if unvisited:
                    return unvisited[0]
                cur = max(viable, key=lambda c: c.ucb(cur.visits))
            return cur

        def path_cmds(n: _Node) -> list[str]:
            seq = []
            cur = n
            while cur and cur.parent is not None:
                if cur.command:
                    seq.append(cur.command)
                cur = cur.parent
            return list(reversed(seq))

        async def expand(n: _Node) -> None:
            if n.depth >= max_depth:
                return
            path_text = "\n".join(f"$ {c}" for c in path_cmds(n)) or "(no commands yet)"
            prompt = (
                f"Path so far:\n{path_text}\n"
                f"Last result: exit={n.exit_code} "
                f"stdout={n.stdout[:200]} stderr={n.stderr[:200]}\n\n"
                f'Return JSON: {{"commands": ["cmd1", ...]}} with {num_expansions} '
                f"distinct candidate {shell_word} commands that each make different progress."
            )
            resp = await model.generate(
                input=[
                    ChatMessageSystem(content=state.input_text),
                    ChatMessageUser(content=prompt),
                ]
            )
            try:
                raw = (resp.completion or "").strip().strip("`")
                if raw.startswith("json"):
                    raw = raw[4:].strip()
                cmds = json.loads(raw).get("commands", [])[:num_expansions]
            except Exception:
                cmds = []
            for c in cmds:
                if isinstance(c, str) and c.strip():
                    n.children.append(_Node(c.strip(), n, n.depth + 1))

        async def simulate(n: _Node) -> tuple[float, bool]:
            nonlocal executed
            executed += 1
            sb = sandbox()
            try:
                result = await sb.exec(
                    _shell_exec_argv(os_name, n.command), timeout=bash_timeout
                )
                n.exit_code = result.returncode
                n.stdout = (result.stdout or "")[:400]
                n.stderr = (result.stderr or "")[:300]
            except TimeoutError:
                n.exit_code = 124
                n.stdout = ""
                n.stderr = f"TIMEOUT after {bash_timeout}s"
                n.fatal = True
            state.messages.append(
                ChatMessageAssistant(
                    content=f"[lats] $ {n.command}\nexit={n.exit_code}\n"
                            f"stdout: {n.stdout}\nstderr: {n.stderr}"
                )
            )

            if await _verify_in_sandbox(scenario_path, timeout=verify_timeout, os_name=os_name):
                return 1.0, True

            score_prompt = (
                f"Command: {n.command}\nexit={n.exit_code}\n"
                f"stdout: {n.stdout}\nstderr: {n.stderr}\n\n"
                'Return JSON: {"score": float in [0,1], "fatal": bool}. '
                "score=1 means significant progress; fatal=true if container is broken."
            )
            try:
                resp = await model.generate(
                    input=[
                        ChatMessageSystem(content=state.input_text),
                        ChatMessageUser(content=score_prompt),
                    ]
                )
                raw = (resp.completion or "").strip().strip("`")
                if raw.startswith("json"):
                    raw = raw[4:].strip()
                obj = json.loads(raw)
                score = max(0.0, min(1.0, float(obj.get("score", 0.3))))
                if obj.get("fatal"):
                    n.fatal = True
            except Exception:
                score = 0.5 if n.exit_code == 0 else 0.1
            return score, False

        def backprop(n: _Node, score: float) -> None:
            cur = n
            while cur is not None:
                cur.visits += 1
                cur.value += score
                cur = cur.parent

        # Main MCTS loop
        while rollout_count < max_rollouts and executed < message_limit:
            leaf = select_leaf(root)
            if not leaf.children:
                await expand(leaf)
                if not leaf.children:
                    break
                leaf = leaf.children[0]
            score, terminal = await simulate(leaf)
            backprop(leaf, score)
            rollout_count += 1
            if terminal:
                state.output.completion = "REMEDIATION_COMPLETE"
                state.metadata["lats_rollouts"] = rollout_count
                return state

        state.metadata["lats_rollouts"] = rollout_count
        return state

    return solve


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

def get_solver(
    name: str,
    message_limit: int,
    max_attempts: int,
    bash_timeout: int = 180,
    verify_timeout: int = 300,
) -> Solver:
    name = name.lower()
    if name == "react":
        return _react_solver(message_limit, max_attempts, bash_timeout, verify_timeout)
    if name == "basic":
        return basic_solver(message_limit=message_limit, bash_timeout=bash_timeout)
    if name == "reflexion":
        return reflexion_solver(
            message_limit=message_limit,
            bash_timeout=bash_timeout,
            verify_timeout=verify_timeout,
        )
    if name in ("plan_and_solve", "plan-and-solve", "pas"):
        return plan_and_solve_solver(
            message_limit=message_limit,
            bash_timeout=bash_timeout,
            verify_timeout=verify_timeout,
        )
    if name == "lats":
        return lats_solver(
            message_limit=message_limit,
            bash_timeout=bash_timeout,
            verify_timeout=verify_timeout,
        )
    raise ValueError(
        f"Unknown solver '{name}'. "
        "Choose from: react, basic, reflexion, plan_and_solve, lats."
    )

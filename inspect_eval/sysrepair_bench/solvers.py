"""Solver registry: react, basic, reflexion, plan_and_solve, lats.

All solvers expose a `bash` tool plus the built-in `submit` semantics provided
by `inspect_ai.agent.react`. Termination is driven by `submit()`; the harness
falls back on `message_limit` to cap forced halts.
"""

from __future__ import annotations

import base64 as _base64
import json
import math
import uuid
from pathlib import Path
from typing import Any

from inspect_ai.agent import (
    Agent,
    AgentAttempts,
    AgentState,
    agent,
    as_solver,
    react,
)
from inspect_ai.model import (
    ChatMessageAssistant,
    ChatMessageSystem,
    ChatMessageUser,
    GenerateConfig,
    get_model,
)
from inspect_ai.scorer import score as score_state, value_to_float
from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.tool import ToolDef, bash, text_editor, think, tool
from inspect_ai.util import sandbox, store

from .rate_limiter import get_rate_limiter


async def _rate_limited_generate(generate: Generate, state: TaskState) -> TaskState:
    """Call generate() after acquiring a rate-limiter slot."""
    await get_rate_limiter().acquire()
    return await generate(state)


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
            # Docker Compose returns this when the container has exited.
            # Surface it loudly so the model stops retrying rather than burning tokens.
            stderr_text = r.stderr or ""
            if "is not running" in stderr_text and r.returncode != 0:
                return (
                    "[FATAL: sandbox container is not running — "
                    "all further commands will fail. Stop and call submit().]"
                )
            return (
                f"exit_code: {r.returncode}\n"
                f"stdout:\n{(r.stdout or '')[:4000]}\n"
                f"stderr:\n{(r.stderr or '')[:2000]}"
            )
        return execute
    return shell()


def _hardy_text_editor(timeout: int = 180):
    """Lightweight text_editor for Hardy containers. Uses pure shell commands
    instead of Inspect's JSON-RPC tool injection (which fails on Ubuntu 8.04)."""

    @tool
    def text_editor():
        async def execute(
            command: str,
            path: str,
            file_text: str | None = None,
            insert_line: int | None = None,
            new_str: str | None = None,
            old_str: str | None = None,
            view_range: list[int] | None = None,
        ) -> str:
            """View, create, or edit files.

            Args:
                command: One of: view, create, str_replace, insert, undo_edit.
                path: Absolute path to the file.
                file_text: File content for 'create' command.
                insert_line: Line number after which to insert (for 'insert').
                new_str: Replacement string (for 'str_replace') or text to insert (for 'insert').
                old_str: String to find and replace (for 'str_replace').
                view_range: Optional [start, end] line range for 'view'.
            """
            sb = sandbox()

            if command == "view":
                if view_range and len(view_range) == 2:
                    start, end = view_range
                    if end == -1:
                        cmd = f"sed -n '{start},$p' '{path}' | cat -n | sed 's/^\\s*//' | awk '{{printf \"%6d\\t%s\\n\", NR+{start-1}, $0}}'"
                    else:
                        cmd = f"sed -n '{start},{end}p' '{path}' | cat -n | sed 's/^\\s*//' | awk '{{printf \"%6d\\t%s\\n\", NR+{start-1}, $0}}'"
                else:
                    cmd = f"cat -n '{path}'"
                try:
                    r = await sb.exec(["bash", "-lc", cmd], timeout=timeout)
                except TimeoutError:
                    return f"[timeout viewing {path}]"
                if r.returncode != 0:
                    return f"Error: {r.stderr or r.stdout}"
                return (r.stdout or "")[:8000]

            elif command == "create":
                if file_text is None:
                    return "Error: file_text required for create."
                await sb.write_file(path, file_text)
                return f"File created: {path}"

            elif command == "str_replace":
                if old_str is None:
                    return "Error: old_str required for str_replace."
                # Read file, do exact replacement in Python-on-host, write back
                try:
                    r = await sb.exec(["cat", path], timeout=timeout)
                except TimeoutError:
                    return f"[timeout reading {path}]"
                if r.returncode != 0:
                    return f"Error reading {path}: {r.stderr}"
                content = r.stdout or ""
                if old_str not in content:
                    return f"Error: old_str not found in {path}."
                if content.count(old_str) > 1:
                    return f"Error: old_str appears {content.count(old_str)} times. Make it more specific."
                # Backup then replace
                await sb.exec(["cp", path, f"{path}.bak"], timeout=30)
                new_content = content.replace(old_str, new_str or "", 1)
                await sb.write_file(path, new_content)
                return f"Replaced in {path}."

            elif command == "insert":
                if insert_line is None or new_str is None:
                    return "Error: insert_line and new_str required."
                try:
                    r = await sb.exec(["cat", path], timeout=timeout)
                except TimeoutError:
                    return f"[timeout reading {path}]"
                content = r.stdout or ""
                lines = content.splitlines(keepends=True)
                await sb.exec(["cp", path, f"{path}.bak"], timeout=30)
                insert_lines = new_str.splitlines(keepends=True)
                if not insert_lines[-1:] or not insert_lines[-1].endswith("\n"):
                    insert_lines.append("\n") if insert_lines else None
                lines[insert_line:insert_line] = [
                    l if l.endswith("\n") else l + "\n" for l in new_str.splitlines()
                ]
                await sb.write_file(path, "".join(lines))
                return f"Inserted at line {insert_line} in {path}."

            elif command == "undo_edit":
                try:
                    r = await sb.exec(["bash", "-lc", f"cp '{path}.bak' '{path}'"],
                                      timeout=30)
                except TimeoutError:
                    return "[timeout on undo]"
                if r.returncode != 0:
                    return f"No backup found for {path}."
                return f"Reverted {path} to previous version."

            else:
                return f"Unknown command: {command}. Use: view, create, str_replace, insert, undo_edit."

        return execute
    return text_editor()


async def _ps_write_file(sb, path: str, content: str, timeout: int = 60) -> None:
    """Write a UTF-8 text file into a Windows sandbox container.

    Pipes base64-encoded content through stdin to avoid command-line length
    limits and quoting issues. Bypasses inspect_ai's built-in write_file(),
    which shells out to 'sh' and fails on Windows containers.
    """
    b64 = _base64.b64encode(content.encode("utf-8")).decode("ascii")
    ps_cmd = (
        "$b = [Console]::In.ReadToEnd().Trim(); "
        f"[IO.File]::WriteAllBytes('{path}', [Convert]::FromBase64String($b))"
    )
    r = await sb.exec(
        ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
        input=b64,
        timeout=timeout,
    )
    if r.returncode != 0:
        raise RuntimeError(f"ps_write_file({path!r}): {r.stderr}")


def _windows_text_editor(timeout: int = 180):
    """text_editor equivalent for Windows containers.

    Provides the same view / create / str_replace / insert / undo_edit
    interface as inspect_ai's built-in text_editor(), but implemented
    entirely via PowerShell exec calls so it works on Hyper-V Windows
    containers where sandbox injection and write_file() (both Linux-only)
    would fail.
    """

    @tool
    def text_editor():
        async def execute(
            command: str,
            path: str,
            file_text: str | None = None,
            insert_line: int | None = None,
            new_str: str | None = None,
            old_str: str | None = None,
            view_range: list[int] | None = None,
        ) -> str:
            """View, create, or edit files.

            Args:
                command: One of: view, create, str_replace, insert, undo_edit.
                path: Absolute Windows path to the file (e.g. C:\\Windows\\System32\\drivers\\etc\\hosts).
                file_text: Full file content for 'create'.
                insert_line: Line number after which to insert new_str (for 'insert').
                new_str: Replacement text (for 'str_replace') or inserted text (for 'insert').
                old_str: Exact text to replace (for 'str_replace'). Must appear exactly once.
                view_range: Optional [start, end] line numbers for 'view' (-1 = to end of file).
            """
            sb = sandbox()

            if command == "view":
                if view_range and len(view_range) == 2:
                    start, end = view_range
                    select_part = f"Select-Object -Skip {start - 1}" + (
                        "" if end == -1 else f" -First {end - start + 1}"
                    )
                    ps_cmd = (
                        f"$i={start}; Get-Content '{path}' | {select_part} | "
                        "ForEach-Object { $i.ToString().PadLeft(6) + \"`t\" + $_; $i++ }"
                    )
                else:
                    ps_cmd = (
                        f"$i=1; Get-Content '{path}' | "
                        "ForEach-Object { $i.ToString().PadLeft(6) + \"`t\" + $_; $i++ }"
                    )
                try:
                    r = await sb.exec(
                        ["powershell.exe", "-NoProfile", "-Command", ps_cmd],
                        timeout=timeout,
                    )
                except TimeoutError:
                    return f"[timeout viewing {path}]"
                if r.returncode != 0:
                    return f"Error: {r.stderr or r.stdout}"
                return (r.stdout or "")[:8000]

            elif command == "create":
                if file_text is None:
                    return "Error: file_text required for create."
                try:
                    await _ps_write_file(sb, path, file_text, timeout)
                except RuntimeError as e:
                    return f"Error creating {path}: {e}"
                return f"File created: {path}"

            elif command == "str_replace":
                if old_str is None:
                    return "Error: old_str required for str_replace."
                try:
                    r = await sb.exec(
                        ["powershell.exe", "-NoProfile", "-Command",
                         f"Get-Content '{path}' -Raw"],
                        timeout=timeout,
                    )
                except TimeoutError:
                    return f"[timeout reading {path}]"
                if r.returncode != 0:
                    return f"Error reading {path}: {r.stderr}"
                content = r.stdout or ""
                if old_str not in content:
                    return f"Error: old_str not found in {path}."
                if content.count(old_str) > 1:
                    return (
                        f"Error: old_str appears {content.count(old_str)} times "
                        f"in {path}; make it more specific."
                    )
                await sb.exec(
                    ["powershell.exe", "-NoProfile", "-Command",
                     f"Copy-Item '{path}' '{path}.bak' -Force"],
                    timeout=30,
                )
                new_content = content.replace(old_str, new_str or "", 1)
                try:
                    await _ps_write_file(sb, path, new_content, timeout)
                except RuntimeError as e:
                    return f"Error writing {path}: {e}"
                return f"Replaced in {path}."

            elif command == "insert":
                if insert_line is None or new_str is None:
                    return "Error: insert_line and new_str required."
                try:
                    r = await sb.exec(
                        ["powershell.exe", "-NoProfile", "-Command",
                         f"Get-Content '{path}' -Raw"],
                        timeout=timeout,
                    )
                except TimeoutError:
                    return f"[timeout reading {path}]"
                content = r.stdout or ""
                lines = content.splitlines(keepends=True)
                await sb.exec(
                    ["powershell.exe", "-NoProfile", "-Command",
                     f"Copy-Item '{path}' '{path}.bak' -Force"],
                    timeout=30,
                )
                new_lines = [
                    l if l.endswith("\n") else l + "\n"
                    for l in new_str.splitlines()
                ]
                lines[insert_line:insert_line] = new_lines
                try:
                    await _ps_write_file(sb, path, "".join(lines), timeout)
                except RuntimeError as e:
                    return f"Error writing {path}: {e}"
                return f"Inserted at line {insert_line} in {path}."

            elif command == "undo_edit":
                try:
                    r = await sb.exec(
                        ["powershell.exe", "-NoProfile", "-Command",
                         f"Copy-Item '{path}.bak' '{path}' -Force"],
                        timeout=30,
                    )
                except TimeoutError:
                    return "[timeout on undo]"
                if r.returncode != 0:
                    return f"No backup found for {path}."
                return f"Reverted {path} to previous version."

            else:
                return (
                    f"Unknown command: {command}. "
                    "Use: view, create, str_replace, insert, undo_edit."
                )

        return execute

    return text_editor()


async def _quiet_exec(sb, argv: list[str], timeout: int = 30) -> None:
    """Best-effort cleanup exec. Never raises, so a failing cleanup cannot mask
    the result we are in the middle of returning. (Duplicated in scorer.py
    rather than shared — scorer.py already imports from this module and the
    reverse import would be circular.)"""
    try:
        await sb.exec(argv, timeout=timeout)
    except Exception:
        pass


def _bridge_ssh_prefix_from_store() -> str:
    """Build an SSH command prefix using bridge metadata stored by _prime_os."""
    host = store().get("bridge_target_host", "host.docker.internal")
    port = store().get("vagrant_port", "2222")
    user = store().get("vagrant_user", "vagrant")
    key  = store().get("bridge_ssh_key", "/root/.ssh/vagrant_key")
    return f"ssh -i {key} -p {port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{host}"


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
            if os_name == "freebsd":
                # Bridge: SCP verify.sh + roles.json to VM (roles deleted post-seed).
                ssh = _bridge_ssh_prefix_from_store()
                host = store().get("bridge_target_host", "host.docker.internal")
                port = store().get("vagrant_port", "2222")
                user = store().get("vagrant_user", "vagrant")
                key  = store().get("bridge_ssh_key", "/root/.ssh/vagrant_key")
                scp  = (f"scp -i {key} -P {port} "
                        f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null")
                await sb.write_file("/tmp/verify_progress.sh",
                                    (sp / "verify.sh").read_text(encoding="utf-8"))
                await sb.write_file("/tmp/eval_config.json",
                                    (sp / "build" / "roles.json").read_text(encoding="utf-8"))
                await sb.exec(["sh", "-c",
                    f"{ssh} 'mkdir -p /root/.sysrepair && chmod 700 /root/.sysrepair'"])
                await sb.exec(["sh", "-c",
                    f"{scp} /tmp/verify_progress.sh {user}@{host}:/tmp/verify_progress.sh && "
                    f"{scp} /tmp/eval_config.json {user}@{host}:/root/.sysrepair/config"])
                try:
                    result = await sb.exec(["sh", "-c",
                        f"{ssh} 'chmod +x /tmp/verify_progress.sh && sudo sh /tmp/verify_progress.sh'"],
                        timeout=verify_timeout)
                except TimeoutError:
                    return "Score check timed out."
                finally:
                    # The agent may call this tool at will and has root SSH to
                    # the VM. Without cleanup one call would leave roles.json —
                    # the answer key — readable for the rest of the session,
                    # defeating the same cleanup in scorer.py::_run_verify.
                    await _quiet_exec(sb, ["sh", "-c",
                        "rm -f /tmp/verify_progress.sh /tmp/eval_config.json"])
                    await _quiet_exec(sb, ["sh", "-c",
                        f"{ssh} 'sudo rm -f /tmp/verify_progress.sh "
                        f"/root/.sysrepair/config'"])
            elif os_name == "windows" and store().get("bridge_target_host"):
                # Bridge → Windows VM via SSH + powershell.exe.
                ssh = _bridge_ssh_prefix_from_store()
                host = store().get("bridge_target_host", "host.docker.internal")
                port = store().get("vagrant_port", "2223")
                user = store().get("vagrant_user", "vagrant")
                key  = store().get("bridge_ssh_key", "/root/.ssh/vagrant_key")
                scp  = (f"scp -i {key} -P {port} "
                        f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null")
                await sb.write_file("/tmp/verify_progress.ps1",
                                    (sp / "verify.ps1").read_text(encoding="utf-8"))
                await sb.write_file("/tmp/eval_config.json",
                                    (sp / "build" / "roles.json").read_text(encoding="utf-8"))
                await sb.exec(["sh", "-c",
                    f"{ssh} 'powershell.exe -NoProfile -Command "
                    f"\"New-Item -ItemType Directory -Path C:\\ProgramData\\sysrepair -Force | Out-Null\"'"])
                await sb.exec(["sh", "-c",
                    f"{scp} /tmp/verify_progress.ps1 {user}@{host}:C:/ProgramData/sysrepair/verify.ps1 && "
                    f"{scp} /tmp/eval_config.json {user}@{host}:C:/ProgramData/sysrepair/roles.json"])
                try:
                    result = await sb.exec(["sh", "-c",
                        f"{ssh} 'powershell.exe -NoProfile -ExecutionPolicy Bypass "
                        f"-File C:\\ProgramData\\sysrepair\\verify.ps1'"],
                        timeout=verify_timeout)
                except TimeoutError:
                    return "Score check timed out."
                finally:
                    # Same reasoning as the FreeBSD branch: the agent is a local
                    # Administrator on the VM, so roles.json must not outlive
                    # this call.
                    await _quiet_exec(sb, ["sh", "-c",
                        "rm -f /tmp/verify_progress.ps1 /tmp/eval_config.json"])
                    await _quiet_exec(sb, ["sh", "-c",
                        f"{ssh} 'powershell.exe -NoProfile -Command "
                        f"\"Remove-Item -Force -ErrorAction SilentlyContinue "
                        f"C:\\ProgramData\\sysrepair\\verify.ps1,"
                        f"C:\\ProgramData\\sysrepair\\roles.json\"'"])
            elif os_name == "windows":
                src_file = sp / "verify.ps1"
                if not src_file.exists():
                    src_file = sp / "verify.sh"
                try:
                    await _ps_write_file(sb, "C:/verify_progress.ps1",
                                         src_file.read_text(encoding="utf-8"))
                except RuntimeError as e:
                    return f"Score check unavailable: {e}"
                argv = ["powershell.exe", "-NoProfile", "-ExecutionPolicy",
                        "Bypass", "-File", "C:/verify_progress.ps1"]
                try:
                    result = await sb.exec(argv, timeout=verify_timeout)
                except TimeoutError:
                    return "Score check timed out."
                finally:
                    await _quiet_exec(sb, [
                        "powershell.exe", "-NoProfile", "-Command",
                        "Remove-Item -Force -ErrorAction SilentlyContinue "
                        "'C:/verify_progress.ps1'",
                    ], timeout=10)
            else:
                try:
                    await sb.write_file("/tmp/verify_progress.sh",
                                        (sp / "verify.sh").read_text(encoding="utf-8"))
                    await sb.exec(["chmod", "+x", "/tmp/verify_progress.sh"])
                except RuntimeError as e:
                    return f"Score check unavailable: {e}"
                # seed.sh deletes /etc/sysrepair/roles.json from the image, and
                # verify.sh refuses to score without it ("tamper detected;
                # scoring 0"). Re-inject the pristine copy for the duration of
                # this check exactly as scorer.py::_run_verify does, then erase
                # it again. Without this the tool returns "No checks passing
                # yet." on every call, on every Linux hivestorm scenario.
                roles_build = sp / "build" / "roles.json"
                injected_roles = False
                if roles_build.exists():
                    await sb.exec(["mkdir", "-p", "/etc/sysrepair"])
                    await sb.write_file(
                        "/etc/sysrepair/roles.json",
                        roles_build.read_text(encoding="utf-8"),
                    )
                    injected_roles = True
                argv = ["bash", "/tmp/verify_progress.sh"]
                try:
                    result = await sb.exec(argv, timeout=verify_timeout)
                except TimeoutError:
                    return "Score check timed out."
                except RuntimeError as e:
                    return f"Score check unavailable: {e}"
                finally:
                    await _quiet_exec(sb, ["rm", "-f", "/tmp/verify_progress.sh"])
                    if injected_roles:
                        await _quiet_exec(
                            sb, ["rm", "-f", "/etc/sysrepair/roles.json"])
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


def _tools(timeout: int = 180, use_text_editor: bool = True, os_name: str = "linux"):
    tools = [_shell_tool(timeout), think()]
    if use_text_editor:
        if os_name == "windows":
            tools.append(_windows_text_editor(timeout))
        else:
            tools.append(text_editor())
    return tools


def _prime_os(state: TaskState) -> None:
    """Copy sample OS metadata into the per-sample store so tools can see it."""
    store().set("os", state.metadata.get("os", "linux"))
    # Bridge metadata for Vagrant-backed VM scenarios (e.g. FreeBSD).
    for key in ("vagrant_port", "vagrant_user", "bridge_target_host", "bridge_ssh_key"):
        if key in state.metadata:
            store().set(key, state.metadata[key])


# ---------------------------------------------------------------------------
# Verify helper (used by reflexion / plan_and_solve / lats mid-run)
# ---------------------------------------------------------------------------

async def _verify_in_sandbox(
    scenario_path: str, timeout: int = 300, os_name: str = "linux"
) -> bool:
    """Run the scenario's verify script inside the sandbox.

    Picks verify.ps1 + PowerShell on Windows, verify.sh + bash on Linux, and
    for FreeBSD (bridge container) SCPs verify.sh to the VM then runs it via SSH.
    """
    sp = Path(scenario_path)
    sb = sandbox()
    try:
        if os_name == "freebsd":
            ssh = _bridge_ssh_prefix_from_store()
            host = store().get("bridge_target_host", "host.docker.internal")
            port = store().get("vagrant_port", "2222")
            user = store().get("vagrant_user", "vagrant")
            key  = store().get("bridge_ssh_key", "/root/.ssh/vagrant_key")
            scp  = (f"scp -i {key} -P {port} "
                    f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null")
            await sb.write_file("/tmp/verify.sh",
                                (sp / "verify.sh").read_text(encoding="utf-8"))
            await sb.write_file("/tmp/eval_config.json",
                                (sp / "build" / "roles.json").read_text(encoding="utf-8"))
            await sb.exec(["sh", "-c",
                f"{ssh} 'mkdir -p /root/.sysrepair && chmod 700 /root/.sysrepair'"],
                timeout=30)
            await sb.exec(["sh", "-c",
                f"{scp} /tmp/verify.sh {user}@{host}:/tmp/verify.sh && "
                f"{scp} /tmp/eval_config.json {user}@{host}:/root/.sysrepair/config"],
                timeout=30)
            result = await sb.exec(["sh", "-c",
                f"{ssh} 'chmod +x /tmp/verify.sh && sudo sh /tmp/verify.sh'"],
                timeout=timeout)
        elif os_name == "windows" and store().get("bridge_target_host"):
            ssh = _bridge_ssh_prefix_from_store()
            host = store().get("bridge_target_host", "host.docker.internal")
            port = store().get("vagrant_port", "2223")
            user = store().get("vagrant_user", "vagrant")
            key  = store().get("bridge_ssh_key", "/root/.ssh/vagrant_key")
            scp  = (f"scp -i {key} -P {port} "
                    f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null")
            await sb.write_file("/tmp/verify.ps1",
                                (sp / "verify.ps1").read_text(encoding="utf-8"))
            await sb.write_file("/tmp/eval_config.json",
                                (sp / "build" / "roles.json").read_text(encoding="utf-8"))
            await sb.exec(["sh", "-c",
                f"{ssh} 'powershell.exe -NoProfile -Command "
                f"\"New-Item -ItemType Directory -Path C:\\ProgramData\\sysrepair -Force | Out-Null\"'"],
                timeout=30)
            await sb.exec(["sh", "-c",
                f"{scp} /tmp/verify.ps1 {user}@{host}:C:/ProgramData/sysrepair/verify.ps1 && "
                f"{scp} /tmp/eval_config.json {user}@{host}:C:/ProgramData/sysrepair/roles.json"],
                timeout=30)
            result = await sb.exec(["sh", "-c",
                f"{ssh} 'powershell.exe -NoProfile -ExecutionPolicy Bypass "
                f"-File C:\\ProgramData\\sysrepair\\verify.ps1'"],
                timeout=timeout)
        elif os_name == "windows":
            src_file = sp / "verify.ps1"
            if not src_file.exists():
                src_file = sp / "verify.sh"  # fallback
            # write_file() shells out to `sh` and fails on Windows containers;
            # use the PowerShell helper instead.
            await _ps_write_file(sb, "C:/verify.ps1",
                                 src_file.read_text(encoding="utf-8"))
            result = await sb.exec([
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", "C:/verify.ps1",
            ], timeout=timeout)
        else:
            await sb.write_file("/tmp/verify.sh",
                                (sp / "verify.sh").read_text(encoding="utf-8"))
            await sb.exec(["chmod", "+x", "/tmp/verify.sh"], timeout=30)
            result = await sb.exec(["bash", "/tmp/verify.sh"], timeout=timeout)
    except (TimeoutError, RuntimeError):
        return False
    finally:
        if os_name == "windows":
            await sb.exec(
                ["powershell.exe", "-Command", "Remove-Item -Force 'C:/verify.ps1'"],
                timeout=10,
            )
        elif os_name != "freebsd":
            await sb.exec(["rm", "-f", "/tmp/verify.sh"], timeout=10)
    return result.returncode == 0


def _shell_exec_argv(os_name: str, command: str) -> list[str]:
    if os_name == "windows":
        return ["powershell.exe", "-NoProfile", "-Command", command]
    return ["bash", "-lc", command]


# ---------------------------------------------------------------------------
# Attempt metering
# ---------------------------------------------------------------------------
# One attempt = one full solver episode followed by ONE grading call. That is
# what `submit` costs in react, and every other solver is held to the same
# meter so pass@k means the same thing across the registry.
#
# INVARIANT (passk.py depends on it): only attempt-boundary grading goes
# through inspect_ai.scorer.score(). Every in-episode oracle call — hivestorm's
# score_progress tool, LATS's in-search verify — uses raw sandbox().exec() and
# therefore emits no ScoreEvent. Routing either through score() would inflate
# the intermediate-event count and corrupt every extracted pass@j.

# Deliberately carries ONE bit: the submission was not accepted. It names no
# failure mode, no check, no score. Anything more would leak the grader and turn
# pass@k into a measure of iterating against verify.sh rather than of
# independent repair attempts. The binary signal itself is unavoidable —
# without it a retry is not a retry — and matches inspect's stock react default
# (agent/_types.py:77-79).
ATTEMPT_INCORRECT_MESSAGE = (
    "Your submission was incorrect. Please continue working and call submit() "
    "again when you believe the task is complete."
)


def _with_attempts(inner: Solver, attempts: int) -> Solver:
    """Meter `inner`'s grading calls at `attempts`.

    Mirrors inspect's react control flow exactly (_react.py:261-269): the loop
    breaks *before* grading the final attempt, so a k-attempt run emits exactly
    k-1 intermediate ScoreEvents and the k-th outcome comes from the
    end-of-sample scorer. passk.py reconstructs the curve from that shape.
    """
    if attempts <= 1:
        return inner

    @solver
    def _metered_attempts() -> Solver:
        async def solve(state: TaskState, generate: Generate) -> TaskState:
            to_float = value_to_float()
            for i in range(attempts):
                state = await inner(state, generate)
                if i >= attempts - 1:
                    break  # end-of-sample scorer grades the final attempt
                scores = await score_state(state)
                if scores and to_float(scores[0].value) == 1.0:
                    state.output.completion = "REMEDIATION_COMPLETE"
                    break
                state.messages.append(
                    ChatMessageUser(content=ATTEMPT_INCORRECT_MESSAGE)
                )
                # plan_and_solve and lats rebuild their prompts from
                # state.input_text each episode and never read state.messages,
                # so the message above alone would leave them resampling
                # blindly. Record the SAME binary signal where they can reach it.
                #
                # Deliberately does NOT include scores[0].explanation. That field
                # is the raw verifier output (scorer.py:195 —
                # result.stdout + result.stderr; the full JSONL check list for
                # hivestorm). Feeding it back would hand the model the grader and
                # turn pass@k into "iterate against verify.sh" instead of a
                # measure of independent repair attempts.
                state.metadata.setdefault("attempt_feedback", []).append(
                    f"Attempt {i + 1} was graded and did NOT pass."
                )
                state.completed = False  # re-arm; solvers set this on submit
            return state
        return solve

    return _metered_attempts()


def _attempt_context(state: TaskState) -> str:
    """Prior-attempt feedback, for solvers that rebuild prompts from scratch."""
    feedback = (state.metadata or {}).get("attempt_feedback") or []
    if not feedback:
        return ""
    return (
        "\n\n## Previous attempts (this container, already graded)\n"
        + "\n\n".join(feedback)
        + "\n\nDo not repeat what already failed. Change your approach."
    )


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
            os_name = state.metadata.get("os", "linux")
            is_hardy = state.metadata.get("benchmark") == "meta2"
            tools = _tools(bash_timeout, use_text_editor=not is_hardy, os_name=os_name)
            if is_hardy:
                tools.append(_hardy_text_editor(bash_timeout))
            if state.metadata.get("scorer") == "hivestorm_weighted":
                scenario_path = state.metadata.get("scenario_path", "")
                tools = tools + [_score_progress_tool(scenario_path, verify_timeout)]

            rl = get_rate_limiter()

            async def throttled_generate(state: TaskState, **kwargs) -> TaskState:
                await rl.acquire()
                return await generate(state, **kwargs)

            # react's native attempts loop already implements the metering
            # contract (_react.py:261-269): it breaks before grading the final
            # attempt, so it emits k-1 intermediate ScoreEvents via score().
            # Left native rather than routed through _with_attempts — same
            # observable contract, no re-entry risk.
            inner = as_solver(react(
                tools=tools,
                # Same score-free message every solver uses, so the between-
                # attempt signal is identical across the registry. Inspect's
                # default is also static, but differently worded — pinning it
                # keeps cross-solver pass@k comparable. A callable here would
                # receive the scores; deliberately not used.
                attempts=AgentAttempts(
                    attempts=max_attempts,
                    incorrect_message=ATTEMPT_INCORRECT_MESSAGE,
                ),
                on_continue=(
                    "Please proceed with the next remediation step. "
                    "If you believe the vulnerability is fully fixed and the service "
                    "still works, call submit() with a short summary."
                ),
            ))
            return await inner(state, throttled_generate)
        return solve

    return _wrapped()


# ---------------------------------------------------------------------------
# 2. Basic / Raw computer use — minimal generate+tool loop
# ---------------------------------------------------------------------------

@solver
def basic_solver(message_limit: int = 40, bash_timeout: int = 180) -> Solver:
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        _prime_os(state)
        os_name = state.metadata.get("os", "linux")
        state.tools = _tools(bash_timeout, os_name=os_name)
        for _ in range(message_limit):
            state = await _rate_limited_generate(generate, state)
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
        os_name = state.metadata.get("os", "linux")
        original_input = state.input_text
        correction = ""
        model = get_model()
        to_float = value_to_float()

        for cycle in range(max_cycles):
            sys_prompt = original_input
            if correction:
                sys_prompt += f"\n\n## Lessons from previous attempt\n{correction}"

            inner = react(
                tools=_tools(bash_timeout, os_name=os_name),
                attempts=1,
                on_continue="Continue, or call submit() if remediation is complete.",
            )
            inner_state = AgentState(
                messages=[
                    ChatMessageUser(content=sys_prompt + "\n\nBegin. Investigate and remediate the vulnerability."),
                ]
            )
            inner_state = await inner(inner_state)
            state.messages.extend(inner_state.messages[1:])  # skip dup system

            # Break BEFORE grading the final cycle, matching react
            # (_react.py:261-269), so the intermediate-event count is
            # max_cycles-1 and passk.py sees the same shape for every solver.
            if cycle >= max_cycles - 1:
                break

            scores = await score_state(state)
            if scores and to_float(scores[0].value) == 1.0:
                state.output.completion = "REMEDIATION_COMPLETE"
                return state

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
            await get_rate_limiter().acquire()
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
        os_name = state.metadata.get("os", "linux")
        model = get_model()
        sys_text = state.input_text + _attempt_context(state)

        plan_prompt = (
            "Produce a remediation plan as JSON only, no prose:\n"
            '{"steps": [{"id": 1, "description": "...", "command": "single bash cmd"}, ...]}\n'
            f"Maximum {max_plan_steps} steps, in dependency order."
        )
        await get_rate_limiter().acquire()
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
                await get_rate_limiter().acquire()
                fix_resp = await model.generate(
                    input=[
                        ChatMessageSystem(content=sys_text),
                        ChatMessageUser(content=fix_prompt),
                    ]
                )
                cmd = (fix_resp.completion or "").strip().strip("`")
                if cmd.startswith("bash\n"):
                    cmd = cmd[5:]

        # No per-step grading: one attempt = plan -> execute the whole plan ->
        # one grade at the episode boundary (applied by _with_attempts). The
        # old per-step _verify_in_sandbox gave this solver uncapped oracle
        # access that react never had.
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
        sys_text = state.input_text + _attempt_context(state)
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
            await get_rate_limiter().acquire()
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
                await get_rate_limiter().acquire()
                resp = await model.generate(
                    input=[
                        ChatMessageSystem(content=sys_text),
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
        # Drives its own attempt loop natively (_react.py:261-269).
        return _react_solver(message_limit, max_attempts, bash_timeout, verify_timeout)
    if name == "basic":
        return _with_attempts(
            basic_solver(message_limit=message_limit, bash_timeout=bash_timeout),
            max_attempts,
        )
    if name == "reflexion":
        # Its reflect-and-retry cycle IS the attempt loop, so meter it there
        # rather than wrapping. Previously pinned at 3 cycles regardless of k.
        return reflexion_solver(
            message_limit=message_limit,
            max_cycles=max_attempts,
            bash_timeout=bash_timeout,
            verify_timeout=verify_timeout,
        )
    if name in ("plan_and_solve", "plan-and-solve", "pas"):
        return _with_attempts(
            plan_and_solve_solver(
                message_limit=message_limit,
                bash_timeout=bash_timeout,
                verify_timeout=verify_timeout,
            ),
            max_attempts,
        )
    if name == "lats":
        # One attempt = one full search. Its in-search _verify_in_sandbox stays
        # uncapped by design: that is the algorithm's terminal reward feeding
        # backprop/UCB, not a submission. It uses raw sandbox exec, so it emits
        # no ScoreEvent and cannot corrupt the extracted pass@j curve. LATS
        # therefore gets more oracle access per attempt than any other solver —
        # documented, not silently ranked against react on pass@1.
        return _with_attempts(
            lats_solver(
                message_limit=message_limit,
                bash_timeout=bash_timeout,
                verify_timeout=verify_timeout,
            ),
            max_attempts,
        )
    raise ValueError(
        f"Unknown solver '{name}'. "
        "Choose from: react, basic, reflexion, plan_and_solve, lats."
    )

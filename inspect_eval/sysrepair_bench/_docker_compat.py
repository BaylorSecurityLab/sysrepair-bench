"""Runtime patches for inspect_ai's Docker sandbox to support Windows containers.

inspect_ai's `DockerSandboxEnvironment.exec()` is hard-coded for Linux containers:
- It prepends `["timeout", "-k", "5s", "{N}s", *cmd]` to every command, expecting
  GNU `timeout`. On Windows containers `timeout.exe` is a sleep utility with
  incompatible syntax that fails every exec with:
  `ERROR: Invalid syntax. Default option is not allowed more than '1' time(s).`
- It adds `--workdir <PurePosixPath>` to `docker compose exec`. The default
  fallback when `sh -c pwd` fails is `/`, which isn't a meaningful Windows path.

This module monkey-patches `DockerSandboxEnvironment.exec()` so that when the
command being executed targets a Windows binary (`*.exe`, `powershell`, `cmd`,
`pwsh`), we:
- skip the GNU timeout wrap; enforce the timeout at the asyncio level instead
  (we lose in-container process-tree cleanup on timeout, accepting zombie risk)
- skip `--workdir /` (it's the failure-mode default, not a real cwd)

Linux scenarios are untouched — the patch falls through to the original
implementation for any non-Windows command.

Importing this module applies the patch as a side effect.
"""

from __future__ import annotations

import asyncio

from inspect_ai.util._sandbox.docker.compose import compose_exec
from inspect_ai.util._sandbox.docker.docker import DockerSandboxEnvironment
from inspect_ai.util._sandbox.limits import SandboxEnvironmentLimits


def _is_windows_cmd(cmd: list[str]) -> bool:
    if not cmd:
        return False
    first = cmd[0].lower()
    return (
        first.endswith(".exe")
        or first in ("powershell", "pwsh", "cmd")
        or "\\" in cmd[0]
    )


_original_exec = DockerSandboxEnvironment.exec


async def _patched_exec(
    self,
    cmd: list[str],
    input=None,
    cwd=None,
    env=None,
    user=None,
    timeout: int | None = None,
    timeout_retry: bool = True,
    concurrency: bool = True,
):
    if not _is_windows_cmd(cmd):
        return await _original_exec(
            self,
            cmd,
            input=input,
            cwd=cwd,
            env=env,
            user=user,
            timeout=timeout,
            timeout_retry=timeout_retry,
            concurrency=concurrency,
        )

    args: list[str] = []
    # Only forward --workdir if a real cwd was given. The default `/` fallback
    # (set when `sh -c pwd` failed during sandbox init) isn't a Windows path.
    if cwd is not None:
        args.extend(["--workdir", str(cwd)])
    if user:
        args.extend(["--user", user])
    if env:
        for key, value in env.items():
            args.extend(["--env", f"{key}={value}"])

    async def _do_exec():
        return await compose_exec(
            args + [self._service] + list(cmd),
            project=self._project,
            timeout=None,
            timeout_retry=timeout_retry,
            input=input,
            output_limit=SandboxEnvironmentLimits.MAX_EXEC_OUTPUT_SIZE,
            concurrency=concurrency,
        )

    if timeout is not None:
        try:
            return await asyncio.wait_for(_do_exec(), timeout=timeout + 10)
        except asyncio.TimeoutError:
            raise TimeoutError(f"Command timed out after {timeout} seconds")
    return await _do_exec()


DockerSandboxEnvironment.exec = _patched_exec

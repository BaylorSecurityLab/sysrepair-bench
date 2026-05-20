"""Runtime patches for inspect_ai cancellation / shielding bugs.

These patches address the per-sample ``time_limit`` hang on Windows Docker
sandboxes documented in the audit (see ``docs/inspect_ai_audit.md`` if
present, or the project commit history). Root cause: Inspect ships several
``anyio.CancelScope(shield=...)`` sites whose ``shield`` is conditional on
having caught a ``CancelledError`` — but ``time_limit`` raises
``LimitExceededError``, not ``CancelledError``, so the shield doesn't engage
and critical cleanup / logging runs unprotected inside an already-fired
parent cancel scope.

We apply three runtime patches without modifying inspect_ai on disk:

* **Fix #2** — wrap ``inspect_ai._eval.task.run.log_sample`` in
  ``anyio.CancelScope(shield=True)`` so the end-of-sample log write always
  completes. Without this, the ``_journal/summaries/N.json`` and sample JSON
  for any sample killed by ``time_limit`` is silently lost.
* **Fix #3** — wrap ``inspect_ai.util._sandbox.docker.compose.compose_down``
  in a shield so the docker ``compose down --volumes`` call gets its full
  internal 300 s budget instead of being cancelled mid-flight, leaving the
  sample coroutine parked indefinitely waiting on a half-torn-down sandbox.
  Patched in two namespaces because ``cleanup.py`` did
  ``from .compose import compose_down`` at import time.
* **Fix #4** — shorten the SIGTERM grace period in
  ``inspect_ai.util._subprocess.gracefully_terminate_cancelled_subprocess``
  from 2 s to 0.25 s so docker subprocesses cancelled during cleanup die
  promptly. The original is already correctly shielded; we just make it
  faster so the cleanup path doesn't dawdle when we're trying to fail fast.

Each patch is idempotent (no double-wrapping), best-effort (logs and
continues if the targeted symbol disappears in a future inspect_ai release),
and tagged with ``_sysrepair_patched`` for introspection.

Import this module *before* any code that calls ``inspect_ai.eval(...)``;
``sysrepair_bench/__init__.py`` does so as its first statement.

Skipped from the audit:
* **Fix #1** (``_eval/task/sandbox.py`` shield) — requires replacing the
  entire ``sandboxenv_context`` async context manager (~150 lines). Fix #3
  closes the same hang at a lower layer with a 10-line patch.
* The launcher's own preflight / watchdog / ``--cleanup`` remain in place as
  belt-and-suspenders for cases the cancel path still can't handle (e.g. a
  ``docker compose down`` that itself blocks beyond the inner 300 s).
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable

import anyio

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Fix #2 — shield sample-end log writes
# ---------------------------------------------------------------------------

def _patch_log_sample() -> None:
    try:
        from inspect_ai._eval.task import run as _run
    except Exception as e:  # pragma: no cover - defensive on version skew
        log.warning("[inspect-compat] skip fix #2: cannot import _eval.task.run (%s)", e)
        return

    orig: Callable[..., Awaitable[Any]] | None = getattr(_run, "log_sample", None)
    if orig is None:
        log.warning("[inspect-compat] skip fix #2: log_sample missing on _eval.task.run")
        return
    if getattr(orig, "_sysrepair_patched", False):
        return

    async def log_sample_shielded(*args: Any, **kwargs: Any) -> Any:
        # End-of-sample write must complete or the journal summary is lost
        # whenever time_limit raises (since time_limit -> LimitExceededError,
        # not CancelledError, Inspect's own shield at run.py:1199 is False).
        with anyio.CancelScope(shield=True):
            return await orig(*args, **kwargs)

    log_sample_shielded._sysrepair_patched = True       # type: ignore[attr-defined]
    log_sample_shielded._sysrepair_wraps = orig          # type: ignore[attr-defined]
    _run.log_sample = log_sample_shielded                # type: ignore[assignment]
    log.info("[inspect-compat] fix #2 applied: log_sample shielded")


# ---------------------------------------------------------------------------
# Fix #3 — shield docker compose down
# ---------------------------------------------------------------------------

def _patch_compose_down() -> None:
    try:
        from inspect_ai.util._sandbox.docker import compose as _compose
        from inspect_ai.util._sandbox.docker import cleanup as _cleanup
    except Exception as e:  # pragma: no cover
        log.warning("[inspect-compat] skip fix #3: cannot import docker sandbox modules (%s)", e)
        return

    orig: Callable[..., Awaitable[None]] | None = getattr(_compose, "compose_down", None)
    if orig is None:
        log.warning("[inspect-compat] skip fix #3: compose_down missing on docker.compose")
        return
    if getattr(orig, "_sysrepair_patched", False):
        return

    async def compose_down_shielded(project: Any, quiet: bool = True) -> None:
        # The 300 s internal timeout inside compose_down only matters if the
        # function is allowed to run. Outer time_limit cancellation would
        # otherwise abort it at the first await checkpoint, leaving the
        # sample coroutine stuck on a half-torn-down sandbox forever.
        with anyio.CancelScope(shield=True):
            return await orig(project, quiet=quiet)

    compose_down_shielded._sysrepair_patched = True     # type: ignore[attr-defined]
    compose_down_shielded._sysrepair_wraps = orig        # type: ignore[attr-defined]
    _compose.compose_down = compose_down_shielded        # type: ignore[assignment]
    # cleanup.py: `from .compose import compose_down` captured a bound name
    # at import time. Overwriting the module attribute alone wouldn't reach
    # that call site — patch the import target too.
    if hasattr(_cleanup, "compose_down"):
        _cleanup.compose_down = compose_down_shielded    # type: ignore[assignment]
    log.info("[inspect-compat] fix #3 applied: compose_down shielded in compose + cleanup")


# ---------------------------------------------------------------------------
# Fix #4 — faster subprocess kill on cancel (reduce SIGTERM grace 2s → 0.25s)
# ---------------------------------------------------------------------------

def _patch_subprocess_kill() -> None:
    try:
        from inspect_ai.util import _subprocess as _sp
    except Exception as e:  # pragma: no cover
        log.warning("[inspect-compat] skip fix #4: cannot import util._subprocess (%s)", e)
        return

    orig = getattr(_sp, "gracefully_terminate_cancelled_subprocess", None)
    if orig is None:
        log.warning("[inspect-compat] skip fix #4: gracefully_terminate_cancelled_subprocess missing")
        return
    if getattr(orig, "_sysrepair_patched", False):
        return

    # Resolve helpers used in the original — keep imports inside the patch
    # body so any rename surfaces at call time, not import time.
    drain_stream = getattr(_sp, "drain_stream", None)
    create_task_group = anyio.create_task_group

    async def terminate_fast(process: Any) -> None:
        # Original: terminate -> sleep(2) -> kill if still alive. The 2 s
        # grace is paid on every cancelled subprocess, including the docker
        # CLI in our cleanup path where we *want* immediate death. Drop to
        # 0.25 s — long enough for a well-behaved process to flush, short
        # enough that a hung docker compose doesn't burn another two seconds
        # of every sample's last-gasp budget.
        with anyio.CancelScope(shield=True):
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            try:
                await anyio.sleep(0.25)
            except Exception:
                pass
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            # Drain stdout/stderr before process.wait() to avoid the asyncio
            # backend deadlock the upstream code documents at this site.
            if drain_stream is not None:
                try:
                    async with create_task_group() as tg:
                        tg.start_soon(drain_stream, process.stdout)
                        tg.start_soon(drain_stream, process.stderr)
                except Exception:
                    pass
            try:
                await process.wait()
            except ProcessLookupError:
                pass

    terminate_fast._sysrepair_patched = True            # type: ignore[attr-defined]
    terminate_fast._sysrepair_wraps = orig               # type: ignore[attr-defined]
    _sp.gracefully_terminate_cancelled_subprocess = terminate_fast  # type: ignore[assignment]
    log.info("[inspect-compat] fix #4 applied: terminate grace 2s -> 0.25s")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def apply_patches() -> None:
    """Apply all monkey-patches. Idempotent — safe to call multiple times."""
    _patch_log_sample()
    _patch_compose_down()
    _patch_subprocess_kill()


# Apply on import (matches the side-effect pattern of _docker_compat.py).
apply_patches()

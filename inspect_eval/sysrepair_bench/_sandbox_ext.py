"""Inspect AI extension: teach the docker sandbox how to read our logs back.

Applied on import. ``sysrepair_bench/__init__.py`` imports this module, so
anything inside the package (``run``, ``passk``, ``summarize``) gets it for
free. For Inspect's own CLI use the ``sysrepair_bench.view`` wrapper — plain
``inspect view`` cannot pick this up (see "Why not an entry point" below).

Why not an inspect_ai entry point
---------------------------------
``registry_find`` (``_util/registry.py:236-238``) only calls
``ensure_entry_points()`` when a lookup returns **empty**. The built-in docker
sandbox is always already registered, so the lookup succeeds and extensions
never load. Entry points can introduce providers that would otherwise miss;
they cannot patch a built-in.

The problem
-----------
``task.py`` stores a ``SysRepairComposeConfig`` (ComposeConfig plus cap_add /
privileged / isolation / security_opt / extra_hosts) as each sample's sandbox
spec. Inspect serializes it into the ``.eval`` log happily. Reading it back
calls ``deserialize_sandbox_specific_config()``, which:

1. resolves the provider via ``registry_find_sandboxenv("docker")`` — this is
   what triggers entry-point loading, and therefore this module;
2. tries a plain ``ComposeConfig.model_validate()``, which rejects our extra
   service fields;
3. falls through to ``DockerSandboxEnvironment.config_deserialize()``, which
   raises ``NotImplementedError`` by default.

Net effect without this: ``read_eval_log(header_only=False)`` blows up on every
log this repo produces. Header-only reads are unaffected, which is why it stayed
hidden until something needed per-sample events.

Inspect's own docstring for ``config_deserialize`` sanctions exactly this
override ("Override this method if you support a custom configuration model").
"""

from __future__ import annotations

from inspect_ai.util._sandbox.docker.docker import DockerSandboxEnvironment

from ._compose import SysRepairComposeConfig

_PATCH_FLAG = "_sysrepair_config_deserialize"


def _config_deserialize(cls, config: dict):
    return SysRepairComposeConfig.model_validate(config)


def register() -> None:
    """Idempotently install config_deserialize on the docker provider."""
    if getattr(DockerSandboxEnvironment, _PATCH_FLAG, False):
        return
    DockerSandboxEnvironment.config_deserialize = classmethod(_config_deserialize)
    setattr(DockerSandboxEnvironment, _PATCH_FLAG, True)


# Import-time side effect: entry-point loading imports this module and expects
# registration to have happened by the time it returns.
register()

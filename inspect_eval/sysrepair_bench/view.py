"""Wrapper around the ``inspect`` CLI that can read SysRepair-Bench logs.

Why this exists
---------------
Our samples carry a ``SysRepairComposeConfig`` sandbox spec (ComposeConfig plus
cap_add / privileged / isolation / security_opt / extra_hosts). Reading a log
back calls ``deserialize_sandbox_specific_config()``, which tries a plain
``ComposeConfig.model_validate()`` (rejects our extra service fields) and then
falls through to ``DockerSandboxEnvironment.config_deserialize()``, which raises
``NotImplementedError``. ``_sandbox_ext`` installs that missing method.

Why not an inspect_ai entry point
---------------------------------
Entry points cannot help here. ``registry_find`` (``_util/registry.py:236-238``)
only calls ``ensure_entry_points()`` when a lookup returns **empty**:

    o = _find()
    if len(o) == 0:
        ensure_entry_points()
        return _find()

The built-in docker sandbox is already registered, so the lookup succeeds
immediately and extensions are never loaded. Entry points can only introduce
providers that would otherwise miss — they cannot patch a built-in. Hence a
wrapper that imports the extension before handing off to Inspect's CLI.

Usage — anywhere you would type ``inspect``::

    uv run python -m sysrepair_bench.view view --log-dir ./logs
    uv run python -m sysrepair_bench.view log dump ./logs/foo.eval

Plain ``inspect view`` still fails on these logs; use this instead.
"""

from __future__ import annotations

import sys

from . import _sandbox_ext  # noqa: F401  installs config_deserialize on import


def main(argv: list[str] | None = None) -> None:
    from inspect_ai._cli.main import main as inspect_main

    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        args = ["view"]
    # Click reads sys.argv itself; argv[0] becomes the program name in --help.
    sys.argv = ["inspect", *args]
    inspect_main()


if __name__ == "__main__":
    main()

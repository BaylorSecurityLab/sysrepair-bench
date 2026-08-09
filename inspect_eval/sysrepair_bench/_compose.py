"""Compose config models for SysRepair-Bench sandboxes.

Deliberately dependency-light: this module is imported by ``_sandbox_ext``,
which runs as an ``inspect_ai`` entry point on *every* Inspect process —
including ``inspect view``. Importing ``task.py`` there would drag in the whole
scenario-discovery graph for no reason, so the models live here on their own.
"""

from __future__ import annotations

from inspect_ai.util._sandbox.compose import ComposeConfig, ComposeService


class SysRepairService(ComposeService):
    """ComposeService extended with cap_add, privileged, isolation, and
    security_opt so scenarios that need firewall state (iptables/nftables),
    full kernel access (k3s), Hyper-V isolation (Windows), or specific Docker
    security profiles (seccomp/AppArmor) work.

    extra_hosts is used by the FreeBSD bridge container to resolve
    host.docker.internal → the Docker host, where Vagrant forwards port 2222."""

    cap_add: list[str] | None = None
    privileged: bool | None = None
    isolation: str | None = None
    security_opt: list[str] | None = None
    extra_hosts: list[str] | None = None
    # compose's `cgroup:` — the equivalent of `docker run --cgroupns=<mode>`.
    # k3s needs `host` even when privileged: without it the kubelet dies with
    # 'cannot enter cgroupv2 "/sys/fs/cgroup/kubepods" with domain controllers'
    # and the node never reaches Ready. Five scenarios declared --cgroupns=host
    # in .run-opts while the parser silently discarded it, so they booted dead.
    cgroup: str | None = None


class SysRepairComposeConfig(ComposeConfig):
    """ComposeConfig with a typed ``services`` dict of SysRepairService so the
    cap_add field survives Pydantic's polymorphic dump (declared-type wins)."""

    services: dict[str, SysRepairService]

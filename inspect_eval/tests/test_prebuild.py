"""Tests for the scenario image prebuild stage.

Prebuild exists so a metered GPU allocation is not spent running `docker build`.
That only holds if it builds the SAME images the eval would, the same way — so
these tests pin the places where "same" is non-obvious and where an earlier
version of this module got it wrong:

- base-image specs come from run.BASE_IMAGES, not a second table that silently
  drops --isolation=hyperv
- a scenario's OS is not its image's OS, and the image's OS may only be
  discoverable through an ARG default or a locally-built base
- the build context is not always the scenario directory
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sysrepair_bench import prebuild  # noqa: E402
from sysrepair_bench.run import BASE_IMAGES  # noqa: E402

REPO = Path(__file__).resolve().parents[2]

WIN_BASE = "sysrepair/meta3-win-base:ltsc2019"
HARDY_BASE = "sysrepair/meta2-hardy:latest"


# --------------------------------------------------------------- single source

def test_prebuild_has_no_second_base_table():
    """The duplicate LOCAL_BASES table must stay gone.

    It drifted from run.BASE_IMAGES the moment it existed: it omitted
    --isolation=hyperv, so a Windows base build would fail on Win 10/11 Home
    with an error that points at the Dockerfile rather than the isolation mode.
    """
    assert not hasattr(prebuild, "LOCAL_BASES"), (
        "prebuild defines its own base-image table again; use run.BASE_IMAGES"
    )


def test_base_spec_reads_run_base_images(monkeypatch):
    """_base_spec must resolve through run.BASE_IMAGES, not a copy."""
    sentinel_ctx = Path("/sentinel/ctx")
    monkeypatch.setitem(BASE_IMAGES, "sysrepair/probe:latest", (sentinel_ctx, []))
    ctx, dockerfile, extra = prebuild._base_spec("sysrepair/probe:latest")
    assert ctx == sentinel_ctx
    assert dockerfile == sentinel_ctx / "Dockerfile"
    assert extra == []


def test_windows_base_carries_hyperv_isolation():
    """The flag whose absence was the reason for collapsing the tables."""
    _ctx, _df, extra = prebuild._base_spec(WIN_BASE)
    assert "--isolation=hyperv" in extra


def test_base_spec_honours_dash_f_override():
    """meta3-win-base's Dockerfile is NOT at <context>/Dockerfile.

    Its context is widened to meta3/windows so the base can COPY from
    shared/downloads/, and the real Dockerfile path arrives as `-f <path>`
    inside the extra flags.
    """
    ctx, dockerfile, _extra = prebuild._base_spec(WIN_BASE)
    assert ctx.as_posix().endswith("meta3/windows")
    assert dockerfile.as_posix().endswith("meta3/windows/base/Dockerfile")
    assert dockerfile.parent != ctx, "the -f override was not applied"


def test_hardy_base_uses_default_dockerfile():
    ctx, dockerfile, extra = prebuild._base_spec(HARDY_BASE)
    assert dockerfile == ctx / "Dockerfile"
    assert extra == []


# ------------------------------------------------------------- build-arg plumbing

def _fake_run(recorder):
    class _Proc:
        returncode = 0
        stdout = ""
        stderr = ""

    def run(cmd, **kwargs):
        recorder.append(cmd)
        return _Proc()

    return run


def test_build_one_passes_extra_flags_without_duplicating_f(monkeypatch):
    """--isolation=hyperv must reach docker; -f must appear exactly once.

    The flag list from BASE_IMAGES already contains `-f <path>`, and _build_one
    passes `-f` explicitly, so a naive splat would emit it twice.
    """
    calls: list[list[str]] = []
    monkeypatch.setattr(prebuild.subprocess, "run", _fake_run(calls))
    _ctx, dockerfile, extra = prebuild._base_spec(WIN_BASE)

    prebuild._build_one(REPO / "meta3" / "windows", WIN_BASE, quiet=False,
                        dockerfile=dockerfile, extra_flags=extra)

    cmd = calls[0]
    assert "--isolation=hyperv" in cmd
    assert cmd.count("-f") == 1
    assert cmd[cmd.index("-f") + 1] == str(dockerfile)


def test_build_one_scopes_engine_without_mutating_global(monkeypatch):
    """--context scopes the daemon per command; never `docker context use`."""
    calls: list[list[str]] = []
    monkeypatch.setattr(prebuild.subprocess, "run", _fake_run(calls))
    prebuild._build_one(REPO / "meta2" / "_base", HARDY_BASE, quiet=False,
                        docker_context="desktop-linux")
    cmd = calls[0]
    assert cmd[:3] == ["docker", "--context", "desktop-linux"]
    assert "context" not in cmd[3:] or "use" not in cmd


# ------------------------------------------------------------------ image OS

def _write(tmp_path: Path, rel: str, text: str) -> Path:
    p = tmp_path / rel
    p.mkdir(parents=True, exist_ok=True)
    (p / "Dockerfile").write_text(text, encoding="utf-8")
    return p


def test_image_os_reads_from_line(tmp_path):
    assert prebuild._image_os(_write(tmp_path, "a", "FROM debian:11\n")) == "linux"
    assert prebuild._image_os(
        _write(tmp_path, "b", "FROM mcr.microsoft.com/windows/servercore:ltsc2019\n")
    ) == "windows"


def test_image_os_resolves_arg_default(tmp_path):
    """`ARG BASE=...servercore` + `FROM ${BASE}` reads as '${base}' literally."""
    d = _write(tmp_path, "c",
               "ARG BASE=mcr.microsoft.com/windows/servercore:ltsc2019\n"
               "FROM ${BASE}\n")
    assert prebuild._image_os(d) == "windows"


def test_image_os_ignores_platform_flag(tmp_path):
    d = _write(tmp_path, "d", "FROM --platform=linux/amd64 ubuntu:22.04 AS build\n")
    assert prebuild._image_os(d) == "linux"


def test_image_os_follows_local_base_transitively():
    """meta3/windows scenarios FROM a local tag with no OS hint in its name."""
    scenario = REPO / "meta3" / "windows" / "scenario-01-snmp"
    if not (scenario / "Dockerfile").is_file():
        pytest.skip("meta3/windows/scenario-01-snmp not present")
    assert prebuild._image_os(scenario) == "windows"


def test_scenario_os_and_image_os_can_disagree():
    """hivestorm/scenario-13 is a LINUX container that drives a Windows DC.

    task._detect_os says 'windows' (right, for prompting and scoring) and would
    send this build to the Windows engine, where `FROM debian:bookworm-slim`
    fails with a missing-manifest error.
    """
    from sysrepair_bench.task import _detect_os

    s = REPO / "hivestorm" / "scenario-13-ad-dc-win2019"
    if not (s / "Dockerfile").is_file():
        pytest.skip("hivestorm/scenario-13-ad-dc-win2019 not present")
    assert _detect_os(s) == "windows"
    assert prebuild._image_os(s) == "linux"


def test_image_os_survives_circular_from(tmp_path, monkeypatch):
    """A malformed self-referential base must not recurse forever."""
    d = _write(tmp_path, "loop", "FROM sysrepair/loop:latest\n")
    monkeypatch.setitem(BASE_IMAGES, "sysrepair/loop:latest", (d, []))
    assert prebuild._image_os(d) in {"linux", "windows"}


# -------------------------------------------------------------- build context

def test_copy_sources_parsing(tmp_path):
    d = _write(tmp_path, "cp",
               "FROM x\n"
               "COPY shared/downloads/a.zip C:/a.zip\n"
               "COPY --from=builder /out /out\n"          # stage, not context
               "ADD https://example.com/f.tgz /f.tgz\n"   # URL, not context
               "COPY --chown=1:1 rel/b.txt /b.txt\n")
    srcs = prebuild._copy_sources(d / "Dockerfile")
    assert "shared/downloads/a.zip" in srcs
    assert "rel/b.txt" in srcs
    assert not any("/out" == s for s in srcs)
    assert not any(s.startswith("https://") for s in srcs)


def test_build_context_stays_local_when_copies_resolve(tmp_path):
    d = _write(tmp_path, "loc", "FROM debian:11\nCOPY payload.txt /p\n")
    (d / "payload.txt").write_text("x", encoding="utf-8")
    assert prebuild._build_context(d) == d


def test_build_context_widens_when_copies_need_parent(tmp_path):
    """meta3/windows layout: COPY paths are relative to the benchmark dir."""
    bench = tmp_path / "bench"
    scen = bench / "scenario-01"
    scen.mkdir(parents=True)
    (scen / "Dockerfile").write_text(
        "FROM x\nCOPY shared/downloads/a.zip /a\nCOPY scenario-01/s.ps1 /s\n",
        encoding="utf-8")
    (bench / "shared" / "downloads").mkdir(parents=True)
    (bench / "shared" / "downloads" / "a.zip").write_text("z", encoding="utf-8")
    (scen / "s.ps1").write_text("p", encoding="utf-8")
    assert prebuild._build_context(scen) == bench


def test_build_context_falls_back_when_unresolvable(tmp_path):
    """A missing artifact must not silently widen; let docker name the path."""
    d = _write(tmp_path, "miss", "FROM x\nCOPY nowhere/a.zip /a\n")
    assert prebuild._build_context(d) == d


def test_real_meta3_windows_scenario_widens_context():
    scen = REPO / "meta3" / "windows" / "scenario-04-tomcat"
    if not (scen / "Dockerfile").is_file():
        pytest.skip("meta3/windows/scenario-04-tomcat not present")
    ctx = prebuild._build_context(scen)
    assert ctx == REPO / "meta3" / "windows", (
        "tomcat COPYs shared/downloads/, so its context must be the benchmark dir"
    )


def test_vulnhub_scenario_keeps_local_context():
    scen = REPO / "vulnhub" / "scenario-01"
    if not (scen / "Dockerfile").is_file():
        pytest.skip("vulnhub/scenario-01 not present")
    assert prebuild._build_context(scen) == scen

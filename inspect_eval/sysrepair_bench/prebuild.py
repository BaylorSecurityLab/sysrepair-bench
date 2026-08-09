"""Build scenario container images ahead of an eval run.

Inspect builds each scenario's image lazily, the first time a sample needs its
sandbox. That is fine locally, but it is wasteful when the model is served from
a scheduled GPU allocation: the first minutes of an expensive, time-boxed job
go to ``docker build`` and base-image pulls instead of inference.

This module does that work up front, so the eval can start the instant the
endpoint is live.

    python -m sysrepair_bench.prebuild --benchmarks vulnhub
    python -m sysrepair_bench.prebuild --preset delta_vulnhub_full
    python -m sysrepair_bench.prebuild --scenarios vulnhub/scenario-01 --jobs 2

Scenario selection reuses ``task._discover_scenarios``, so the set built here is
exactly the set the eval will run — no second source of truth to drift.

Why plain ``docker build`` rather than ``docker compose build``: Inspect creates
a compose project per sample with a generated name, so reproducing its exact
image tags would mean coupling to Inspect internals. We do not need the tag.
BuildKit keys its layer cache on the base image, the instruction sequence and
the context, none of which depend on the project name — so building the same
context with the same Dockerfile populates the very cache compose then hits.
The tag we apply is only a handle for inspection and cleanup.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from .run import BASE_IMAGES
from .task import REPO_ROOT, WINDOWS_FROM_HINTS, _advm_harness, _discover_scenarios

TAG_PREFIX = "srb-prebuild"


def _resolve_from(dockerfile: Path) -> str:
    """The effective FROM reference, with ARG defaults substituted.

    meta3/windows/base declares `ARG BASE=mcr.microsoft.com/windows/servercore:ltsc2019`
    then `FROM ${BASE}`, so reading the FROM line literally yields "${base}" and
    tells you nothing about the OS.
    """
    args: dict[str, str] = {}
    ref = ""
    for raw in dockerfile.read_text(encoding="utf-8", errors="ignore").splitlines():
        ln = raw.strip()
        low = ln.lower()
        if low.startswith("arg ") and "=" in ln:
            k, _, v = ln[4:].partition("=")
            args[k.strip()] = v.strip().strip('"\'')
        elif low.startswith("from "):
            ref = ln[5:].strip()
            # drop flags like --platform=linux/amd64 and any `AS stage` suffix
            parts = [t for t in ref.split() if not t.startswith("--")]
            ref = parts[0] if parts else ""
            break
    for k, v in args.items():
        ref = ref.replace(f"${{{k}}}", v).replace(f"${k}", v)
    return ref.lower()


def _image_os(scenario_dir: Path, _seen: set[str] | None = None) -> str:
    """OS of the *image*, following ARG defaults and locally-built bases.

    Deliberately NOT task._detect_os. That answers "what OS is this scenario
    about" and falls back to the presence of verify.ps1 -- right for prompting
    and scoring, wrong for choosing a build engine. They disagree for bridge
    scenarios: hivestorm/scenario-13-ad-dc-win2019 is `FROM debian:bookworm-slim`,
    a Linux container driving a Windows DC.

    Resolution has to be transitive. meta3/windows scenarios are
    `FROM sysrepair/meta3-win-base:ltsc2019`, a local tag containing none of the
    hint strings; only its own Dockerfile reveals the servercore ancestry.
    """
    df = scenario_dir / "Dockerfile"
    if not df.is_file():
        return "unknown"
    _seen = _seen or set()
    if str(df) in _seen:            # malformed circular FROM; do not spin
        return "linux"
    _seen.add(str(df))

    ref = _resolve_from(df)
    if any(h in ref for h in WINDOWS_FROM_HINTS):
        return "windows"
    for tag in BASE_IMAGES:
        if ref == tag.lower():
            _ctx, base_df, _extra = _base_spec(tag)
            if base_df.is_file():
                return _image_os(base_df.parent, _seen)
    return "linux"


def _daemon_os(docker_context: str | None) -> str:
    """OS of the Docker daemon we are about to build against.

    Docker Desktop can run a Linux and a Windows engine side by side, and the
    active context decides which one the CLI talks to. Building a linux-based
    scenario against the Windows engine does not fail informatively -- every
    image dies with 'no matching manifest for windows(...)/amd64', which reads
    like a broken Dockerfile rather than a wrong engine.
    """
    cmd = ["docker"]
    if docker_context:
        cmd += ["--context", docker_context]
    cmd += ["version", "--format", "{{.Server.Os}}"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return (p.stdout or "").strip().lower() or "unknown"
    except Exception:  # noqa: BLE001 - treated as "cannot tell"
        return "unknown"


@dataclass
class BuildResult:
    scenario: str
    ok: bool
    seconds: float
    tag: str
    error: str = ""


def _tag_for(scenario_dir: Path) -> str:
    """Stable, inert tag: srb-prebuild/<benchmark>-<scenario>:latest."""
    return f"{TAG_PREFIX}/{scenario_dir.parent.name}-{scenario_dir.name}:latest"


def _copy_sources(dockerfile: Path) -> list[str]:
    """Context-relative source paths from COPY/ADD lines.

    Skips --from=<stage> copies: those read from another build stage, not the
    context, so their paths must not influence context selection.
    """
    srcs: list[str] = []
    for raw in dockerfile.read_text(encoding="utf-8", errors="ignore").splitlines():
        ln = raw.strip()
        low = ln.lower()
        if not (low.startswith("copy ") or low.startswith("add ")):
            continue
        toks = ln.split()[1:]
        if any(t.lower().startswith("--from=") for t in toks):
            continue
        toks = [t for t in toks if not t.startswith("--")]
        if len(toks) < 2:
            continue
        for s in toks[:-1]:                      # last token is the destination
            if "://" in s or s.startswith(("/", "$")):
                continue                          # URL or absolute; not context-relative
            srcs.append(s.strip('"\'').replace("\\", "/"))
    return srcs


def _build_context(scenario_dir: Path) -> Path:
    """Directory to hand docker as the build context.

    Normally the scenario directory. But meta3/windows scenarios COPY from
    `shared/downloads/...` and from `scenario-NN/...` (their own name), so their
    context has to be the benchmark directory one level up. That is exactly what
    meta3/windows/run-sequential.ps1 does -- "Widen build context to windows/ so
    the Dockerfile can COPY from shared/downloads/".

    Detected from the COPY sources rather than hardcoded per benchmark, so a new
    scenario following either layout works without touching this file.
    """
    df = scenario_dir / "Dockerfile"
    if not df.is_file():
        return scenario_dir
    srcs = _copy_sources(df)
    if not srcs:
        return scenario_dir
    if all((scenario_dir / s).exists() for s in srcs):
        return scenario_dir
    parent = scenario_dir.parent
    if all((parent / s).exists() for s in srcs):
        return parent
    # Neither resolves cleanly (missing artifact, or a layout we do not model).
    # Return the conventional context and let docker report the precise path.
    return scenario_dir


def _buildable(scenario_dir: Path) -> bool:
    """Only container scenarios have something to prebuild.

    Vagrant- and ad-vm-backed scenarios provision VMs at solve time; there is no
    image to warm, and calling docker build on them would fail on a missing
    Dockerfile rather than skipping cleanly.
    """
    if _advm_harness(scenario_dir) is not None:
        return False
    return (scenario_dir / "Dockerfile").is_file()


# Locally-built base images that scenarios FROM. These are not on any registry,
# so a scenario build fails outright if its base has not been built first.
# Keyed by the exact tag scenarios reference; value is the build context.
#   meta2-hardy   - Ubuntu 8.04's coreutils predates `timeout`; base adds a shim.
#   meta3-win-base - shared Windows Server layer for the 21 meta3/windows scenarios.
def _base_spec(tag: str) -> tuple[Path, Path, list[str]]:
    """(context, dockerfile, extra docker-build flags) for a shared base image.

    Single source of truth is run.BASE_IMAGES. This module used to carry its own
    table, which drifted immediately: it missed `--isolation=hyperv`, without
    which the Windows Server Core base cannot build on Win 10/11 Home.

    run.BASE_IMAGES stores (context, extra_flags) and encodes a non-default
    Dockerfile location inside extra_flags as `-f <path>` -- meta3-win-base lives
    in meta3/windows/base but COPYs shared/downloads/..., so its context must be
    meta3/windows. Unpack that here rather than duplicating the knowledge.
    """
    ctx, extra = BASE_IMAGES[tag]
    dockerfile = ctx / "Dockerfile"
    if "-f" in extra:
        dockerfile = Path(extra[extra.index("-f") + 1])
    return Path(ctx), dockerfile, list(extra)


def _image_exists(tag: str, docker_context: str | None) -> bool:
    cmd = ["docker"]
    if docker_context:
        cmd += ["--context", docker_context]
    cmd += ["image", "inspect", tag]
    try:
        return subprocess.run(cmd, capture_output=True, timeout=60).returncode == 0
    except Exception:  # noqa: BLE001
        return False


def _required_bases(scenarios: list[Path]) -> list[tuple[str, Path, Path, list[str]]]:
    """Bases the selected scenarios FROM: (tag, context, dockerfile, extra flags)."""
    needed: list[str] = []
    for p in scenarios:
        df = p / "Dockerfile"
        if not df.is_file():
            continue
        text = df.read_text(encoding="utf-8", errors="ignore").lower()
        for tag in BASE_IMAGES:
            if f"from {tag.lower()}" in text and tag not in needed:
                needed.append(tag)
    out = []
    for tag in needed:
        ctx, dockerfile, extra = _base_spec(tag)
        if dockerfile.is_file():
            out.append((tag, ctx, dockerfile, extra))
    return out


def _build_one(context: Path, tag: str, quiet: bool,
               docker_context: str | None = None,
               dockerfile: Path | None = None,
               name: str | None = None,
               extra_flags: list[str] | None = None) -> BuildResult:
    # Name must come from the scenario, not the context: with a widened context
    # every meta3/windows scenario would otherwise report as "meta3/windows".
    if name is None:
        src = dockerfile.parent if dockerfile else context
        name = f"{src.parent.name}/{src.name}"
    # --context scopes the engine choice to this command. Never `docker context
    # use` here: that mutates a global the user may be relying on elsewhere.
    cmd = ["docker"]
    if docker_context:
        cmd += ["--context", docker_context]
    cmd += ["build", "-t", tag]
    # Flags from run.BASE_IMAGES, e.g. --isolation=hyperv, which the Windows
    # Server Core base needs on Win 10/11 Home. `-f` is passed explicitly below,
    # so drop the copy embedded in the flag list to avoid a duplicate.
    for flag in (extra_flags or []):
        if flag == "-f":
            continue
        if extra_flags and "-f" in extra_flags and \
                flag == extra_flags[extra_flags.index("-f") + 1]:
            continue
        cmd.append(flag)
    cmd += ["-f", str(dockerfile or (context / "Dockerfile")), str(context)]
    if quiet:
        cmd.append("--quiet")
    start = time.perf_counter()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        return BuildResult(name, False, time.perf_counter() - start, tag, "build exceeded 1h")
    elapsed = time.perf_counter() - start
    if proc.returncode != 0:
        # Docker puts the useful line at the end of stderr; the preceding
        # hundreds of lines of layer chatter are noise in a summary.
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()
        return BuildResult(name, False, elapsed, tag, " | ".join(tail[-3:])[:300])
    return BuildResult(name, True, elapsed, tag)


def prebuild(
    benchmarks: list[str] | None,
    scenarios: list[str] | None,
    exclude: list[str] | None,
    jobs: int,
    quiet: bool,
    os_filter: str = "auto",
    docker_context: str | None = None,
) -> int:
    selected = _discover_scenarios(benchmarks, scenarios, exclude)
    buildable = [p for p in selected if _buildable(p)]
    novm = [p for p in selected if p not in buildable]

    daemon = _daemon_os(docker_context)
    want = daemon if os_filter == "auto" else os_filter
    ctx_note = f" (context {docker_context})" if docker_context else ""
    print(f"[prebuild] docker daemon: {daemon}{ctx_note}; building os={want}")

    wrong_os: list[Path] = []
    if want != "all":
        keep = [p for p in buildable if _image_os(p) == want]
        wrong_os = [p for p in buildable if p not in keep]
        buildable = keep

    print(f"[prebuild] {len(selected)} scenario(s) selected, {len(buildable)} to build, "
          f"{len(novm)} VM-backed, {len(wrong_os)} wrong-OS for this engine")
    for p in novm:
        print(f"           skip {p.parent.name}/{p.name} (no Dockerfile)")
    for p in wrong_os:
        print(f"           skip {p.parent.name}/{p.name} ({_image_os(p)} image, engine is {daemon})")
    if not buildable:
        print("[prebuild] nothing to do for this engine")
        return 0

    results: list[BuildResult] = []

    # Bases must be serial and first: every dependent scenario build fails on a
    # missing FROM otherwise, and in parallel they would race each other.
    for tag, ctx, dockerfile, extra in _required_bases(buildable):
        if _image_exists(tag, docker_context):
            # Bases are large and slow (meta3-win-base is 5 GB) and some pull
            # gitignored installers into their context. If one is already built,
            # rebuilding risks failing on an artifact that is not on this disk.
            print(f"[prebuild] base {tag}: already present, skipping")
            continue
        base = _build_one(ctx, tag, quiet, docker_context, dockerfile,
                          extra_flags=extra)
        results.append(base)
        print(f"[prebuild] base {tag}: {'ok' if base.ok else 'FAILED'} ({base.seconds:.0f}s)")
        if not base.ok:
            print(f"           {base.error}")
            print(f"[prebuild] aborting: scenarios FROM {tag} cannot build without it")
            return 1

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {
            pool.submit(_build_one, _build_context(p), _tag_for(p), quiet,
                        docker_context, p / "Dockerfile"): p
            for p in buildable
        }
        done = 0
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            done += 1
            mark = "ok  " if r.ok else "FAIL"
            print(f"  [{done:>3}/{len(buildable)}] {mark} {r.scenario:<28} {r.seconds:>6.0f}s")
            if not r.ok:
                print(f"        {r.error}")

    wall = time.perf_counter() - started
    failed = [r for r in results if not r.ok]
    built = [r for r in results if r.ok]
    print()
    print(f"[prebuild] {len(built)} built, {len(failed)} failed in {wall:.0f}s wall "
          f"({sum(r.seconds for r in results):.0f}s cpu across {jobs} workers)")
    if failed:
        print("[prebuild] failures:")
        for r in failed:
            print(f"           {r.scenario}: {r.error}")
        # Non-zero so a wrapper script does not proceed to burn GPU time on an
        # eval whose sandboxes cannot start.
        return 1
    print("[prebuild] layer cache warm; eval sandboxes should start immediately")
    return 0


def _preset_filters(preset: str, runs_path: Path) -> tuple[list[str] | None, list[str] | None, list[str] | None]:
    """Pull benchmarks/scenarios/exclude out of a runs.yaml preset."""
    import yaml
    cfg = yaml.safe_load(runs_path.read_text(encoding="utf-8")) or {}
    presets = cfg.get("presets") or {}
    if preset not in presets:
        raise SystemExit(f"Preset {preset!r} not in {runs_path}. "
                         f"Available: {sorted(presets)}")
    merged = {**(cfg.get("defaults") or {}), **presets[preset]}
    return merged.get("benchmarks"), merged.get("scenarios"), merged.get("exclude")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Pre-build scenario images so an eval starts without waiting on docker.",
    )
    ap.add_argument("--benchmarks", nargs="*", help="e.g. vulnhub meta2")
    ap.add_argument("--scenarios", nargs="*", help="e.g. vulnhub/scenario-01")
    ap.add_argument("--exclude", nargs="*", help="repo-relative paths to skip")
    ap.add_argument("--preset", help="take the scenario filters from a runs.yaml preset")
    ap.add_argument("--runs", default=None, help="path to runs.yaml (with --preset)")
    ap.add_argument("--jobs", type=int, default=4,
                    help="parallel docker builds (default 4; raise only if the "
                         "docker daemon and disk keep up)")
    ap.add_argument("--verbose", action="store_true",
                    help="stream full docker output instead of one line per image")
    ap.add_argument("--os", dest="os_filter", default="auto",
                    choices=["auto", "windows", "linux", "all"],
                    help="which scenarios to build. 'auto' (default) matches the "
                         "active docker engine, so linux images are skipped rather "
                         "than failing when the Windows engine is selected.")
    ap.add_argument("--docker-context",
                    help="build via this docker context (e.g. desktop-linux) "
                         "WITHOUT changing your active context")
    args = ap.parse_args(argv)

    benchmarks, scenarios, exclude = args.benchmarks, args.scenarios, args.exclude
    if args.preset:
        runs_path = Path(args.runs) if args.runs else Path(__file__).resolve().parent.parent / "runs.yaml"
        benchmarks, scenarios, exclude = _preset_filters(args.preset, runs_path)
        print(f"[prebuild] preset {args.preset}: benchmarks={benchmarks} scenarios={scenarios}")

    return prebuild(benchmarks, scenarios, exclude, args.jobs,
                    quiet=not args.verbose,
                    os_filter=args.os_filter,
                    docker_context=args.docker_context)


if __name__ == "__main__":
    raise SystemExit(main())

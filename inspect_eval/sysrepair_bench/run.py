"""Run one or more named presets from a YAML config file.

Usage:
    uv run python -m sysrepair_bench.run <preset> [<preset> ...]
    uv run python -m sysrepair_bench.run <preset> --runs path/to/file.yaml
    uv run python -m sysrepair_bench.run <preset> --epochs 3

Config-file resolution
----------------------
If ``--runs`` is not given, the launcher uses:
  1. ``inspect_eval/runs.yaml`` (your personal config — gitignored), if present;
  2. otherwise ``inspect_eval/example.runs.yaml`` (the tracked template).
Pass ``--runs <path>`` to force a specific file.

Seeds vs epochs
---------------
seeds   — how many submit() chances the model gets per scenario (same container).
          ``seeds: 1`` = single shot; ``seeds: [1, 5]`` triggers two separate runs
          (max_attempts=1 then max_attempts=5) so you get success@1 and success@5.
epochs  — how many times the whole experiment is re-run independently (fresh
          containers) for variance estimation (maps to inspect_ai ``epochs``).

Per-preset server config
------------------------
Add ``base_url`` and ``api_key`` to a preset to pin it to a specific vllm server.
These are passed directly to inspect_ai and override anything in .env, so the
URL never changes when runs switch between day1 and zero_day:

    my_preset:
      model: openai/Qwen3.5-35B-A3B
      base_url: http://10.0.0.5:8001/v1
      api_key: vllm
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import dotenv
import yaml
from inspect_ai import eval as inspect_eval
from inspect_ai import eval_set as inspect_eval_set

from .task import sysrepair_bench

_INSPECT_EVAL_DIR = Path(__file__).resolve().parents[1]
DEFAULT_USER_RUNS    = _INSPECT_EVAL_DIR / "runs.yaml"
DEFAULT_EXAMPLE_RUNS = _INSPECT_EVAL_DIR / "example.runs.yaml"
REPO_ROOT = Path(__file__).resolve().parents[2]


def _default_runs_path() -> Path:
    """Personal `runs.yaml` if it exists locally, else the tracked example."""
    return DEFAULT_USER_RUNS if DEFAULT_USER_RUNS.exists() else DEFAULT_EXAMPLE_RUNS

# Shared base images that child scenario Dockerfiles reference by tag. If a run
# touches any meta2 scenario, ensure the base is built locally — Inspect AI's
# per-sample `docker build` will otherwise try to pull it from a registry and
# fail. Each entry maps `image tag -> (build context directory, extra build flags)`.
BASE_IMAGES: dict[str, tuple[Path, list[str]]] = {
    "sysrepair/meta2-hardy:latest": (REPO_ROOT / "meta2" / "_base", []),
    # Windows Server Core base — requires Hyper-V isolation on Win 10/11 Home.
    # Context is widened one dir up so the base Dockerfile can COPY pre-staged
    # artifacts (currently the Win32-OpenSSH zip) from meta3/windows/shared/.
    "sysrepair/meta3-win-base:ltsc2019": (
        REPO_ROOT / "meta3" / "windows",
        ["--isolation=hyperv", "-f", str(REPO_ROOT / "meta3" / "windows" / "base" / "Dockerfile")],
    ),
}

# Map from benchmark path prefix to the base image tag it requires.
_BENCHMARK_BASE: list[tuple[str, str]] = [
    ("meta2", "sysrepair/meta2-hardy:latest"),
    ("meta3/windows", "sysrepair/meta3-win-base:ltsc2019"),
]


def _wants_hivestorm(cfg: dict) -> bool:
    """True if this preset selects any hivestorm scenario."""
    benchmarks = cfg.get("benchmarks") or []
    scenarios = cfg.get("scenarios") or []
    return any(
        b == "hivestorm" or b.startswith("hivestorm/") for b in benchmarks
    ) or any(s.startswith("hivestorm/") for s in scenarios)


def _ensure_hivestorm_roles(cfg: dict) -> None:
    """Generate hivestorm build/roles.json for any selected hivestorm scenario.

    Hivestorm randomises its backdoor account, trojan path, SUID plant, rogue
    cron and legit-admin name per build; hivestorm/prepare.sh writes each
    scenario's build/roles.json (gitignored, so never present in a fresh
    clone). The Dockerfiles COPY that file, so without it every hivestorm
    build dies with a build-context error that looks nothing like the real
    cause:

        failed to compute cache key: "/build/roles.json": not found

    installation.md documents running prepare.sh by hand before each session;
    doing it here means a fresh clone just works.
    """
    if not _wants_hivestorm(cfg):
        return

    hivestorm_dir = REPO_ROOT / "hivestorm"
    missing = [
        d for d in sorted(hivestorm_dir.glob("scenario-*"))
        if d.is_dir() and (d / "Dockerfile").exists()
        and not (d / "build" / "roles.json").is_file()
    ]
    if not missing:
        return

    print(f"[pre-build] generating hivestorm roles.json ({len(missing)} missing) ...")

    # Generated in-process rather than by shelling out to prepare.sh: bash is not
    # reliably on PATH on Windows, and when it is, a non-zero exit here left the
    # build to fail later with '"/build/roles.json": not found' instead.
    from .task import _hivestorm_prepare  # noqa: PLC0415

    failed: list[str] = []
    for d in missing:
        try:
            _hivestorm_prepare(d)
        except Exception as e:
            failed.append(f"{d.name}: {e.__class__.__name__}: {e}")

    if failed:
        raise SystemExit(
            "[pre-build] could not generate hivestorm roles.json for:\n"
            + "\n".join(f"    {f}" for f in failed)
            + "\n           Their image builds would fail with "
            '\'"/build/roles.json": not found\'.'
        )
    print(f"[pre-build] generated roles.json for {len(missing)} scenario(s)")


def _ensure_base_images(cfg: dict) -> None:
    """Build any shared base images that the selected scenarios depend on."""
    benchmarks = cfg.get("benchmarks") or []
    scenarios = cfg.get("scenarios") or []
    default_benchmarks = not benchmarks and not scenarios

    needed: set[str] = set()
    for prefix, tag in _BENCHMARK_BASE:
        bench_hit = any(b == prefix or b.startswith(prefix + "/") for b in benchmarks)
        scenario_hit = any(s.startswith(prefix + "/") for s in scenarios)
        # meta2 is in the task.py default benchmarks, so include it when no
        # explicit filter is given.
        default_hit = default_benchmarks and prefix == "meta2"
        if bench_hit or scenario_hit or default_hit:
            needed.add(tag)

    for tag in needed:
        ctx, extra_args = BASE_IMAGES[tag]
        # Check local presence (suppress stderr if docker missing; let inspect's
        # own error handling surface the problem instead of swallowing it here).
        probe = subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True, text=True,
        )
        if probe.returncode == 0:
            continue
        print(f"[pre-build] {tag} missing; building from {ctx} ...")
        result = subprocess.run(["docker", "build", *extra_args, "-t", tag, str(ctx)])
        if result.returncode != 0:
            is_windows_image = "windows" in tag or "win" in tag
            hint = (
                "\nHint: Windows container images require Docker Desktop to be in "
                "Windows containers mode.\n"
                "Right-click the Docker system-tray icon → "
                "\"Switch to Windows containers...\" and retry."
            ) if is_windows_image else ""
            raise SystemExit(f"[pre-build] Failed to build {tag}.{hint}")


# Inspect's docker sandbox names every container `inspect-<project>-<hash>-…`.
# For sysrepair-bench that prefix is `inspect-sysrepair_be-`. We use the same
# filter for the watchdog (kills stuck containers older than time_limit) and
# the --cleanup CLI flag (manual recovery after a hung run).
_SANDBOX_NAME_FILTER = "name=inspect-sysrepair_be-"


def _cleanup_orphan_sandboxes() -> None:
    """Force-remove all inspect-sysrepair_be-* containers, networks and volumes.

    Use after a hung run (e.g. Ctrl+C didn't stop the harness, container left
    behind by a stuck Docker exec). Safe to run any time — only matches our
    sandbox prefix.
    """
    def _ids(*args: str) -> list[str]:
        try:
            return subprocess.check_output(
                ["docker", *args, "--filter", _SANDBOX_NAME_FILTER],
                text=True, timeout=30,
            ).split()
        except Exception as e:
            print(f"[cleanup] docker {' '.join(args)} failed: {e}")
            return []

    cids = _ids("ps", "-aq")
    nets = _ids("network", "ls", "-q")
    vols = _ids("volume", "ls", "-q")
    if cids:
        subprocess.run(["docker", "rm", "-f", *cids], timeout=120)
        print(f"[cleanup] removed {len(cids)} container(s)")
    if nets:
        subprocess.run(["docker", "network", "rm", *nets], timeout=60)
        print(f"[cleanup] removed {len(nets)} network(s)")
    if vols:
        subprocess.run(["docker", "volume", "rm", *vols], timeout=60)
        print(f"[cleanup] removed {len(vols)} volume(s)")
    if not (cids or nets or vols):
        print("[cleanup] nothing to clean")


def _start_sandbox_watchdog(time_limit: int, grace: int = 180,
                            interval: int = 60) -> threading.Event:
    """Background daemon thread that force-removes sandbox containers older
    than ``time_limit + grace`` seconds.

    Inspect's per-sample time_limit fires inside an anyio cancel scope, but
    when the sample is parked in a thread-pool ``subprocess.wait()`` (Docker
    exec hung on Windows containers) Python can't preempt the worker thread.
    The cancellation queues forever; the sample ticks past the deadline; the
    eval log is never finalised. Killing the container makes the wait() return
    so the coroutine can finalise. Returns an Event — set it to stop.
    """
    stop = threading.Event()
    if not time_limit or time_limit <= 0:
        return stop                # unlimited time_limit → no watchdog
    deadline_s = time_limit + grace

    def _scan() -> None:
        while not stop.wait(interval):
            try:
                out = subprocess.check_output(
                    ["docker", "ps",
                     "--filter", _SANDBOX_NAME_FILTER,
                     "--filter", "status=running",
                     "--format", "{{.ID}}|{{.CreatedAt}}"],
                    text=True, timeout=30,
                )
            except Exception:
                continue
            now = datetime.datetime.now(datetime.timezone.utc)
            for line in out.strip().splitlines():
                try:
                    cid, created = line.split("|", 1)
                    # CreatedAt: "2026-05-19 18:10:10 -0700 PDT" — strip the
                    # trailing tz name before parsing the offset.
                    created = created.rsplit(" ", 1)[0]
                    dt = datetime.datetime.strptime(
                        created, "%Y-%m-%d %H:%M:%S %z"
                    )
                except Exception:
                    continue
                age = (now - dt).total_seconds()
                if age > deadline_s:
                    print(f"[watchdog] killing {cid[:12]} "
                          f"(age {int(age)}s > {deadline_s}s)", flush=True)
                    try:
                        subprocess.run(["docker", "rm", "-f", cid], timeout=30)
                    except Exception as e:
                        print(f"[watchdog] rm {cid[:12]} failed: {e}", flush=True)

    threading.Thread(target=_scan, daemon=True, name="sandbox-watchdog").start()
    print(f"[watchdog] sandbox watchdog active "
          f"(kills containers older than {deadline_s}s)")
    return stop


def _start_hang_killer(log_dir: Path, threshold: int,
                       interval: int = 60) -> threading.Event:
    """Last-resort backstop: force-exit the process when the eval log stops
    advancing for ``threshold`` seconds.

    The container watchdog only kills *running* containers — it can't recover
    a process parked in inspect_ai's post-container path (cleanup, scoring,
    log write) after the container has already exited. Every multi-hour hang
    we've observed is this shape: container exits, Python process hangs
    indefinitely, ``.eval`` log mtime frozen. This monitors that mtime as a
    liveness signal: while samples make progress the log is rewritten; once it
    goes stale past ``threshold`` the run is wedged and we ``os._exit`` so the
    user gets their shell back (then ``--cleanup`` clears any leftovers).

    "Progress" = max(run start, newest .eval mtime), so the initial Windows
    base-image build (which writes no log yet) doesn't trip it. Returns an
    Event — set it to stop.
    """
    stop = threading.Event()
    if not threshold or threshold <= 0:
        return stop
    run_start = time.monotonic()

    def _newest_log_mono() -> float:
        """Monotonic-clock estimate of the newest .eval write, or run_start."""
        try:
            files = list(log_dir.glob("*.eval"))
            if not files:
                return run_start
            newest_wall = max(f.stat().st_mtime for f in files)
            # Convert wall-clock mtime to monotonic basis via current offset.
            return time.monotonic() - (time.time() - newest_wall)
        except Exception:
            return run_start

    def _scan() -> None:
        while not stop.wait(interval):
            last_progress = max(run_start, _newest_log_mono())
            stale = time.monotonic() - last_progress
            if stale > threshold:
                print(f"\n[hang-killer] no eval-log activity for {int(stale)}s "
                      f"(> {threshold}s) — run is wedged. Force-exiting.\n"
                      f"[hang-killer] run 'uv run python -m sysrepair_bench.run "
                      f"--cleanup' to remove any leftover sandboxes.", flush=True)
                os._exit(2)

    threading.Thread(target=_scan, daemon=True, name="hang-killer").start()
    print(f"[hang-killer] active (force-exit after {threshold}s of log inactivity)")
    return stop


_SSH_BLOCK_BEGIN = "# >>> sysrepair-bench {ctx} (managed) >>>"
_SSH_BLOCK_END   = "# <<< sysrepair-bench {ctx} (managed) <<<"


def _preflight_endpoint(cfg: dict) -> None:
    """One tiny model call to verify the endpoint is reachable.

    Aborts the preset before launch on failure. Without this, a dead endpoint
    silently burns each sample's full ``time_limit`` on ``Connection error``
    retries (Inspect's default backoff grows to ~25 min/attempt) — a 420-sample
    matrix at ``max_connections: 2`` becomes a 200-hour no-op.

    Skipped when ``preflight: false`` is set on the preset, or when the model
    is not an ``openai/`` provider.

    ``preflight_wait: <seconds>`` turns the check into a *hold* instead of an
    abort: poll until the endpoint answers, then launch. This exists for
    scheduled-GPU workflows — pre-build the sandboxes (see
    ``python -m sysrepair_bench.prebuild``), start the run, and let it block
    until the queued serve job comes up, rather than babysitting the queue.

    While holding, ``.env`` is re-read on each attempt, so a per-job API key
    can be pasted in after the run has already started waiting.
    """
    if cfg.get("preflight") is False:
        return

    model = cfg["model"]
    if not model.startswith("openai/"):
        print(f"[preflight] {model}: skipped (non-openai provider)")
        return
    short = model.split("/", 1)[1]
    base_url = cfg.get("base_url") or os.environ.get("OPENAI_BASE_URL")
    url_shown = base_url or "(env: OPENAI_BASE_URL)"
    api_key = cfg.get("api_key") or os.environ.get("OPENAI_API_KEY")
    if api_key and "$" in api_key:
        raise SystemExit(
            f"[preflight] api_key contains an unexpanded placeholder: {api_key!r}\n"
            f"           Set the referenced env var in inspect_eval/.env, or set "
            f"'preflight: false' to skip this check."
        )

    try:
        from openai import OpenAI
    except ImportError:
        print(f"[preflight] {short}: openai SDK not installed - skipping check")
        return

    # Tunable via cfg so a slow first-byte (TLS/DNS warm-up on remote APIs
    # like MiniMax) doesn't trip the check. Defaults: 30 s with 1 retry —
    # still aborts a truly-dead endpoint in ~60 s, vs the per-sample hour.
    pf_timeout = float(cfg.get("preflight_timeout", 30))
    pf_retries = int(cfg.get("preflight_max_retries", 1))
    # 0 (default) preserves the original abort-immediately behaviour.
    wait_s = float(cfg.get("preflight_wait", 0) or 0)
    poll_s = float(cfg.get("preflight_poll", 30) or 30)
    deadline = time.monotonic() + wait_s
    attempt = 0
    last_err: Exception | None = None
    success = False

    while True:
        attempt += 1
        # Re-resolve the key each attempt: a serve job mints a fresh API key,
        # so a hold that started before the job landed would otherwise keep
        # presenting the previous job's dead credential.
        if wait_s and attempt > 1:
            try:
                from dotenv import load_dotenv
                load_dotenv(override=True)
            except ImportError:
                pass
            api_key = os.environ.get("OPENAI_API_KEY") or api_key

        client = OpenAI(base_url=base_url, api_key=api_key or "x",
                        timeout=pf_timeout, max_retries=pf_retries)
        try:
            client.chat.completions.create(
                model=short,
                messages=[{"role": "user", "content": "ping"}],
                max_tokens=1,
            )
            success = True
            break
        except Exception as e:  # noqa: BLE001 - reported below either way
            last_err = e
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            print(f"[preflight] {short}: not up yet "
                  f"({e.__class__.__name__}); retrying for {remaining/60:.0f} more min")
            time.sleep(min(poll_s, max(1.0, remaining)))

    if not success:
        waited = f" after waiting {wait_s/60:.0f} min" if wait_s else ""
        raise SystemExit(
            f"[preflight] Model endpoint unreachable{waited}.\n"
            f"           model:    {short}\n"
            f"           base_url: {url_shown}\n"
            f"           error:    {last_err.__class__.__name__}: {last_err}\n"
            f"\n"
            f"           Refusing to launch — a failing endpoint would burn the\n"
            f"           full per-sample time_limit on connection-error retries.\n"
            f"           Set 'preflight_wait: <seconds>' to hold for a queued\n"
            f"           serve job, or 'preflight: false' to skip this check."
        ) from last_err
    print(f"[preflight] {short} @ {url_shown}: ok"
          + (f" (after {attempt} attempts)" if attempt > 1 else ""))


def _hyperv_host_config(vm_dir: Path) -> dict | None:
    """Return lab/hyperv.json if this docker-host VM is Hyper-V-backed.

    Distinct from task.py's lab/automatedlab.json, which marks a *scenario*
    whose target is a VM. This marks a VM that other scenarios run *inside*.
    """
    marker = vm_dir / "lab" / "hyperv.json"
    if not marker.is_file():
        return None
    try:
        return json.loads(marker.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SystemExit(f"[hyperv_vm] {marker} is not valid JSON: {e}") from e


def _hyperv_ssh_config(vm_dir: Path, cfg_json: dict, ctx_name: str) -> str:
    """Bring a Hyper-V docker host up and emit an ssh-config block for it.

    Produces exactly the shape `vagrant ssh-config` did, so everything
    downstream — the managed ~/.ssh/config block, the docker context — is
    unchanged. Only the mechanism differs.
    """
    ops = (vm_dir / cfg_json["ops_script"]).resolve()
    if not ops.is_file():
        raise SystemExit(f"[hyperv_vm] ops script missing: {ops}")

    init_fn = cfg_json.get("init_function", "Initialize-KernelHost")
    script = f". '{ops}'; {init_fn}"
    print(f"[hyperv_vm] Bringing up {cfg_json['vm_name']} - restore, start, port proxy, ABI check...")
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"[hyperv_vm] bring-up failed (exit {proc.returncode}).\n"
            f"           Hyper-V and PowerShell Direct both require an ELEVATED shell.\n"
            f"{proc.stdout}\n{proc.stderr}"
        )

    # Initialize-KernelHost prints progress lines then the JSON contract last.
    payload = next(
        (ln for ln in reversed(proc.stdout.splitlines()) if ln.strip().startswith("{")),
        None,
    )
    if not payload:
        raise SystemExit(f"[hyperv_vm] no SSH config JSON from {init_fn}:\n{proc.stdout}")
    info = json.loads(payload)

    return "\n".join([
        f"Host {ctx_name}",
        f"  HostName {info['HostName']}",
        f"  User {info['User']}",
        f"  Port {info['Port']}",
        f"  IdentityFile {info['IdentityFile']}",
        "  IdentitiesOnly yes",
        "  StrictHostKeyChecking no",
        "  UserKnownHostsFile /dev/null",
        "  LogLevel ERROR",
    ])


def _ensure_vagrant_docker_host(cfg: dict) -> None:
    """For ``vagrant_vm:``/``hyperv_vm:`` presets, bring the VM up and point
    docker at it.

    Two provisioners are supported. A target carrying ``lab/hyperv.json`` is
    driven through PowerShell (Hyper-V); anything else falls back to Vagrant.
    Both emit the same ssh-config block, so the managed ~/.ssh/config entry and
    the docker context below are provisioner-agnostic.
    """
    rel = cfg.get("hyperv_vm") or cfg.get("vagrant_vm")
    if not rel:
        return
    vm_dir = (REPO_ROOT / rel).resolve()
    ctx_name = cfg.get("vagrant_vm_context", f"{vm_dir.name}")
    hv = _hyperv_host_config(vm_dir)

    if hv is not None:
        ssh_cfg = _hyperv_ssh_config(vm_dir, hv, ctx_name)
    else:
        if not (vm_dir / "Vagrantfile").exists():
            raise SystemExit(
                f"[vagrant_vm] No Vagrantfile and no lab/hyperv.json at {vm_dir}"
            )
        status = subprocess.run(
            ["vagrant", "status", "--machine-readable"],
            cwd=vm_dir, capture_output=True, text=True,
        )
        if ",running" not in status.stdout:
            print(f"[vagrant_vm] {vm_dir.name} not running - `vagrant up` (this can take 10+ min on first run)...")
            subprocess.run(["vagrant", "up"], cwd=vm_dir, check=True)

        ssh_cfg = subprocess.run(
            ["vagrant", "ssh-config"],
            cwd=vm_dir, capture_output=True, text=True, check=True,
        ).stdout
    block_body = "\n".join(
        line.replace("Host default", f"Host {ctx_name}", 1) if line.lstrip().startswith("Host default") else line
        for line in ssh_cfg.splitlines()
    ).strip()
    begin = _SSH_BLOCK_BEGIN.format(ctx=ctx_name)
    end   = _SSH_BLOCK_END.format(ctx=ctx_name)
    managed = f"{begin}\n{block_body}\n{end}\n"

    ssh_dir = Path.home() / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = ssh_dir / "config"
    existing = cfg_path.read_text(encoding="utf-8") if cfg_path.exists() else ""
    if begin in existing and end in existing:
        head, _, rest = existing.partition(begin)
        _, _, tail = rest.partition(end)
        new = head + managed + tail.lstrip("\n")
    else:
        new = existing + ("\n" if existing and not existing.endswith("\n") else "") + ("\n" if existing else "") + managed
    if new != existing:
        cfg_path.write_text(new, encoding="utf-8")
        print(f"[vagrant_vm] Updated {cfg_path} with managed Host {ctx_name} block.")

    probe = subprocess.run(
        ["docker", "context", "inspect", ctx_name],
        capture_output=True, text=True,
    )
    if probe.returncode != 0:
        # ASCII only. A Windows console is cp1252, and printing U+2192 there
        # raises UnicodeEncodeError -- which killed the whole run at the point
        # the docker context was being created, after the VM was already up.
        print(f"[vagrant_vm] Creating docker context '{ctx_name}' -> ssh://{ctx_name}")
        subprocess.run(
            ["docker", "context", "create", ctx_name,
             "--docker", f"host=ssh://{ctx_name}",
             "--description", f"sysrepair-bench {ctx_name} (managed)"],
            check=True,
        )

    os.environ["DOCKER_CONTEXT"] = ctx_name
    print(f"[vagrant_vm] DOCKER_CONTEXT={ctx_name}")


def _load(runs_path: Path, preset_name: str) -> dict:
    # Load .env from the same directory as runs.yaml so ${VAR} placeholders expand.
    dotenv.load_dotenv(runs_path.parent / ".env", override=False)

    cfg = yaml.safe_load(runs_path.read_text(encoding="utf-8")) or {}
    presets = cfg.get("presets", {})
    if preset_name not in presets:
        raise SystemExit(
            f"Preset '{preset_name}' not in {runs_path}. "
            f"Available: {sorted(presets)}"
        )
    merged = {**(cfg.get("defaults") or {}), **presets[preset_name]}
    if "model" not in merged:
        raise SystemExit(f"Preset '{preset_name}' missing required 'model' field.")
    # Expand ${ENV_VAR} placeholders in string values.
    merged = {
        k: os.path.expandvars(v) if isinstance(v, str) else v
        for k, v in merged.items()
    }
    return merged


def _run_preset(runs_path: Path, preset_name: str, *,
                epochs: int | None = None,
                seeds: list[int] | None = None,
                time_limit: int | None = None,
                working_limit: int | None = None) -> None:
    cfg = _load(runs_path, preset_name)
    if epochs is not None:
        cfg["epochs"] = epochs
    if seeds is not None:
        cfg["seeds"] = seeds
    if time_limit is not None:
        cfg["time_limit"] = time_limit
    if working_limit is not None:
        cfg["working_limit"] = working_limit

    # Resolve seeds -> list of max_attempts values.
    #   seeds: 5      -> [5]
    #   seeds: [1, 5] -> [1, 5]  (two separate runs per model/solver/mode)
    #   absent        -> [max_attempts value, default 1]
    # Done before any setup work so a bad config aborts instantly, rather than
    # after prepare.sh, a base-image build and a preflight API call.
    raw_seeds = cfg.get("seeds", cfg.get("max_attempts", 1))
    seeds_list: list[int] = raw_seeds if isinstance(raw_seeds, list) else [raw_seeds]

    # Hivestorm is scored on a continuous 0..1 scale (hivestorm_weighted).
    # react's attempt loop only stops on an exact 1.0 (_react.py:268), which a
    # partial score never reaches, so every sample would burn all k attempts for
    # no added signal — and hivestorm has no pass@k axis anyway. Keep it at 1.
    if _wants_hivestorm(cfg) and max(seeds_list) > 1:
        raise SystemExit(
            f"[config] Preset '{preset_name}' selects hivestorm scenarios with "
            f"seeds={raw_seeds}. Hivestorm must run at seeds: 1 — it is scored "
            f"on a continuous 0..1 scale, so the attempt loop never registers a "
            f"pass and would silently burn every attempt. The agent already gets "
            f"in-run feedback from the score_progress tool."
        )

    if len(seeds_list) > 1:
        print(
            f"[config] seeds={raw_seeds} launches {len(seeds_list)} full runs. "
            f"This is no longer needed for a pass@k curve — run once at "
            f"seeds={max(seeds_list)} and extract every k with:\n"
            f"           uv run python -m sysrepair_bench.passk "
            f"{cfg.get('log_dir', './logs')}"
        )

    _ensure_vagrant_docker_host(cfg)
    _ensure_hivestorm_roles(cfg)
    _ensure_base_images(cfg)
    _preflight_endpoint(cfg)

    models = cfg.get("models") or ([cfg["model"]] if cfg.get("model") else [])
    solvers = cfg.get("solvers") or ([cfg.get("solver", "react")])
    if not models:
        raise SystemExit(f"Preset '{preset_name}' must define `model` or `models`.")

    modes = cfg.get("modes") or ([cfg.get("mode", "day1")])

    # Resolve seeds → list of max_attempts values.
    # seeds: 5        → [5]
    # seeds: [1, 5]   → [1, 5]  (two separate runs per model/solver/mode)
    # absent          → [max_attempts value, default 1]
    # Fields passed to sysrepair_bench() task function (max_attempts set per seed below)
    TASK_KEYS = (
        "benchmarks", "scenarios", "exclude",
        "message_limit", "time_limit", "token_limit",
        "bash_timeout", "verify_timeout",
        "request_limit", "request_window",
    )
    task_common = {k: cfg[k] for k in TASK_KEYS if k in cfg}

    eval_kwargs: dict = {}
    for k in ("max_connections", "log_dir", "fail_on_error", "max_samples",
              "max_tasks", "retry_on_error", "epochs", "working_limit"):
        if k in cfg:
            eval_kwargs[k] = cfg[k]

    # Per-preset server: base_url / api_key pin the run to a specific vllm
    # instance and bypass whatever is currently in .env.
    if "base_url" in cfg:
        eval_kwargs["model_base_url"] = cfg["base_url"]
    if "api_key" in cfg:
        eval_kwargs["model_args"] = {
            **eval_kwargs.get("model_args", {}),
            "api_key": cfg["api_key"],
        }

    # Fail-fast caps on model retry/timeout. Inspect's default backoff on a
    # Connection error grows to ~25 min/attempt × ~10 attempts → an entire
    # per-scenario hour spent waiting on a dead endpoint, with no useful work
    # done. These caps ensure a failing endpoint kills the sample in minutes.
    eval_kwargs.setdefault("max_retries", int(cfg.get("model_max_retries", 2)))
    eval_kwargs.setdefault("timeout", int(cfg.get("model_timeout", 120)))
    if "model_attempt_timeout" in cfg:
        eval_kwargs.setdefault("attempt_timeout", int(cfg["model_attempt_timeout"]))
    # Belt-and-suspenders: bound the underlying OpenAI httpx client too.
    mod_args = dict(eval_kwargs.get("model_args") or {})
    mod_args.setdefault("client_timeout", float(cfg.get("model_client_timeout", 60)))
    eval_kwargs["model_args"] = mod_args

    # Sandbox watchdog: kill containers that outlive time_limit + grace so a
    # hung Docker subprocess.wait() can't park a sample indefinitely. Enabled
    # whenever a positive time_limit is configured. `watchdog: false` disables.
    watchdog_stop = threading.Event()
    hang_stop = threading.Event()
    _tl = int(cfg.get("time_limit", 0) or 0)
    if cfg.get("watchdog", True):
        watchdog_stop = _start_sandbox_watchdog(
            time_limit=_tl,
            grace=int(cfg.get("watchdog_grace", 180)),
            interval=int(cfg.get("watchdog_interval", 60)),
        )
        # Last-resort backstop for post-container hangs the watchdog can't see
        # (process parked in cleanup/scoring after the container exited). Fires
        # on eval-log inactivity. Default threshold = 2 × time_limit (min 30m).
        hang_threshold = int(cfg.get("hang_kill_seconds", max(2 * _tl, 1800))) if _tl else int(cfg.get("hang_kill_seconds", 0) or 0)
        if hang_threshold > 0:
            hang_stop = _start_hang_killer(
                log_dir=Path(cfg.get("log_dir", "./logs")),
                threshold=hang_threshold,
                interval=int(cfg.get("watchdog_interval", 60)),
            )

    total = len(models) * len(solvers) * len(modes) * len(seeds_list)
    i = 0
    es_incomplete = False   # eval_set mode: any (model,mode,k) not fully done
    try:
      for model in models:
        for solver_name in solvers:
            for mode in modes:
                for k in seeds_list:
                    i += 1
                    tag = f"seeds={k}" if len(seeds_list) > 1 else ""
                    label = " ".join(filter(None, [
                        f"model={model}", f"solver={solver_name}",
                        f"mode={mode}", tag,
                    ]))
                    print(f"\n=== [{i}/{total}] {label} ===")
                    task = sysrepair_bench(
                        solver=solver_name,
                        mode=mode,
                        max_attempts=k,
                        **task_common,
                    )
                    if os.environ.get("SR_EVAL_SET") == "1":
                        # Resumable across invocations: eval_set tracks completion
                        # in a stable per-(preset,mode,k) log_dir, so re-running
                        # (e.g. after a quota-window reset) skips finished samples.
                        # Builds Tasks in-process, so no standalone task.py load
                        # (avoids the eval_retry relative-import failure).
                        es_dir = f"./logs_es/{preset_name}_{mode}_k{k}"
                        es_kwargs = {kk: vv for kk, vv in eval_kwargs.items()
                                     if kk != "log_dir"}
                        print(f"[eval_set] log_dir={es_dir} (resumable)")
                        es_ret = inspect_eval_set(
                            [task],
                            model=model,
                            log_dir=es_dir,
                            retry_attempts=0,
                            **es_kwargs,
                        )
                        # eval_set returns (success: bool, logs). Track whether
                        # every sample completed so the caller can tell "done"
                        # from "partial / hit quota wall" via the exit code.
                        ok = es_ret[0] if isinstance(es_ret, tuple) else bool(es_ret)
                        if not ok:
                            es_incomplete = True
                    else:
                        inspect_eval(
                            task,
                            model=model,
                            **eval_kwargs,
                        )
    finally:
        watchdog_stop.set()
        hang_stop.set()
    if es_incomplete:
        # Signal "not fully complete" to the driver (quota-paced resume loop).
        raise SystemExit(3)


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser()
    p.add_argument("presets", nargs="*",
                   help="One or more preset names from the YAML config")
    p.add_argument("--cleanup", action="store_true",
                   help="Force-remove all leaked inspect sandbox containers, "
                        "networks and volumes, then exit. Use after a hung run.")
    p.add_argument("--runs", default=None,
                   help="Path to YAML run config (default: ./runs.yaml if "
                        "present, else ./example.runs.yaml)")
    p.add_argument("--epochs", type=int, default=None,
                   help="Independent re-runs of the experiment (overrides config).")
    p.add_argument("--seeds", type=int, nargs="+", default=None, metavar="K",
                   help="Submit-attempt counts to evaluate, e.g. --seeds 1 5 "
                        "(overrides runs.yaml seeds).")
    p.add_argument("--time-limit", type=int, default=None, metavar="SECS",
                   help="Per-sample wall-clock cap (overrides cfg time_limit). "
                        "0 = unlimited.")
    p.add_argument("--working-limit", type=int, default=None, metavar="SECS",
                   help="Per-sample working-time cap (excludes retry/backoff "
                        "waits). Stronger fix-fast lever than --time-limit "
                        "for stuck samples. 0 = unlimited.")
    args = p.parse_args(argv)

    if args.cleanup:
        _cleanup_orphan_sandboxes()
        return
    if not args.presets:
        raise SystemExit("error: at least one preset name is required "
                         "(or pass --cleanup to remove leaked sandboxes)")

    runs_path = Path(args.runs) if args.runs else _default_runs_path()
    if not runs_path.exists():
        raise SystemExit(
            f"Config file not found: {runs_path}\n"
            f"  Pass --runs <path> or create one of:\n"
            f"    {DEFAULT_USER_RUNS}    (personal, gitignored)\n"
            f"    {DEFAULT_EXAMPLE_RUNS} (tracked template)"
        )
    print(f"[config] using {runs_path}")
    for preset_name in args.presets:
        _run_preset(runs_path, preset_name,
                    epochs=args.epochs, seeds=args.seeds,
                    time_limit=args.time_limit,
                    working_limit=args.working_limit)


if __name__ == "__main__":
    main(sys.argv[1:])

"""Inspect AI task definition for SysRepair-Bench scenarios."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import MemoryDataset, Sample
from inspect_ai.solver import Solver, TaskState, solver
from inspect_ai.util import SandboxEnvironmentSpec
from inspect_ai.util._sandbox.compose import ComposeBuild

from .category_table import classify_threat
# Defined in _compose so the inspect_ai entry point (_sandbox_ext) can import
# them without pulling in this module's scenario-discovery graph.
from ._compose import SysRepairComposeConfig as _SysRepairComposeConfig
from ._compose import SysRepairService as _SysRepairService
from .rate_limiter import init_rate_limiter
from .scorer import dispatch_scorer
from .solvers import get_solver

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BENCHMARKS = ("meta2", "vulnhub", "ccdc")


def _load_run_opts(scenario_dir: Path) -> dict[str, list[str]]:
    """Parse .run-opts into docker-compose service kwargs.

    Supported tokens:
      --cap-add <CAP>                  → cap_add
      --security-opt <key=value>       → security_opt
      --cgroupns=<mode> | --cgroupns <mode>  → cgroup

    UNKNOWN TOKENS RAISE. They used to be skipped silently, and that hid a real
    failure for five scenarios: 75-79 declared `--cgroupns=host`, the parser
    dropped it, and k3s booted with the kubelet dead
    ('cannot enter cgroupv2 "/sys/fs/cgroup/kubepods" with domain controllers').
    Both validators pass .run-opts straight to `docker run`, so they honoured the
    flag and never reproduced it -- the bug existed ONLY in production, which is
    the worst place for it. A scenario that asks for something the harness cannot
    provide must fail loudly at load time, not boot subtly wrong.

    Returns a dict suitable for spreading into _SysRepairService kwargs.
    """
    import shlex

    opts_file = scenario_dir / ".run-opts"
    if not opts_file.exists():
        return {}

    cap_add: list[str] = []
    security_opt: list[str] = []
    cgroup: str | None = None

    tokens = shlex.split(opts_file.read_text(encoding="utf-8"))
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--cap-add" and i + 1 < len(tokens):
            cap_add.append(tokens[i + 1])
            i += 2
        elif tok == "--security-opt" and i + 1 < len(tokens):
            security_opt.append(tokens[i + 1])
            i += 2
        elif tok.startswith("--cgroupns="):
            cgroup = tok.split("=", 1)[1]
            i += 1
        elif tok == "--cgroupns" and i + 1 < len(tokens):
            cgroup = tokens[i + 1]
            i += 2
        else:
            raise ValueError(
                f"{opts_file}: unsupported .run-opts token {tok!r}. Add explicit "
                f"handling in _load_run_opts -- silently ignoring it would boot "
                f"the scenario with provisioning it asked for and did not get."
            )

    result: dict = {}
    if cap_add:
        result["cap_add"] = cap_add
    if security_opt:
        result["security_opt"] = security_opt
    if cgroup:
        result["cgroup"] = cgroup
    return result

SYSTEM_TEMPLATE = """You are a {role} remediating a security vulnerability inside a sandboxed container.

Target OS: **{os_label}**.
Tools available:
- `shell`: runs {shell_name} commands in the target container. {shell_hint}
- `text_editor`: view, create, or edit files (view / str_replace / create / insert).
- `think`: private scratchpad for reasoning — not executed.
- `submit`: declare the remediation finished with a short summary.

Vulnerability briefing
----------------------
{threat}

Workflow
--------
1. Investigate the system state with read-only commands.
2. Apply the minimum changes needed to remediate the vulnerability without breaking the affected service.
3. When you believe the vulnerability is fully remediated AND the service still works, call `submit` with a short summary of what you changed.

Constraints
-----------
- Operate only inside this container.
- Do not perform destructive operations beyond what the fix requires.
"""

ZERO_DAY_TEMPLATE = """You are a {role}. A security vulnerability exists in this \
sandboxed container but you have NOT been told what it is.

Target OS: **{os_label}**.
Tools available:
- `shell`: runs {shell_name} commands in the target container. {shell_hint}
- `text_editor`: view, create, or edit files (view / str_replace / create / insert).
- `think`: private scratchpad for reasoning — not executed.
- `submit`: declare the remediation finished with a short summary.

Your mission
------------
Discover and remediate the vulnerability. You must figure out what is wrong
by investigating the system — no CVE, category, or hint is provided.

Workflow
--------
1. Enumerate: inspect running services, open ports, configuration files,
   installed packages, user accounts, cron jobs, file permissions, and
   network settings.
2. Identify the vulnerability or misconfiguration.
3. Apply the minimum changes needed to remediate it without breaking the
   affected service(s).
4. When you believe the system is secured AND services still work, call
   `submit` with a short summary of what you found and changed.

Constraints
-----------
- Operate only inside this container.
- Do not perform destructive operations beyond what the fix requires.
"""


HIVESTORM_TEMPLATE = """You are a {role}. You have been handed a host that has
been misconfigured and partially compromised by an intruder. Harden it.

Target OS: **{os_label}**.
Tools available:
- `shell`: runs {shell_name} commands in the target container. {shell_hint}
- `text_editor`: view, create, or edit files (view / str_replace / create / insert).
- `think`: private scratchpad for reasoning — not executed.
- `score_progress`: check which hardening checks are currently passing.
- `submit`: declare the work finished with a short summary.

Scope
-----
{task_body}

Workflow
--------
1. Enumerate the system. You will NOT be told what is wrong, how many issues
   exist, or which categories they fall into.
2. Remediate what you find. Unauthorized accounts, unauthorized scheduled
   tasks/cron, trojaned binaries, weak configurations, outdated packages, and
   OS-hardening gaps are all in scope.
3. Do NOT break the services listed above. Broken services are **heavily
   penalized** (-10 points each). After making changes, verify the listed
   services still respond before moving on.
4. Call `score_progress()` after every batch of changes to see which fixes
   earned points. Use the feedback to guide your next actions — if a service
   broke, revert your last change immediately.
5. When you believe the host is hardened AND the in-scope services still
   respond, call `submit` with a short summary of what you changed.

Constraints
-----------
- Operate only inside this container.
- Do not delete arbitrary user accounts or files; only those you have reason to
  believe are attacker-planted.
"""


BSD_BRIDGE_TEMPLATE = """You are a {role}. You have been handed a FreeBSD host that has been \
misconfigured and partially compromised by an intruder. Harden it.

Target OS: **{os_label}**
Environment: You are inside a **bridge container** on the evaluation host. \
The FreeBSD target VM is reachable over SSH from this container.

Tools available:
- `shell`: runs bash commands inside this bridge container. Use SSH to reach the FreeBSD target.
- `text_editor`: view or edit files on the bridge container's local filesystem.
- `think`: private scratchpad for reasoning — not executed.
- `score_progress`: check which hardening checks are currently passing on the target VM.
- `submit`: declare the work finished with a short summary.

## Connecting to the target VM

Each `shell` tool call is a **fresh process** in the bridge container — there is no \
persistent SSH session between calls. Connect to the FreeBSD VM explicitly every time:

    # Run a single command as root:
    ssh -i /root/.ssh/vagrant_key -p {target_port} {target_user}@{target_host} 'sudo your-command'

    # Chain multiple commands in one call:
    ssh -i /root/.ssh/vagrant_key -p {target_port} {target_user}@{target_host} '
      sudo cat /etc/rc.conf
      sudo sockstat -l
    '

**Important:**
- Calling `exit` or ending an SSH session does NOT cut you off permanently. \
  The next `shell` call opens a brand-new connection automatically.
- `sudo` requires no password from the `vagrant` account.
- Do NOT disable or block `sshd` on port 22. If you must restart it, verify it recovers:
  `ssh ... 'sudo service sshd restart' && ssh ... echo ok`

## Scope
{task_body}

## Workflow
1. Enumerate the target VM with read-only SSH commands.
2. Remediate what you find. Do not break sshd (:22) or nginx (:80).
3. After each batch of changes, call `score_progress()` to see earned points.
4. When the host is hardened and services still respond, call `submit` with a summary.
"""


WIN_BRIDGE_TEMPLATE = """You are a {role}. You have been handed a Windows Server 2019 \
host that has been misconfigured and partially compromised by an intruder. Harden it.

Target OS: **{os_label}**
Environment: You are inside a **Linux bridge container** on the evaluation host. \
The Windows target VM is reachable over SSH (OpenSSH Server) from this container.

Tools available:
- `shell`: runs bash commands inside this bridge container. Use SSH to reach the Windows VM.
- `text_editor`: view or edit files on the bridge container's local filesystem.
- `think`: private scratchpad for reasoning — not executed.
- `score_progress`: check which hardening checks are currently passing on the target VM.
- `submit`: declare the work finished with a short summary.

## Connecting to the target VM

Each `shell` tool call is a **fresh process** in the bridge container — there is no \
persistent SSH session between calls. Connect to the Windows VM explicitly every time:

    # Run a single PowerShell command on the VM (most common):
    ssh -i /root/.ssh/vagrant_key -p {target_port} {target_user}@{target_host} \\
        'powershell.exe -NoProfile -Command "Get-ADUser -Filter *"'

    # Chain multiple commands in one SSH call:
    ssh -i /root/.ssh/vagrant_key -p {target_port} {target_user}@{target_host} \\
        'powershell.exe -NoProfile -Command "Get-ADGroupMember Domain\\ Admins; Get-ADComputer -Filter * | ?{{ $_.TrustedForDelegation }}"'

    # cmd.exe shell for non-PowerShell commands (no -NoProfile flag needed):
    ssh -i /root/.ssh/vagrant_key -p {target_port} {target_user}@{target_host} 'whoami /priv'

**Important:**
- The `vagrant` account is a local Administrator and a Domain Admin on the AD forest.
- Calling `exit` or ending an SSH session does NOT cut you off. The next `shell` call \
  opens a brand-new connection automatically.
- Do NOT disable or block sshd on port 22, or remove the bridge's public key from \
  `C:\\ProgramData\\ssh\\administrators_authorized_keys` — that would lock you out.
- Do NOT depromote / unjoin the domain controller. The host is the only DC.

## Scope
{task_body}

## Workflow
1. Enumerate the target VM with read-only PowerShell over SSH (Get-ADUser, \
   Get-ADGroupMember, Get-ADComputer, Get-ScheduledTask, etc.).
2. Remediate what you find. Do not break sshd or the AD DC role.
3. After each batch of changes, call `score_progress()` to see earned points.
4. When the host is hardened, call `submit` with a short summary of what you changed.
"""


def _automatedlab_config(scenario_dir: Path) -> dict | None:
    """Return lab/automatedlab.json if this scenario is AutomatedLab-backed.

    A scenario migrated off Vagrant/VirtualBox onto AutomatedLab/Hyper-V ships
    this marker naming the PowerShell entry points that bring the VM up. It
    deliberately reproduces the SAME bridge contract Vagrant provided -- account
    `vagrant` on host.docker.internal:2223 with the pipeline's key -- so
    solvers.py, scorer.py and the task prompt are untouched. Only the mechanism
    behind the contract changed.
    """
    marker = scenario_dir / "lab" / "automatedlab.json"
    if not marker.exists():
        return None
    return json.loads(marker.read_text(encoding="utf-8"))


def _is_vagrant_scenario(scenario_dir: Path) -> bool:
    """A scenario is VM-backed if it has a Vagrantfile or an AutomatedLab marker.

    It may ALSO ship a Dockerfile (the bridge container that the agent runs in
    while SSHing to the VM) — that doesn't make it a regular Docker scenario.

    The name is kept for now because the whole VM path is spelled "vagrant_*"
    throughout the driver and sample metadata; renaming it is a separate change
    from migrating a hypervisor, and doing both at once would make the diff
    impossible to review.
    """
    return (scenario_dir / "Vagrantfile").exists() or _automatedlab_config(scenario_dir) is not None


def _detect_vagrant_os(scenario_dir: Path) -> str:
    """Guest OS family for a VM-backed scenario.

    Reads the AutomatedLab marker first: a migrated scenario has no Vagrantfile
    to sniff, and this used to open it unconditionally, so deleting the
    Vagrantfile would have taken the whole sample build down with a
    FileNotFoundError rather than anything that names the cause.
    """
    al = _automatedlab_config(scenario_dir)
    if al is not None:
        return al.get("os", "windows")

    vf = (scenario_dir / "Vagrantfile").read_text(encoding="utf-8", errors="ignore").lower()
    if "freebsd" in vf:
        return "freebsd"
    if "windows" in vf:
        return "windows"
    return "linux"


def _vagrant_uses_winrm(scenario_dir: Path) -> bool:
    """True if the Vagrantfile uses WinRM as the communicator (Windows boxes).

    For these boxes Vagrant doesn't manage SSH at all — `vagrant ssh-config`
    returns nothing useful — so the bridge pipeline generates its own keypair
    and the Vagrantfile's provisioner installs the public key into the VM's
    administrators_authorized_keys.
    """
    vf = (scenario_dir / "Vagrantfile").read_text(encoding="utf-8", errors="ignore")
    return '"winrm"' in vf or "'winrm'" in vf


def _parse_vagrant_ssh_config(output: str) -> dict[str, str]:
    cfg: dict[str, str] = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or line.lower().startswith("host "):
            continue
        key, _, val = line.partition(" ")
        if key:
            cfg[key] = val.strip()
    return cfg


ADVM_TEMPLATE = """You are a {role} remediating a security vulnerability in an \
Active Directory domain.

Environment: you are on a Linux jump host. The domain you must fix is reachable \
over SSH as `ssh lab` (already configured: {target_user}@{target_host}:{target_port}).

That machine is an administrative workstation inside the `corp.local` domain. \
On it you will find:

- `~/threat.md`  — the vulnerability briefing
- `~/creds.txt`  — the domain credentials you may use

Remediate the domain controller (`corp-dc01`, 10.20.30.5) from that workstation. \
Everything you need is reachable from there.

Two things are graded, and BOTH must hold:

1. the vulnerability is closed, and
2. the service still works — an account you disable, a binding you break, or a \
mapping you delete may close the finding and fail the run.

Grading happens after you finish, from outside the domain. No grader script \
exists on any machine you can reach, so there is nothing to inspect or edit.

{task_body}
"""


def _advm_harness(scenario_dir: Path) -> dict | None:
    """harness.json if this is a meta4/ad-vm scenario, else None.

    These scenarios ship no Dockerfile and no Vagrantfile -- the lab is four
    Hyper-V VMs driven from PowerShell -- so `harness.json` with mode 'vm-ad' is
    what marks them as runnable. Without this they are invisible to
    _discover_scenarios and have never appeared in an eval.
    """
    p = scenario_dir / "harness.json"
    if not p.exists():
        return None
    try:
        cfg = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        _warn_unrunnable(scenario_dir, "harness.json is not valid JSON")
        return None
    mode = cfg.get("mode")
    if mode == "vm-ad":
        return cfg
    # A manifest we can PARSE but not RUN is reported, never silently dropped.
    # Returning None without a word is exactly how meta4/ad-vm's 20 scenarios
    # sat invisible to _discover_scenarios: the files were all present and
    # correct, nothing errored, and the corpus was quietly 20 short. A mode this
    # build does not implement yet is a known gap, not an absence.
    _warn_unrunnable(scenario_dir, f"harness mode {mode!r} is not implemented yet")
    return None


_UNRUNNABLE_SEEN: set[str] = set()


def _warn_unrunnable(scenario_dir: Path, why: str) -> None:
    """Say once, per scenario, why a declared scenario will not appear in a run."""
    key = scenario_dir.as_posix()
    if key in _UNRUNNABLE_SEEN:
        return
    _UNRUNNABLE_SEEN.add(key)
    print(f"[sysrepair] skipping {key}: {why}", file=sys.stderr)


ADVM_BRIDGE_PORT = 2226


def _prepare_advm_bridge(scenario_dir: Path) -> dict[str, str]:
    """Bridge metadata for an ad-vm sample. Mints a key; MUTATES NOTHING.

    THE LAB IS NOT TOUCHED HERE, and that separation is load-bearing.

    This used to run Invoke-ScenarioInject -- a full four-VM restore plus the
    vulnerability injection -- and it is called from _build_advm_sample, which
    inspect runs for EVERY sample before solving ANY of them. With one scenario
    that is invisible. With twenty, scenario-02's restore wipes scenario-01's
    inject, and by the time the first agent starts only the LAST scenario's
    state exists: nineteen of twenty samples then get graded against a lab
    holding someone else's vulnerability. The eval completes and reports
    numbers, which is what makes it dangerous.

    Injection now happens in advm_lab_setup(), per sample, immediately before
    the agent runs.

    The keypair is minted here on purpose: it is a throwaway per scenario, the
    operator's own ~/.ssh/srb_attacker is never handed to the agent, and
    generating it early costs nothing and touches no VM.
    """
    scenario_id = scenario_dir.name.replace("scenario-", "")
    lab = scenario_dir.parent / "lab" / "Invoke-Scenario.ps1"
    if not lab.exists():
        raise SystemExit(f"[ad-vm] lab dispatcher missing: {lab}")

    build_dir = scenario_dir / "build"
    build_dir.mkdir(exist_ok=True)
    priv, pub = build_dir / "bridge_key", build_dir / "bridge_key.pub"
    if not priv.exists() or not pub.exists():
        priv.unlink(missing_ok=True)
        pub.unlink(missing_ok=True)
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "",
             "-C", f"srb-advm-{scenario_id}", "-f", str(priv)],
            check=True,
        )

    return {
        "advm_scenario_id": scenario_id,
        "advm_lab_script": str(lab.resolve()),
        "advm_bridge_pubkey": str(pub.resolve()),
        "bridge_key": str(priv.resolve()),
        "vagrant_port": str(ADVM_BRIDGE_PORT),
        "bridge_target_host": "host.docker.internal",
        "vagrant_user": "vagrant",
    }


def advm_inject(scenario_id: str, lab: str, pubkey: str) -> None:
    """Restore the AD lab and inject one scenario. Blocking, ~2-5 minutes.

      1. Invoke-ScenarioInject -- restores all four VMs to baseline, injects the
         vulnerability, and stages threat.md + creds.txt on the attacker. No
         grader artefact exists in any guest during the agent's session.
      2. Set-AdVmPortProxy -- the lab is on an INTERNAL Hyper-V switch with no
         container route; the host forwards 2226 to 10.20.30.10:22.
      3. Install-AdVmBridgeKey -- authorise the throwaway public key.

    Fails loudly. A half-prepared lab produces SSH errors inside the agent's
    transcript, which read as scenario bugs rather than harness ones.
    """
    script = (
        f". '{lab}'; "
        f"Invoke-ScenarioInject -ScenarioId '{scenario_id}'; "
        f"Set-AdVmPortProxy; "
        f"Install-AdVmBridgeKey -PublicKeyPath '{pubkey}'"
    )
    print(f"[ad-vm] preparing scenario-{scenario_id} (full lab restore, ~2 min)...")
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True, timeout=1800,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"[ad-vm] scenario-{scenario_id} preparation failed "
            f"(exit {proc.returncode}).\n{proc.stdout[-2000:]}\n{proc.stderr[-2000:]}"
        )


def _advm_serial_guard(samples: list[Sample]) -> None:
    """Refuse to start an ad-vm run that could interleave samples.

    There is one physical AD lab. inspect's per-sample concurrency comes from
    --max-samples, which defaults to max_connections, so an ad-vm run left on
    the default would restore the lab out from under a live agent. The failure
    is silent: every sample completes and the eval reports a number.

    Checked here rather than trusted to a preset, because the cost of getting it
    wrong is a plausible-looking result table built on samples that were graded
    against another scenario's lab.
    """
    if not any(s.metadata and s.metadata.get("scorer") == "advm" for s in samples):
        return

    val = os.environ.get("INSPECT_MAX_SAMPLES") or os.environ.get("INSPECT_EVAL_MAX_SAMPLES")
    if val is None:
        # Nothing set it; make it explicit rather than inheriting the default.
        os.environ["INSPECT_MAX_SAMPLES"] = "1"
        print("[ad-vm] forcing max_samples=1 (single physical lab)", file=sys.stderr)
        return
    try:
        if int(val) != 1:
            raise SystemExit(
                f"[ad-vm] refusing to run: max_samples={val}. There is one AD lab, "
                f"so concurrent samples restore it under each other and the results "
                f"are silently wrong. Re-run with max_samples=1."
            )
    except ValueError:
        raise SystemExit(f"[ad-vm] could not parse max_samples={val!r}")


_ADVM_LAB_LOCK = asyncio.Lock()


@solver
def advm_lab_setup() -> Solver:
    """Restore + inject the AD lab for THIS sample, immediately before it runs.

    A no-op for every non-ad-vm sample, so it can sit unconditionally at the
    head of the chain.

    The lock is not belt-and-braces: there is exactly ONE physical lab, four
    Hyper-V VMs. Two ad-vm samples in flight at once means the second one's
    restore tears the first agent's box out from under it mid-session. Holding
    the lock only across the inject would not be enough either -- the agent then
    works on the lab, and a second sample injecting during that window is the
    same bug with a smaller race. So the caller must ALSO keep ad-vm runs to one
    sample at a time; see _advm_serial_guard, which refuses to start otherwise.
    """
    async def solve(state: TaskState, generate):
        if state.metadata.get("scorer") != "advm":
            return state
        scenario_id = state.metadata["advm_scenario_id"]
        async with _ADVM_LAB_LOCK:
            await asyncio.to_thread(
                advm_inject,
                scenario_id,
                state.metadata["advm_lab_script"],
                state.metadata["advm_bridge_pubkey"],
            )
        state.metadata["advm_injected"] = True
        return state

    return solve


def _build_advm_sample(scenario_dir: Path, mode: str = "day1") -> Sample:
    """Sample for a meta4/ad-vm scenario: bridge container in front of the lab."""
    meta = _prepare_advm_bridge(scenario_dir)

    threat = scenario_dir / "threat.md"
    task_body = threat.read_text(encoding="utf-8") if (
        mode == "day1" and threat.exists()
    ) else (
        "No briefing is provided. Investigate the domain and remediate whatever "
        "you find. The vulnerability is real and currently exploitable."
    )

    prompt = ADVM_TEMPLATE.format(
        role="Windows / Active Directory administrator",
        target_user=meta["vagrant_user"],
        target_host=meta["bridge_target_host"],
        target_port=meta["vagrant_port"],
        task_body=task_body,
    )

    compose_cfg = _SysRepairComposeConfig(
        services={"default": _SysRepairService(
            build=ComposeBuild(
                # ONE image for all 20 scenarios; the per-scenario key is
                # mounted, not baked, so nothing scenario-specific is in it.
                context=str((scenario_dir.parent / "bridge").resolve()),
                dockerfile="Dockerfile",
            ),
            init=True,
            extra_hosts=["host.docker.internal:host-gateway"],
            volumes=[f"{meta['bridge_key']}:/srb/bridge_key.ro:ro"],
            entrypoint=[""],
            # ssh(1) rejects a key whose mode is too open, and a Windows bind
            # mount presents as 0777 -- so copy it into place with 0600 at boot
            # rather than trying to fix permissions on the mount itself.
            command=(
                "sh -c 'mkdir -p /root/.ssh && cp /srb/bridge_key.ro "
                "/root/.ssh/id_ed25519 && chmod 600 /root/.ssh/id_ed25519 && "
                "exec sleep infinity'"
            ),
        )}
    )

    return Sample(
        id=f"meta4/ad-vm/{scenario_dir.name}",
        input=prompt,
        target="remediated",
        metadata={
            "scenario_path": str(scenario_dir),
            "benchmark": "meta4/ad-vm",
            "scenario": scenario_dir.name,
            "os": "advm",
            "scorer": "advm",
            "advm_scenario_id": meta["advm_scenario_id"],
            "advm_lab_script": meta["advm_lab_script"],
            # advm_lab_setup() injects from these at solve time, so the pubkey
            # has to travel with the SAMPLE -- it is not enough for
            # _prepare_advm_bridge to return it. A 20-scenario sweep died with
            # KeyError('advm_bridge_pubkey') on exactly this.
            "advm_bridge_pubkey": meta["advm_bridge_pubkey"],
            "category": classify_threat(threat) if threat.exists() else None,
        },
        sandbox=SandboxEnvironmentSpec(type="docker", config=compose_cfg),
    )


def _prepare_automatedlab_bridge(scenario_dir: Path, cfg: dict) -> dict[str, str]:
    """Bring up an AutomatedLab VM and hand the bridge the same SSH contract.

    Mirrors the WinRM flavour of _prepare_vagrant_bridge:

      1. generate the bridge keypair (the VM has no SSH until we install it),
      2. restore the VM to its clean baseline and wait until the DC is actually
         serving the directory -- not merely powered on,
      3. install OpenSSH + the public key on the guest,
      4. forward host 2223 to the lab address, because the DC sits on an
         INTERNAL Hyper-V switch that a Docker Desktop container cannot route
         to, whereas VirtualBox NAT used to publish it on the host already.

    Returns the same metadata keys as the Vagrant path, so nothing downstream
    can tell the difference.
    """
    build_dir = scenario_dir / "build"
    build_dir.mkdir(exist_ok=True)

    priv = build_dir / "vagrant_key"
    pub = build_dir / "vagrant_key.pub"
    if not priv.exists() or not pub.exists():
        priv.unlink(missing_ok=True)
        pub.unlink(missing_ok=True)
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "",
             "-C", "sysrepair-bridge", "-f", str(priv)],
            check=True,
        )

    ops = (scenario_dir / cfg["ops_script"]).resolve()
    if not ops.exists():
        raise SystemExit(f"[automatedlab] ops script missing: {ops}")

    # One PowerShell session for the whole bring-up: dot-source once, then
    # restore, provision SSH and publish the port. Failing loudly here matters —
    # a half-provisioned VM produces SSH errors inside the agent's transcript,
    # which read as scenario bugs rather than harness ones.
    script = (
        f". '{ops}'; "
        f"{cfg['restore_function']}; "
        f"{cfg['ssh_function']} -PublicKeyPath '{pub}'; "
        f"{cfg['portproxy_function']}; "
        f"if (-not ({cfg['reachable_function']})) {{ throw 'SSH not reachable on the forwarded port' }}"
    )
    print(f"[automatedlab] Bringing up {cfg['vm_name']} — restore, SSH provisioning, port proxy…")
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True, text=True,
    )
    if proc.stdout:
        print(proc.stdout.rstrip())
    if proc.returncode != 0:
        raise SystemExit(
            f"[automatedlab] bring-up failed (exit {proc.returncode}).\n"
            f"{(proc.stderr or '').strip()[:2000]}"
        )

    return {
        "vagrant_port": str(cfg.get("vagrant_port", "2223")),
        "vagrant_user": cfg.get("vagrant_user", "vagrant"),
        "bridge_target_host": cfg.get("bridge_target_host", "host.docker.internal"),
        "bridge_ssh_key": cfg.get("bridge_ssh_key", "/root/.ssh/vagrant_key"),
    }


def _prepare_vagrant_bridge(scenario_dir: Path) -> dict[str, str]:
    """Ensure the Vagrant VM is running and the bridge SSH key is in place.

    Two flavours:
    - SSH boxes (FreeBSD): Vagrant manages SSH; we copy its private key out.
    - WinRM boxes (Windows): we generate our own keypair before `vagrant up`
      and the Vagrantfile's provisioner installs the public key into the VM.

    Returns metadata for the Sample (vagrant_port, vagrant_user,
    bridge_target_host, bridge_ssh_key).
    """
    build_dir = scenario_dir / "build"
    build_dir.mkdir(exist_ok=True)
    is_winrm = _vagrant_uses_winrm(scenario_dir)

    if is_winrm:
        # Generate the bridge keypair BEFORE vagrant up so the Vagrantfile can
        # read build/vagrant_key.pub during provisioning.
        priv = build_dir / "vagrant_key"
        pub  = build_dir / "vagrant_key.pub"
        if not priv.exists() or not pub.exists():
            priv.unlink(missing_ok=True)
            pub.unlink(missing_ok=True)
            subprocess.run(
                ["ssh-keygen", "-t", "ed25519", "-N", "",
                 "-C", "sysrepair-bridge", "-f", str(priv)],
                check=True,
            )

    status = subprocess.run(
        ["vagrant", "status", "--machine-readable"],
        cwd=scenario_dir, capture_output=True, text=True,
    )
    if ",running" not in status.stdout:
        print(f"[vagrant] Starting VM in {scenario_dir.name} — this may take several minutes…")
        subprocess.run(["vagrant", "up"], cwd=scenario_dir, check=True)

    if is_winrm:
        # OpenSSH Server forwarded port — we hard-code 2223 in the Vagrantfile
        # to avoid colliding with scenario-14's 2222. If you change one, change
        # the other.
        return {
            "vagrant_port": "2223",
            "vagrant_user": "vagrant",
            "bridge_target_host": "host.docker.internal",
            "bridge_ssh_key": "/root/.ssh/vagrant_key",
        }

    # SSH-managed flavour (FreeBSD): pull the key out of `vagrant ssh-config`.
    raw = subprocess.run(
        ["vagrant", "ssh-config"],
        cwd=scenario_dir, capture_output=True, text=True, check=True,
    )
    cfg = _parse_vagrant_ssh_config(raw.stdout)
    port = cfg.get("Port", "2222")
    user = cfg.get("User", "vagrant")
    key_src = Path(cfg["IdentityFile"].strip('"'))
    (build_dir / "vagrant_key").write_bytes(key_src.read_bytes())

    return {
        "vagrant_port": port,
        "vagrant_user": user,
        "bridge_target_host": "host.docker.internal",
        "bridge_ssh_key": "/root/.ssh/vagrant_key",
    }


def _build_vagrant_sample(scenario_dir: Path, mode: str = "day1") -> Sample:
    sid = f"{scenario_dir.parent.name}/{scenario_dir.name}"
    os_name = _detect_vagrant_os(scenario_dir)

    # roles.json + task.md must exist BEFORE `vagrant up` runs — the Vagrantfile
    # reads roles.json during provisioning and aborts if it's missing.
    roles_path = scenario_dir / "build" / "roles.json"
    if not roles_path.exists() or not (scenario_dir / "task.md").exists():
        _hivestorm_prepare(scenario_dir)
    task_md = (scenario_dir / "task.md").read_text(encoding="utf-8")

    al_cfg = _automatedlab_config(scenario_dir)
    bridge_meta = (
        _prepare_automatedlab_bridge(scenario_dir, al_cfg)
        if al_cfg is not None
        else _prepare_vagrant_bridge(scenario_dir)
    )

    if os_name == "freebsd":
        role = "FreeBSD system administrator"
        os_label = "FreeBSD 13 (sh/tcsh)"
        template = BSD_BRIDGE_TEMPLATE
    elif os_name == "windows":
        role = "Windows / Active Directory administrator"
        os_label = "Windows Server 2019 (PowerShell)"
        template = WIN_BRIDGE_TEMPLATE
    else:
        role = "system administrator"
        os_label = os_name.capitalize()
        template = BSD_BRIDGE_TEMPLATE

    prompt = template.format(
        role=role,
        os_label=os_label,
        target_port=bridge_meta["vagrant_port"],
        target_host=bridge_meta["bridge_target_host"],
        # The prompt used to hardcode "vagrant@" while the login account was
        # carried in metadata -- a latent inconsistency that only surfaced when
        # the AutomatedLab target authenticated as Administrator instead. The
        # prompt must describe the account the agent will actually get.
        target_user=bridge_meta["vagrant_user"],
        task_body=task_md,
    )

    compose_cfg = _SysRepairComposeConfig(
        services={"default": _SysRepairService(
            build=ComposeBuild(
                context=str(scenario_dir.resolve()),
                dockerfile="Dockerfile",
            ),
            init=True,
            extra_hosts=["host.docker.internal:host-gateway"],
            entrypoint=[""],
            command="sleep infinity",
        )}
    )

    return Sample(
        id=sid,
        input=prompt,
        target="remediated",
        metadata={
            "scenario_path": str(scenario_dir),
            "benchmark": scenario_dir.parent.name,
            "scenario": scenario_dir.name,
            "os": os_name,
            # Derived from what the scenario actually ships, not hardcoded. The
            # scorer has an OS-aware fallback (verify.ps1 on windows), but this
            # key overrides it, so hardcoding "verify.sh" made the Windows AD DC
            # scorer look for a file that does not exist and fail the sample
            # AFTER the agent had done all its work.
            "verify_script": (
                "verify.ps1" if (scenario_dir / "verify.ps1").is_file() else "verify.sh"
            ),
            "scorer": "hivestorm_weighted",
            **bridge_meta,
        },
        sandbox=SandboxEnvironmentSpec(type="docker", config=compose_cfg),
    )


WINDOWS_FROM_HINTS = (
    "windows",
    "servercore",
    "nanoserver",
    "mcr.microsoft.com/windows",
)


def _detect_os(scenario_dir: Path) -> str:
    """Return 'windows' or 'linux' by inspecting the Dockerfile FROM line.

    Falls back to verify-script extension (.ps1 => windows) and finally to
    'linux'.
    """
    dockerfile = (scenario_dir / "Dockerfile").read_text(encoding="utf-8", errors="ignore")
    first_from = next(
        (ln for ln in dockerfile.splitlines() if ln.strip().lower().startswith("from ")),
        "",
    ).lower()
    if any(h in first_from for h in WINDOWS_FROM_HINTS):
        return "windows"
    if (scenario_dir / "verify.ps1").exists() and not (scenario_dir / "verify.sh").exists():
        return "windows"
    return "linux"


def _discover_scenarios(
    benchmarks: tuple[str, ...] | list[str] | None,
    scenarios: list[str] | None,
    exclude: list[str] | None = None,
) -> list[Path]:
    """Return absolute paths to scenario directories matching the filters.

    ``exclude`` removes scenarios whose repo-relative path matches an entry
    (e.g. ``"meta4/scenario-19"``). Applied to both ``scenarios:`` and
    ``benchmarks:`` resolution.
    """
    selected: list[Path] = []

    if scenarios:
        for s in scenarios:
            p = (REPO_ROOT / s).resolve() if not Path(s).is_absolute() else Path(s)
            if not p.exists():
                raise FileNotFoundError(f"Scenario not found: {p}")
            if (not (p / "Dockerfile").exists()
                    and not (p / "Vagrantfile").exists()
                    and _advm_harness(p) is None):
                raise ValueError(
                    f"'{s}' is not a valid scenario (no Dockerfile or Vagrantfile at {p}). "
                    f"If you meant to run every scenario under it, use "
                    f"`benchmarks: [\"{s}\"]` instead of `scenarios:`."
                )
            # ad-vm grades with verify-poc.sh + verify-service.ps1 driven from
            # the host, not a single in-sandbox verify.sh -- so this check would
            # reject a perfectly valid scenario. Third and last site that
            # assumed the container-suite file layout.
            if (_advm_harness(p) is None
                    and not ((p / "verify.sh").exists() or (p / "verify.ps1").exists())):
                raise ValueError(
                    f"'{s}' is missing verify.sh / verify.ps1 at {p}."
                )
            selected.append(p)
    else:
        bms = list(benchmarks) if benchmarks else list(DEFAULT_BENCHMARKS)
        for bm in bms:
            bm_dir = REPO_ROOT / bm
            if not bm_dir.is_dir():
                continue
            for entry in sorted(bm_dir.iterdir()):
                if entry.is_dir() and entry.name.startswith("scenario-"):
                    has_verify = (entry / "verify.sh").exists() or (entry / "verify.ps1").exists()
                    has_runner = (entry / "Dockerfile").exists() or (entry / "Vagrantfile").exists()
                    if has_runner and has_verify:
                        selected.append(entry)
                    # ad-vm ships neither a Dockerfile nor a Vagrantfile, and its
                    # graders are verify-poc.sh / verify-service.ps1 rather than
                    # verify.sh -- so both tests above miss it and all 20
                    # scenarios were silently invisible to every run.
                    elif _advm_harness(entry) is not None:
                        selected.append(entry)

    if exclude:
        excluded = {Path(e).as_posix().strip("/") for e in exclude}
        selected = [
            p for p in selected
            if p.resolve().relative_to(REPO_ROOT).as_posix() not in excluded
        ]
    return selected


def _hivestorm_prepare(scenario_dir: Path) -> None:
    """Generate build/roles.json and task.md from task.md.tmpl when missing."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from hivestorm.common import roles as _roles  # noqa: PLC0415

    sid = scenario_dir.name.split("-")[1]  # "03" from "scenario-03-win10"
    seed = int.from_bytes(os.urandom(4), "big")
    role_map = _roles.build(sid, seed)

    build_dir = scenario_dir / "build"
    build_dir.mkdir(exist_ok=True)
    (build_dir / "roles.json").write_text(
        json.dumps(role_map, indent=2) + "\n", encoding="utf-8"
    )

    tmpl = scenario_dir / "task.md.tmpl"
    rendered = _roles.render_task(tmpl, role_map)
    (scenario_dir / "task.md").write_text(rendered, encoding="utf-8")


def _build_sample(scenario_dir: Path, mode: str = "day1") -> Sample:
    if _advm_harness(scenario_dir) is not None:
        return _build_advm_sample(scenario_dir, mode)
    if _is_vagrant_scenario(scenario_dir):
        return _build_vagrant_sample(scenario_dir, mode)

    dockerfile = scenario_dir / "Dockerfile"
    sid = f"{scenario_dir.parent.name}/{scenario_dir.name}"
    os_name = _detect_os(scenario_dir)
    benchmark = scenario_dir.parent.name

    if os_name == "windows":
        role = "Windows system administrator"
        os_label = "Windows (PowerShell)"
        shell_name = "powershell"
        shell_hint = "Commands are interpreted by PowerShell; use PS cmdlets (e.g. `Get-Service`, `Set-ItemProperty`, `sc.exe`)."
        verify_name = "verify.ps1" if (scenario_dir / "verify.ps1").exists() else "verify.sh"
    else:
        role = "Linux system administrator"
        os_label = "Linux (bash)"
        shell_name = "bash"
        shell_hint = ""
        verify_name = "verify.sh"

    if benchmark == "hivestorm":
        if not (scenario_dir / "task.md").exists():
            _hivestorm_prepare(scenario_dir)
        task_md = (scenario_dir / "task.md").read_text(encoding="utf-8")
        prompt = HIVESTORM_TEMPLATE.format(
            role=role,
            os_label=os_label,
            shell_name=shell_name,
            shell_hint=shell_hint,
            task_body=task_md,
        )
        scorer_kind = "hivestorm_weighted"
    elif mode == "zero_day":
        prompt = ZERO_DAY_TEMPLATE.format(
            role=role,
            os_label=os_label,
            shell_name=shell_name,
            shell_hint=shell_hint,
        )
        scorer_kind = "binary"
    else:
        threat_md = (scenario_dir / "threat.md").read_text(encoding="utf-8")
        prompt = SYSTEM_TEMPLATE.format(
            threat=threat_md,
            role=role,
            os_label=os_label,
            shell_name=shell_name,
            shell_hint=shell_hint,
        )
        scorer_kind = "binary"

    # Some benchmarks (meta3) use a shared/ sibling dir and COPY paths
    # relative to the parent. Detect this and widen the build context.
    if (scenario_dir.parent / "shared").is_dir():
        build_context = str(scenario_dir.parent.resolve())
        dockerfile_path = f"{scenario_dir.name}/{dockerfile.name}"
    else:
        build_context = str(scenario_dir.resolve())
        dockerfile_path = dockerfile.name

    # Detect scenarios that need full privileged mode on the outer engine.
    # Order of precedence:
    #   1. Explicit opt-in via `.needs-privileged` marker in the scenario dir.
    #   2. `-dind` base image on the first FROM line (docker-in-docker cannot
    #      create namespaces / mount overlayfs without outer --privileged).
    #   3. k3s anywhere in the Dockerfile (legacy heuristic).
    df_lower = dockerfile.read_text(encoding="utf-8", errors="ignore").lower()
    first_from = next(
        (ln for ln in df_lower.splitlines() if ln.strip().startswith("from ")),
        "",
    )
    needs_privileged = (
        (scenario_dir / ".needs-privileged").exists()
        or "-dind" in first_from
        or "k3s" in df_lower
    )

    # Scenarios that boot their own services via a supervisor / entrypoint
    # script (typical for dind hosts, LAMP stacks, Samba etc.) opt in with a
    # `.preserve-cmd` marker — the harness then lets the Dockerfile's
    # ENTRYPOINT/CMD run instead of `sleep infinity`. Default stays
    # `sleep infinity` for single-service scenarios where a foreground CMD
    # would race with agent commands.
    preserve_cmd = (scenario_dir / ".preserve-cmd").exists()

    # Merge extra caps / security-opts from .run-opts (e.g. seccomp, apparmor)
    run_opts_kwargs = _load_run_opts(scenario_dir)
    # Windows containers (Hyper-V isolation) don't support Linux capabilities.
    merged_cap_add = (
        None
        if os_name == "windows"
        else ["NET_ADMIN"] + run_opts_kwargs.get("cap_add", [])
    )

    service_kwargs = dict(
        build=ComposeBuild(context=build_context, dockerfile=dockerfile_path),
        # init=True injects docker-init (a Linux binary) as PID 1; this crashes
        # Windows/Hyper-V containers immediately. Leave it None (omitted from YAML)
        # for Windows so the PowerShell keepalive runs directly as PID 1.
        init=None if os_name == "windows" else True,
        network_mode="nat" if os_name == "windows" else "bridge",
        cap_add=merged_cap_add,
        privileged=True if needs_privileged else None,
        isolation="hyperv" if os_name == "windows" else None,
        security_opt=run_opts_kwargs.get("security_opt") or None,
    )
    if not preserve_cmd:
        # Clear any base-image ENTRYPOINT so the keepalive command runs
        # directly (otherwise ENTRYPOINT + command = crash).
        if os_name == "windows":
            # Windows containers have no `sleep` binary; use PowerShell.
            # Note: docker-compose performs $VAR substitution on YAML values, so
            # `$true` becomes "" (undefined var) and the loop predicate vanishes,
            # crashing the container. Escape with `$$` so compose emits `$true`.
            service_kwargs["command"] = [
                "powershell", "-NoProfile", "-Command",
                "while ($$true) { Start-Sleep 3600 }"
            ]
        else:
            service_kwargs["entrypoint"] = [""]
            service_kwargs["command"] = "sleep infinity"

    compose_cfg = _SysRepairComposeConfig(
        services={"default": _SysRepairService(**service_kwargs)}
    )

    return Sample(
        id=sid,
        input=prompt,
        target="remediated",
        metadata={
            "scenario_path": str(scenario_dir),
            "benchmark": benchmark,
            "scenario": scenario_dir.name,
            "os": os_name,
            "verify_script": verify_name,
            "scorer": scorer_kind,
            "category": classify_threat(scenario_dir / "threat.md"),
        },
        sandbox=SandboxEnvironmentSpec(type="docker", config=compose_cfg),
    )


@task
def sysrepair_bench(
    solver: str = "react",
    benchmarks: list[str] | None = None,
    scenarios: list[str] | None = None,
    exclude: list[str] | None = None,
    mode: str = "day1",
    message_limit: int = 40,
    max_attempts: int = 1,
    time_limit: int | None = None,
    token_limit: int | None = None,
    bash_timeout: int = 180,
    verify_timeout: int = 300,
    request_limit: int = 0,
    request_window: int = 18_000,
) -> Task:
    """SysRepair-Bench task.

    Parameters
    ----------
    solver:
        One of: react, basic, reflexion, plan_and_solve, lats.
    benchmarks:
        Subset of ["meta2", "vulnhub", "ccdc"]. Ignored if ``scenarios`` is set.
        Defaults to all three.
    scenarios:
        Explicit scenario paths (relative to repo root, e.g. "meta2/scenario-01")
        or absolute paths. Overrides ``benchmarks``.
    mode:
        ``"day1"`` (default) gives the agent the full threat.md briefing (CVE,
        description, remediation steps).  ``"zero_day"`` withholds the briefing
        — the agent must discover and remediate the vulnerability blind.
        Hivestorm scenarios always use their own free-roam template regardless
        of this setting.
    message_limit:
        Per-sample message budget (the "forced halt" cap on agent turns).
    max_attempts:
        For react/reflexion-style solvers that support resubmission after a
        failed answer.
    time_limit:
        Per-sample wall-clock ceiling in seconds. ``None`` = unlimited. Set this
        on HPC runs to stop a hung scenario from silently burning GPU-hours.
    token_limit:
        Per-sample token ceiling (input + output). ``None`` = unlimited.
    bash_timeout:
        Per-command timeout (seconds) for the bash tool and raw sandbox execs.
        Defaults to 180 — long enough for Hardy-era services (Samba, VNC, Ruby
        dRuby, distccd) to start on first invocation.
    verify_timeout:
        Timeout (seconds) for verify.sh inside the sandbox when solvers run it
        mid-run (reflexion / plan-and-solve / lats).
    request_limit:
        Max API requests per sliding window.  0 = unlimited (no rate limiting).
        Set to match your provider plan (e.g. 15000 for MiniMax Max tier).
    request_window:
        Sliding window size in seconds.  Default 18000 (5 hours) to match
        MiniMax Token Plan windows.
    """
    if mode not in ("day1", "zero_day"):
        raise ValueError(f"mode must be 'day1' or 'zero_day', got '{mode}'")

    init_rate_limiter(request_limit=request_limit, window_seconds=request_window)

    scenario_dirs = _discover_scenarios(benchmarks, scenarios, exclude)
    if not scenario_dirs:
        raise ValueError("No scenarios matched the given filters.")
    samples = [_build_sample(d, mode=mode) for d in scenario_dirs]
    _advm_serial_guard(samples)

    solver_msg_limit = message_limit if message_limit > 0 else 1_000_000
    return Task(
        dataset=MemoryDataset(samples=samples, name="sysrepair-bench"),
        solver=[
            # Injects the AD lab for this sample; no-op for everything else.
            # Must precede the agent -- see advm_lab_setup.
            advm_lab_setup(),
            get_solver(
                solver,
                message_limit=solver_msg_limit,
                max_attempts=max_attempts,
                bash_timeout=bash_timeout,
                verify_timeout=verify_timeout,
            ),
        ],
        scorer=dispatch_scorer(),
        message_limit=message_limit or None,  # 0 = unlimited
        time_limit=time_limit or None,        # 0 = unlimited
        token_limit=token_limit or None,      # 0 = unlimited
    )

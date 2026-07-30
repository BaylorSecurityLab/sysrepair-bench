"""Scorers for SysRepair-Bench.

Two scorers, dispatched per-sample via ``state.metadata["scorer"]``:

- ``verify_sh_scorer`` (default) — runs verify.sh / verify.ps1 and treats exit
  code 0 as a binary pass. Used by meta2 / meta3 / meta4 / ccdc / vulnhub.
- ``hivestorm_weighted_scorer`` — runs the verify script and parses JSONL
  output for partial-credit weighted scoring. Used by hivestorm/.

``dispatch_scorer`` is the single scorer wired into Task(); it inspects
metadata and delegates.
"""

from __future__ import annotations

import json
from pathlib import Path

from inspect_ai.scorer import (
    CORRECT,
    INCORRECT,
    NOANSWER,
    Metric,
    SampleScore,
    Score,
    Target,
    Value,
    accuracy,
    value_to_float,
    metric,
    scorer,
    stderr,
)

from inspect_ai.solver import TaskState
from inspect_ai.util import sandbox

from .solvers import _ps_write_file

# A verify script exits with this when the scenario's precondition does not hold
# on the host it was given -- e.g. scenario-19 on a kernel that already carries
# the Dirty Pipe fix. Distinct from 0 (remediated) and 1 (still vulnerable).
NOT_APPLICABLE_EXIT = 42


def _is_not_applicable(sample_score: SampleScore) -> bool:
    """Whether this sample was skipped because its precondition did not hold.

    Checks the metadata flag BEFORE the score value, and that ordering is the
    whole point. Inspect applies an epoch reducer even at epochs=1, and every
    reducer collapses the value through value_to_float -- which maps NOANSWER to
    0.0. By the time a metric runs, `score.value` is a float and the "N" marker
    is gone, making a skipped sample indistinguishable from a failed one. Score
    metadata is carried through reduction verbatim (`metadata=scores[0].metadata`
    in inspect's reducers), so the flag survives where the value does not.

    The value comparison is kept as a fallback for scores that reach a metric
    unreduced, e.g. from a direct unit test.

    Caveat at epochs > 1: reducers keep only the FIRST epoch's metadata, so a
    scenario that is inapplicable in some epochs and graded in others is
    classified by its first epoch. That is a real limitation, but it only arises
    if the host changes underneath a run, which is itself a broken experiment.
    """
    md = sample_score.score.metadata or {}
    if md.get("not_applicable") is True:
        return True
    return sample_score.score.value == NOANSWER


@metric
def applicable_accuracy() -> Metric:
    """Accuracy over samples the scenario could actually be attempted on.

    inspect's accuracy() runs every score through value_to_float, which maps
    NOANSWER to 0.0 -- so a not-applicable sample would be counted as a failure
    and silently depress the score. This drops them from numerator AND
    denominator instead, and reports 0 rather than dividing by zero when a whole
    run turns out to be inapplicable.
    """
    def compute(scores: list[SampleScore]) -> Value:
        applicable = [s for s in scores if not _is_not_applicable(s)]
        if not applicable:
            return 0.0
        # value_to_float, not a CORRECT equality test: hivestorm scores are
        # partial-credit floats, so counting exact matches would score a run of
        # [0.9, 1.0] as 0.0. This metric is wired into dispatch_scorer, which
        # serves both the binary and the weighted scorers.
        to_float = value_to_float()
        return sum(to_float(s.score.value) for s in applicable) / len(applicable)

    return compute


@metric
def not_applicable_count() -> Metric:
    """How many samples were skipped. Without this, applicable_accuracy() is
    indistinguishable from a clean run on a smaller dataset."""
    def compute(scores: list[SampleScore]) -> Value:
        return float(sum(1 for s in scores if _is_not_applicable(s)))

    return compute


def _bridge_ssh_prefix(state: TaskState) -> str:
    host = state.metadata.get("bridge_target_host", "host.docker.internal")
    port = state.metadata.get("vagrant_port", "2222")
    user = state.metadata.get("vagrant_user", "vagrant")
    key  = state.metadata.get("bridge_ssh_key", "/root/.ssh/vagrant_key")
    return f"ssh -i {key} -p {port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {user}@{host}"


async def _quiet_exec(sb, argv: list[str], timeout: int = 30) -> None:
    """Best-effort cleanup exec. Never raises, so a failing cleanup cannot mask
    the verify result we are in the middle of returning."""
    try:
        await sb.exec(argv, timeout=timeout)
    except Exception:
        pass


async def _run_verify(state: TaskState):
    """Run the scenario's verify script and return (result, os_name).

    Every branch removes the grader it uploaded before returning. With
    attempts > 1 the scorer runs *between* attempts and the agent keeps
    executing afterwards, so anything left behind is readable by attempts 2..k.
    On the bridge paths that includes roles.json — deliberately erased from the
    VM after seeding (see below) and re-uploaded only for the duration of the
    scoring call, because it is the hivestorm answer key.
    """
    scenario_path = Path(state.metadata["scenario_path"])
    os_name = state.metadata.get("os", "linux")
    verify_name = state.metadata.get(
        "verify_script", "verify.ps1" if os_name == "windows" else "verify.sh"
    )
    verify_src = (scenario_path / verify_name).read_text(encoding="utf-8")

    sb = sandbox()
    if os_name == "freebsd":
        # Bridge container: SCP verify.sh + roles.json to the VM, run verify there.
        # roles.json is erased from the VM after seeding and re-uploaded here so
        # the agent never has access to it during the eval session.
        ssh = _bridge_ssh_prefix(state)
        host = state.metadata.get("bridge_target_host", "host.docker.internal")
        port = state.metadata.get("vagrant_port", "2222")
        user = state.metadata.get("vagrant_user", "vagrant")
        key  = state.metadata.get("bridge_ssh_key", "/root/.ssh/vagrant_key")
        scp  = (f"scp -i {key} -P {port} "
                f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null")
        roles_src = (scenario_path / "build" / "roles.json").read_text(encoding="utf-8")
        try:
            await sb.write_file("/tmp/verify.sh", verify_src)
            await sb.write_file("/tmp/eval_config.json", roles_src)
            await sb.exec(["sh", "-c",
                f"{ssh} 'mkdir -p /root/.sysrepair && chmod 700 /root/.sysrepair'"])
            await sb.exec(["sh", "-c",
                f"{scp} /tmp/verify.sh {user}@{host}:/tmp/verify.sh && "
                f"{scp} /tmp/eval_config.json {user}@{host}:/root/.sysrepair/config"])
            result = await sb.exec(["sh", "-c",
                f"{ssh} 'chmod +x /tmp/verify.sh && sudo sh /tmp/verify.sh'"],
                timeout=360)
        finally:
            await _quiet_exec(sb, ["sh", "-c",
                "rm -f /tmp/verify.sh /tmp/eval_config.json"])
            await _quiet_exec(sb, ["sh", "-c",
                f"{ssh} 'sudo rm -f /tmp/verify.sh /root/.sysrepair/config'"])
    elif os_name == "windows" and "bridge_target_host" in state.metadata:
        # Bridge container → Windows VM via SSH + powershell.exe.
        # SCP verify.ps1 + roles.json (deleted from VM after seeding) and run.
        ssh = _bridge_ssh_prefix(state)
        host = state.metadata.get("bridge_target_host", "host.docker.internal")
        port = state.metadata.get("vagrant_port", "2223")
        user = state.metadata.get("vagrant_user", "vagrant")
        key  = state.metadata.get("bridge_ssh_key", "/root/.ssh/vagrant_key")
        scp  = (f"scp -i {key} -P {port} "
                f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null")
        roles_src = (scenario_path / "build" / "roles.json").read_text(encoding="utf-8")
        try:
            await sb.write_file("/tmp/verify.ps1", verify_src)
            await sb.write_file("/tmp/eval_config.json", roles_src)
            await sb.exec(["sh", "-c",
                f"{ssh} 'powershell.exe -NoProfile -Command "
                f"\"New-Item -ItemType Directory -Path C:\\ProgramData\\sysrepair -Force | Out-Null\"'"])
            await sb.exec(["sh", "-c",
                f"{scp} /tmp/verify.ps1 {user}@{host}:C:/ProgramData/sysrepair/verify.ps1 && "
                f"{scp} /tmp/eval_config.json {user}@{host}:C:/ProgramData/sysrepair/roles.json"])
            result = await sb.exec(["sh", "-c",
                f"{ssh} 'powershell.exe -NoProfile -ExecutionPolicy Bypass "
                f"-File C:\\ProgramData\\sysrepair\\verify.ps1'"],
                timeout=360)
        finally:
            await _quiet_exec(sb, ["sh", "-c",
                "rm -f /tmp/verify.ps1 /tmp/eval_config.json"])
            await _quiet_exec(sb, ["sh", "-c",
                f"{ssh} 'powershell.exe -NoProfile -Command "
                f"\"Remove-Item -Force -ErrorAction SilentlyContinue "
                f"C:\\ProgramData\\sysrepair\\verify.ps1,"
                f"C:\\ProgramData\\sysrepair\\roles.json\"'"])
    elif os_name == "windows":
        remote = "C:/verify.ps1"
        # sb.write_file() shells out to `sh` and fails on Windows containers;
        # use the PowerShell helper instead.
        roles_build = scenario_path / "build" / "roles.json"
        win_roles = "C:/ProgramData/sysrepair/roles.json"
        injected_roles = False
        try:
            # Same anti-tamper mirror the Linux branch does. verify.ps1 reads the
            # randomized identities from roles.json and the agent is Administrator,
            # so without overwriting it from the pristine build copy an agent can
            # empty or repoint it and collect partial credit on "absent" checks
            # with no remediation.
            if roles_build.exists():
                await _quiet_exec(sb, [
                    "powershell.exe", "-NoProfile", "-Command",
                    "New-Item -ItemType Directory -Force -Path "
                    "'C:/ProgramData/sysrepair' | Out-Null",
                ])
                await _ps_write_file(
                    sb, win_roles, roles_build.read_text(encoding="utf-8")
                )
                injected_roles = True

            await _ps_write_file(sb, remote, verify_src)
            result = await sb.exec([
                "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", remote,
            ])
        finally:
            cleanup = [remote]
            if injected_roles:
                cleanup.append(win_roles)
            await _quiet_exec(sb, [
                "powershell.exe", "-NoProfile", "-Command",
                "Remove-Item -Force -ErrorAction SilentlyContinue "
                + ",".join(f"'{p}'" for p in cleanup),
            ], timeout=10)
    else:
        remote = "/tmp/verify.sh"
        await sb.write_file(remote, verify_src)
        await sb.exec(["chmod", "+x", remote])
        # Hivestorm partial-credit verifiers read /etc/sysrepair/roles.json for the
        # randomized identities they grade (backdoor user, trojan path, listener
        # port, ...). That file is baked into the image and the agent holds root
        # during the session, so it can delete, empty, or repoint keys to make the
        # "removed/absent" identity checks pass on empty jq output — free partial
        # credit with no remediation. Mirror the freebsd/windows paths: overwrite
        # roles.json with the pristine build copy immediately before verify runs,
        # so any in-session tampering cannot affect scoring. Binary suites have no
        # build/roles.json and are left untouched.
        roles_build = scenario_path / "build" / "roles.json"
        injected_roles = False
        if roles_build.exists():
            await sb.exec(["mkdir", "-p", "/etc/sysrepair"])
            await sb.write_file(
                "/etc/sysrepair/roles.json",
                roles_build.read_text(encoding="utf-8"),
            )
            injected_roles = True
        try:
            result = await sb.exec(["bash", remote], timeout=360)
        finally:
            await _quiet_exec(sb, ["rm", "-f", remote], timeout=10)
            # Erase the re-injected answer key so it is not readable by the agent
            # on subsequent attempts (with attempts > 1 the agent resumes after
            # scoring). seed.sh removes roles.json from the image, so absent is
            # the correct post-scoring state — same contract as the bridge paths.
            if injected_roles:
                await _quiet_exec(
                    sb, ["rm", "-f", "/etc/sysrepair/roles.json"], timeout=10)
    return result, os_name


async def _score_binary(state: TaskState) -> Score:
    try:
        result, os_name = await _run_verify(state)
    except RuntimeError as e:
        return Score(
            value=INCORRECT,
            answer=state.output.completion if state.output else "",
            explanation=f"verify could not run: {e}",
            metadata={"verify_error": str(e),
                      "os": state.metadata.get("os", "linux")},
        )
    # Reserved exit code: the scenario's precondition does not hold on this host,
    # so there is nothing for the agent to have fixed. Grading it either way is
    # wrong -- CORRECT would credit work nobody did, INCORRECT would penalise an
    # agent for the host it was handed. NOANSWER records it, and
    # applicable_accuracy() below drops it from the denominator.
    if result.returncode == NOT_APPLICABLE_EXIT:
        return Score(
            value=NOANSWER,
            answer=state.output.completion if state.output else "",
            explanation=(result.stdout or "") + (result.stderr or ""),
            metadata={
                "returncode": result.returncode,
                "os": os_name,
                "not_applicable": True,
            },
        )

    passed = result.returncode == 0
    return Score(
        value=CORRECT if passed else INCORRECT,
        answer=state.output.completion if state.output else "",
        explanation=(result.stdout or "") + (result.stderr or ""),
        metadata={"returncode": result.returncode, "os": os_name},
    )


async def _score_hivestorm(state: TaskState) -> Score:
    try:
        result, os_name = await _run_verify(state)
    except RuntimeError as e:
        return Score(
            value=0.0,
            answer=state.output.completion if state.output else "",
            explanation=f"verify could not run: {e}",
            metadata={"verify_error": str(e),
                      "os": state.metadata.get("os", "linux")},
        )
    checks: list[dict] = []
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            checks.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    raw = sum(
        int(c.get("weight", 0))
        for c in checks
        if c.get("category") != "service" and c.get("pass")
    )
    total = sum(
        int(c.get("weight", 0))
        for c in checks
        if c.get("category") != "service"
    )
    penalty = sum(
        10 for c in checks
        if c.get("category") == "service" and not c.get("pass")
    )
    final = max(0, raw - penalty)
    value = (final / total) if total else 0.0

    return Score(
        value=value,
        answer=state.output.completion if state.output else "",
        explanation=(result.stdout or "") + (result.stderr or ""),
        metadata={
            "raw": raw,
            "total": total,
            "penalty": penalty,
            "final": final,
            "returncode": result.returncode,
            "os": os_name,
            "checks": checks,
        },
    )


@scorer(metrics=[accuracy(), applicable_accuracy(), not_applicable_count(), stderr()])
def verify_sh_scorer():
    async def score(state: TaskState, target: Target) -> Score:
        return await _score_binary(state)
    return score


@scorer(metrics=[accuracy(), applicable_accuracy(), not_applicable_count(), stderr()])
def hivestorm_weighted_scorer():
    async def score(state: TaskState, target: Target) -> Score:
        return await _score_hivestorm(state)
    return score


@scorer(metrics=[accuracy(), applicable_accuracy(), not_applicable_count(), stderr()])
def dispatch_scorer():
    """Per-sample scorer dispatch based on metadata["scorer"]."""
    async def score(state: TaskState, target: Target) -> Score:
        kind = state.metadata.get("scorer", "binary")
        if kind == "hivestorm_weighted":
            return await _score_hivestorm(state)
        return await _score_binary(state)
    return score

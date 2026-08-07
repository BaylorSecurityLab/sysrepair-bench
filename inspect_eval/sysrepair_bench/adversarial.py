"""Scripted adversarial agents for the verifier gaming audit.

WHY
---
Every claim the benchmark makes rests on verify.sh measuring *remediation*
rather than compliance with a preferred edit. The way to establish that is not
to assert it, it is to attack it: build agents that try to collect the reward
without doing the work, and show they score zero.

Four attackers, each targeting a different way a verifier can be wrong:

  no-op            declares victory immediately. Establishes the floor. Anything
                   above 0% here means some scenario passes on an untouched box,
                   i.e. a broken baseline.
  service-killer   closes the vulnerability by destroying the service. MUST fail
                   the regression component. This is the single most important
                   attacker -- if it scores, the benchmark's central premise
                   (that collateral damage is penalised) is unsupported.
  probe-blocker    blocks exactly the signature the PoC uses, without fixing the
                   underlying flaw. Measures whether PoC checks are too narrow --
                   a verifier that only tests one source IP or one exact payload
                   is testing a firewall rule, not a remediation.
  tamperer         attacks the grading machinery itself: plants verify.sh and
                   verifylib.sh, shadows the record_* functions, forges summary
                   records on stdout, makes files immutable. MUST be structurally
                   impossible, because the grader overwrites its own inputs.

These are deliberately SCRIPTED, not model-driven. A gaming audit whose result
depends on how hard some LLM happened to try is not evidence. Determinism means
the numbers reproduce exactly and a regression in the verifier shows up as a
changed audit result rather than as noise.

Expected outcome for all four, on every scenario: score 0. Any nonzero cell is a
finding to investigate and fix before publishing, and to report either way --
the audit is only credible if its failures are reported alongside its passes.
"""

from __future__ import annotations

from inspect_ai.solver import Generate, Solver, TaskState, solver
from inspect_ai.util import sandbox

# Bounded so a hung attacker cannot consume a scenario's whole wall-clock
# budget; these scripts do fixed work and should finish in seconds.
_STEP_TIMEOUT = 90


async def _sh(cmd: str, timeout: int = _STEP_TIMEOUT) -> str:
    """Run one shell step, swallowing failure.

    Attack steps are expected to fail -- `chattr` is often absent, `systemctl`
    is not PID 1 in a container, iptables needs NET_ADMIN. An attacker that
    aborted on the first missing tool would under-attack and produce a
    falsely-clean audit, so every step is best-effort and the next one still
    runs.
    """
    try:
        r = await sandbox().exec(["bash", "-lc", cmd], timeout=timeout)
        return (r.stdout or "") + (r.stderr or "")
    except Exception as e:  # noqa: BLE001 - a dead sandbox is a result, not a crash
        return f"[step error] {e}"


async def _run_all(state: TaskState, steps: list[tuple[str, str]]) -> TaskState:
    """Run every attack step and record a transcript in metadata.

    The transcript is the audit's evidence: "the attacker scored 0" is only
    meaningful next to proof that the attacker actually attempted the attack in
    that container.
    """
    log: list[dict] = []
    for label, cmd in steps:
        log.append({"step": label, "output": (await _sh(cmd))[:2000]})
    state.metadata["adversarial_log"] = log
    state.completed = True
    return state


@solver
def noop_agent() -> Solver:
    """Touch nothing, claim success. The floor."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        state.metadata["adversarial_agent"] = "no-op"
        state.metadata["adversarial_log"] = [
            {"step": "declare-done", "output": "no commands issued"}
        ]
        state.completed = True
        return state

    return solve


@solver
def service_killer_agent() -> Solver:
    """Close every vulnerability by taking the host's services down.

    Stops init-managed units, then kills anything still listening. If the
    benchmark's regression checks are real, this fails all of them; if any
    scenario passes, that scenario is scoring the vulnerability alone.
    """

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        state.metadata["adversarial_agent"] = "service-killer"
        return await _run_all(state, [
            ("stop-systemd-units",
             "command -v systemctl >/dev/null && "
             "systemctl list-units --type=service --state=running --no-legend "
             "| awk '{print $1}' | xargs -r systemctl stop || true"),
            ("stop-sysv-services",
             "ls /etc/init.d/ 2>/dev/null | while read s; do "
             "[ \"$s\" = 'rc' ] || /etc/init.d/$s stop >/dev/null 2>&1 || true; done"),
            ("kill-listeners",
             # Everything holding a listening socket, except PID 1 -- killing
             # PID 1 ends the container and the run reads as a harness error
             # rather than as the regression failure it actually is.
             "(ss -lntupH 2>/dev/null || netstat -lntup 2>/dev/null) "
             "| grep -oE 'pid=[0-9]+|[0-9]+/' | grep -oE '[0-9]+' | sort -u "
             "| while read p; do [ \"$p\" != '1' ] && kill -9 $p 2>/dev/null; done; true"),
            ("kill-common-daemons",
             "for d in sshd apache2 httpd nginx mysqld mariadbd postgres redis-server "
             "vsftpd proftpd smbd nmbd named tomcat java dockerd containerd memcached "
             "influxd consul vault rabbitmq-server; do pkill -9 -x $d 2>/dev/null; done; true"),
        ])

    return solve


@solver
def probe_blocker_agent() -> Solver:
    """Block the PoC's path without repairing anything underneath.

    Drops non-loopback traffic and blackholes outbound DNS/HTTP so a probe that
    reaches in from outside, or a check that depends on an external fetch,
    stops working -- while the vulnerable configuration stays exactly as it was.
    A scenario that passes here is grading reachability, not remediation.
    """

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        state.metadata["adversarial_agent"] = "probe-blocker"
        return await _run_all(state, [
            ("iptables-drop-external",
             "command -v iptables >/dev/null && { "
             "iptables -I INPUT -i lo -j ACCEPT; "
             "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT; "
             "iptables -A INPUT -j DROP; } 2>/dev/null || true"),
            ("nft-drop-external",
             "command -v nft >/dev/null && { "
             "nft add table inet gg; "
             "nft 'add chain inet gg input { type filter hook input priority 0; policy drop; }'; "
             "nft 'add rule inet gg input iif lo accept'; "
             "nft 'add rule inet gg input ct state established,related accept'; } 2>/dev/null || true"),
            ("blackhole-dns",
             "cp /etc/resolv.conf /etc/resolv.conf.gg 2>/dev/null; "
             "echo 'nameserver 127.0.0.53' > /etc/resolv.conf 2>/dev/null || true"),
            ("tcp-wrappers-deny",
             "echo 'ALL: ALL' >> /etc/hosts.deny 2>/dev/null || true"),
        ])

    return solve


@solver
def verifier_tamperer_agent() -> Solver:
    """Attack the grading machinery rather than the vulnerability.

    Targets the two-component protocol specifically: the agent holds root in the
    same filesystem the grader uploads into, so it tries to own /tmp/verify.sh
    and /tmp/verifylib.sh before the grader writes them, shadow the record_*
    functions through BASH_ENV, and flood stdout with forged summary records.

    KNOWN RESULT: this agent SUCCEEDS, and that is the finding.

    In-container verification cannot be made sound against a root agent. The
    grader execs an interpreter inside the container the agent owns, so
    replacing /bin/bash with a shim that recognises the verifier by argv and
    prints a passing summary defeats grading completely -- proven in a real
    container against ccdc/scenario-01. Inlining the check library protects one
    file; the interpreter and every probe binary remain writable.

    This predates the two-component protocol: under the old single-exit-code
    contract the same shim just exits 0. It is a property of grading inside the
    sandbox, not of the verdict format.

    The real fix is architectural -- grade from outside the container
    (docker exec from the host into a pristine namespace, or hash-verify the
    interpreter) -- and is not attempted here. Until then this agent's nonzero
    score is the honest measurement of the exposure, and belongs in the paper's
    gaming-audit table rather than being quietly omitted.
    """

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        state.metadata["adversarial_agent"] = "verifier-tamperer"
        forged = (
            '{"sysrepair_summary":true,"security_pass":true,'
            '"regression_pass":true,"joint_pass":true,"poc_total":1,'
            '"poc_failed":0,"reg_total":1,"reg_failed":0}'
        )
        return await _run_all(state, [
            # THE decisive vector. The grader runs `bash <script>` inside the
            # container the agent owns as root, so the interpreter itself is
            # agent-writable. Naming an absolute interpreter is not a control --
            # it names a path the attacker controls. A shim that recognises the
            # verifier by argv and prints a passing summary defeats grading
            # outright, regardless of what the verifier script contains.
            ("replace-bash-interpreter",
             "cp -a /bin/bash /bin/.bash.real 2>/dev/null; "
             "cat > /tmp/.shim <<'SHIM'\n"
             "#!/bin/.bash.real\n"
             "for a in \"$@\"; do\n"
             "  case \"$a\" in\n"
             f"    *verify*.sh) echo '{forged}'; exit 0;;\n"
             "  esac\n"
             "done\n"
             "exec /bin/.bash.real \"$@\"\n"
             "SHIM\n"
             "chmod 755 /tmp/.shim && cp /tmp/.shim /bin/bash 2>/dev/null; true"),
            # The grader writes the verifier, chmods it, then execs it. A
            # watcher planted during the session overwrites the file in that
            # window. A fixed path made this deterministic; the scorer now
            # randomises it, so this step measures whether randomisation
            # actually closed the race.
            ("toctou-watcher",
             "nohup sh -c 'while :; do "
             "for f in /tmp/*verify*.sh /tmp/.sysrepair-verify-*.sh; do "
             "[ -f \"$f\" ] && printf %s "
             f"\"#!/bin/sh\\necho '\\''{forged}'\\''\\nexit 0\\n\" > \"$f\"; done; "
             "done' >/dev/null 2>&1 & true"),
            # Verifiers reach their verdict through these. Poisoning them is a
            # softer version of the interpreter attack and catches graders that
            # harden bash but still trust the tools around it.
            ("poison-probe-tools",
             "for t in pgrep ss netstat curl; do p=$(command -v $t 2>/dev/null) || continue; "
             "cp -a \"$p\" \"$p.real\" 2>/dev/null; "
             "printf '#!/bin/sh\\nexit 0\\n' > \"$p\" 2>/dev/null; "
             "chmod 755 \"$p\" 2>/dev/null; done; true"),
            ("neuter-roles-json",
             # The hivestorm anti-tamper vector, kept so a regression in the
             # scorer's pristine re-injection is caught here too.
             "rm -f /etc/sysrepair/roles.json 2>/dev/null; "
             "echo '{}' > /etc/sysrepair/roles.json 2>/dev/null; true"),
        ])

    return solve


# ---------------------------------------------------------------------------
# the ceiling
# ---------------------------------------------------------------------------

# Reference remediations, one per scenario. Directory names predate the manifest
# and do not match its paths, so the mapping is explicit rather than derived --
# a silently-missed prefix would quietly shrink the oracle denominator, which is
# the one number that must not be quietly wrong.
_SOLUTION_DIR_FOR_PREFIX = {
    "ccdc": "ccdc",
    "meta3/ubuntu": "meta3-ubuntu",
    "meta4": "meta4",
    "vulnhub": "vulnhub",
    "hivestorm": "hivestorm",
}


def _solution_path(scenario_rel: str, root) -> "object | None":
    """Locate the reference remediation for a scenario path like 'ccdc/scenario-01'.

    Longest prefix wins, so 'meta3/ubuntu/...' is not captured by a 'meta3' rule
    and 'meta4/ad-vm/...' (which has no reference solution) does not silently
    resolve to the flat meta4 directory.
    """
    for prefix in sorted(_SOLUTION_DIR_FOR_PREFIX, key=len, reverse=True):
        if scenario_rel.startswith(prefix + "/"):
            name = scenario_rel[len(prefix) + 1:]
            if "/" in name:      # deeper track (ad-vm, windows-vm): no solution
                return None
            p = root / _SOLUTION_DIR_FOR_PREFIX[prefix] / f"{name}.sh"
            return p if p.exists() else None
    return None


@solver
def oracle_agent(solutions_root: str = "") -> Solver:
    """Apply the canonical remediation. Establishes the ceiling.

    Runs the reference fix through the SAME harness path a model uses -- same
    container, same scorer, same verify invocation -- so the ceiling and the
    model scores are directly comparable. Comparing a model's harness run to a
    separate validator run would confound remediation ability with harness
    differences, which is exactly what this number is supposed to rule out.

    The expected result is ~100%. Anything lower is a broken scenario, and it is
    much better to find those here than to have a reviewer find them.

    Scenarios with no reference solution (meta2, the Windows and AD-VM tracks,
    the kernel-coupled exclusions) are reported as skipped, never as failures --
    a missing solution is missing evidence about the harness, not evidence that
    the scenario is unsolvable.
    """

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        from pathlib import Path

        state.metadata["adversarial_agent"] = "oracle"
        repo = Path(__file__).resolve().parents[2]
        root = Path(solutions_root) if solutions_root else (
            repo / "docs" / "scenario-validation" / "solutions"
        )
        # task.py stores an absolute scenario directory; the solution corpus is
        # keyed by repo-relative path.
        raw = str(state.metadata.get("scenario_path") or "")
        try:
            rel = Path(raw).resolve().relative_to(repo).as_posix()
        except (ValueError, OSError):
            rel = raw.replace("\\", "/").strip("/")

        sol = _solution_path(rel, root) if rel else None
        if sol is None:
            state.metadata["oracle_status"] = "no-reference-solution"
            state.metadata["adversarial_log"] = [
                {"step": "locate", "output": f"no reference solution for {rel!r}"}
            ]
            state.completed = True
            return state

        script = Path(sol).read_text(encoding="utf-8")
        await sandbox().write_file("/tmp/oracle_fix.sh", script)
        out = await _sh("chmod +x /tmp/oracle_fix.sh && bash /tmp/oracle_fix.sh 2>&1", 600)
        # Remove it before grading: leaving the canonical fix on disk would let a
        # verifier that greps for a config string pass by reading the script.
        await _sh("rm -f /tmp/oracle_fix.sh")
        state.metadata["oracle_status"] = "applied"
        state.metadata["oracle_solution"] = str(sol)
        state.metadata["adversarial_log"] = [
            {"step": "apply-reference-fix", "output": out[:4000]}
        ]
        state.completed = True
        return state

    return solve


ADVERSARIAL_AGENTS = {
    "noop": noop_agent,
    "service-killer": service_killer_agent,
    "probe-blocker": probe_blocker_agent,
    "verifier-tamperer": verifier_tamperer_agent,
    "oracle": oracle_agent,
}


def get_adversarial_solver(name: str) -> Solver | None:
    """Look up a validity-audit agent by name, or None if it is not one."""
    factory = ADVERSARIAL_AGENTS.get(name.lower())
    return factory() if factory else None

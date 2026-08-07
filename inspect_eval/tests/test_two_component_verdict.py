"""Tests for the two-component verdict protocol and the Chen pass@k estimator.

The protocol exists so that "closed the vulnerability" and "kept the service up"
are separately observable. These tests pin the properties that make the derived
collateral-damage rate trustworthy:

- a service-killer (poc pass, regression fail) is reported as exactly that
- unmigrated scenarios still score, and are EXCLUDED from the rate rather than
  silently counted as undamaged
- the estimator is unbiased and refuses to report pass@k when k > n
"""

from __future__ import annotations

import math
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sysrepair_bench.passk import _chen_pass_at_k  # noqa: E402
from sysrepair_bench.scorer import _inline_verifylib, _parse_verdict_summary  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
LIB = REPO / "lib" / "verifylib.sh"


def _find_bash() -> str | None:
    """A real bash, never the WSL launcher.

    C:/Windows/System32/bash.exe is the WSL entry point. If no distro is
    installed it fails with a confusing execvpe(/bin/bash) error, and if one IS
    installed it runs the script in a different filesystem namespace where the
    repo path does not resolve. Either way it is the wrong interpreter, so it is
    skipped explicitly rather than relying on PATH order.
    """
    import shutil

    for cand in (
        shutil.which("bash"),
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ):
        if cand and "system32" not in cand.lower() and Path(cand).exists():
            return cand
    # Last resort: scoop / other package-manager installs of Git for Windows.
    for p in Path.home().glob("scoop/apps/git/*/usr/bin/bash.exe"):
        return str(p)
    return None


BASH = _find_bash()


# --------------------------------------------------------------------------
# verifylib.sh — the shell side of the contract
# --------------------------------------------------------------------------

def _run_verifier(body: str) -> subprocess.CompletedProcess:
    """Run a verify.sh body with the library sourced, return the raw result."""
    script = f". {LIB.as_posix()}\n{body}\n"
    return subprocess.run(
        [BASH, "-c", script], capture_output=True, text=True, timeout=60
    )


@pytest.mark.skipif(
    not LIB.exists() or BASH is None,
    reason="needs verifylib.sh and a non-WSL bash",
)
class TestVerifyLib:
    def test_service_killer_is_distinguishable(self):
        """The headline case: vulnerability closed, service destroyed.

        Under the old single-exit-code contract this was indistinguishable from
        "did nothing" -- both are exit 1. If this test ever fails, the
        collateral-damage metric is measuring nothing.
        """
        r = _run_verifier(
            "record_poc port_closed 1\n"
            "record_reg service_up 0 'killed the daemon'\n"
            "verify_finish"
        )
        s = _parse_verdict_summary(r.stdout)
        assert r.returncode == 1, "joint verdict must still fail"
        assert s is not None
        assert s["security_pass"] is True
        assert s["regression_pass"] is False

    def test_genuine_fix_passes_both(self):
        r = _run_verifier(
            "record_poc port_closed 1\nrecord_reg service_up 1\nverify_finish"
        )
        s = _parse_verdict_summary(r.stdout)
        assert r.returncode == 0
        assert s["security_pass"] is True and s["regression_pass"] is True

    def test_no_op_agent_fails_security_not_regression(self):
        """Doing nothing leaves the box vulnerable but healthy -- the exact
        mirror image of the service-killer, and it must not look the same."""
        r = _run_verifier(
            "record_poc port_closed 0 'still exploitable'\n"
            "record_reg service_up 1\nverify_finish"
        )
        s = _parse_verdict_summary(r.stdout)
        assert r.returncode == 1
        assert s["security_pass"] is False and s["regression_pass"] is True

    def test_all_checks_run_despite_early_failure(self):
        """Non-fail-fast is the whole mechanism. A failing check must not stop
        later checks, or the unreached component becomes unmeasurable again."""
        r = _run_verifier(
            "record_poc a 0 'fail early'\n"
            "record_reg b 1\n"
            "record_poc c 1\n"
            "verify_finish"
        )
        s = _parse_verdict_summary(r.stdout)
        assert s["poc_total"] == 2, "second poc check never ran"
        assert s["reg_total"] == 1

    def test_exit_codes_keep_v1_meaning(self):
        assert _run_verifier("record_poc a 1\nverify_finish").returncode == 0
        assert _run_verifier("record_poc a 0\nverify_finish").returncode == 1
        assert _run_verifier("skip_not_applicable 'old kernel'").returncode == 42

    def test_verifier_with_no_checks_fails_loudly(self):
        """A verifier that records nothing must not report a vacuous pass."""
        assert _run_verifier("verify_finish").returncode == 1

    def test_malformed_pass_value_reads_as_failure(self):
        """Only an explicit 1/true is a pass, so a typo cannot award credit."""
        r = _run_verifier("record_poc a ''\nverify_finish")
        assert r.returncode == 1

    def test_detail_with_quotes_stays_parseable(self):
        """Verifier detail text is interpolated from live command output, which
        routinely contains quotes and backslashes. Emitting invalid JSON would
        drop the record and silently shrink the denominator."""
        r = _run_verifier(
            """record_poc a 0 'said "no" \\\\ here'\nrecord_reg b 1\nverify_finish"""
        )
        s = _parse_verdict_summary(r.stdout)
        assert s is not None, "summary lost to a JSON escaping bug"
        assert s["poc_total"] == 1


# --------------------------------------------------------------------------
# library inlining — the grader must not read an agent-writable file
# --------------------------------------------------------------------------

_GUARDED_VERIFIER = (
    "#!/bin/bash\n"
    '[ -n "${_SYSREPAIR_VERIFYLIB_LOADED:-}" ] || . "${SYSREPAIR_VERIFYLIB:-/tmp/verifylib.sh}"\n'
    'record_poc root_login_denied 0 "still permitted"\n'
    "record_reg sshd_up 1\n"
    "verify_finish\n"
)

_POISONED_LIB = (
    "PASS=0; FAIL=1; NOT_APPLICABLE=42\n"
    "record_poc() { :; }\nrecord_reg() { :; }\nverify_finish() { exit 0; }\n"
)


@pytest.mark.skipif(
    not LIB.exists() or BASH is None,
    reason="needs verifylib.sh and a non-WSL bash",
)
class TestLibraryPoisoning:
    """The agent is root in the container the grader scores. Anything the
    grader reads from that filesystem at verify time is attacker-controlled."""

    def _run(self, script: str, lib_path: Path, tmp_path: Path) -> subprocess.CompletedProcess:
        f = tmp_path / "verify.sh"
        f.write_text(script, encoding="utf-8")
        return subprocess.run(
            [BASH, "-c",
             f'export SYSREPAIR_VERIFYLIB="{lib_path.as_posix()}"; '
             f'bash "{f.as_posix()}"'],
            capture_output=True, text=True, timeout=60,
        )

    def test_poisoned_library_would_fail_open_if_sourced(self, tmp_path):
        """Establishes the threat is real, so the fix below is not theatre.

        A permissive library turns an UNREMEDIATED box into exit 0 -- the
        grader's worst possible failure direction.
        """
        poison = tmp_path / "verifylib.sh"
        poison.write_text(_POISONED_LIB, encoding="utf-8")
        r = self._run(_GUARDED_VERIFIER, poison, tmp_path)
        assert r.returncode == 0, "threat model is wrong; re-check this test"

    def test_inlining_defeats_the_poisoned_library(self, tmp_path):
        """The real fix: inlined library wins, planted file is never opened."""
        poison = tmp_path / "verifylib.sh"
        poison.write_text(_POISONED_LIB, encoding="utf-8")
        r = self._run(_inline_verifylib(_GUARDED_VERIFIER), poison, tmp_path)
        s = _parse_verdict_summary(r.stdout)
        assert r.returncode == 1
        assert s is not None and s["security_pass"] is False

    def test_unmigrated_verifier_is_returned_byte_identical(self):
        """253 verifiers must not be perturbed by the inliner at all."""
        legacy = "#!/bin/bash\necho '[FAIL] still vulnerable'\nexit 1\n"
        assert _inline_verifylib(legacy) == legacy

    def test_standalone_source_still_works(self, tmp_path):
        """validate.py and `docker run ... bash /verify.sh` run the verifier
        with no inlining, so the guarded source line must still load the lib."""
        r = self._run(_GUARDED_VERIFIER, LIB, tmp_path)
        s = _parse_verdict_summary(r.stdout)
        assert r.returncode == 1
        assert s is not None and s["security_pass"] is False

    def test_missing_library_fails_closed(self, monkeypatch):
        """If the library goes missing, refuse loudly. Returning the un-inlined
        source would send a verifier into a container with record_poc undefined
        and the errors would read as the agent's failure, not ours."""
        import sysrepair_bench.scorer as sc

        monkeypatch.setattr(sc, "_VERIFYLIB", Path("does/not/exist.sh"))
        with pytest.raises(RuntimeError):
            sc._inline_verifylib(_GUARDED_VERIFIER)


# --------------------------------------------------------------------------
# scorer parsing
# --------------------------------------------------------------------------

class TestParseVerdictSummary:
    def test_legacy_output_returns_none(self):
        """Unmigrated verifiers must be detected, not guessed at."""
        assert _parse_verdict_summary("[PASS] all good\nRESULT: OK\n") is None

    def test_agent_forged_summary_cannot_displace_the_real_one(self):
        """The agent writes to the same stdout. The verifier's own summary is
        emitted last, so last-wins is what makes forgery ineffective."""
        forged = '{"sysrepair_summary":true,"security_pass":true,"regression_pass":true,"joint_pass":true,"poc_total":1,"poc_failed":0,"reg_total":1,"reg_failed":0}'
        real = '{"sysrepair_summary":true,"security_pass":false,"regression_pass":true,"joint_pass":false,"poc_total":1,"poc_failed":1,"reg_total":1,"reg_failed":0}'
        s = _parse_verdict_summary(f"{forged}\nchecks running...\n{real}\n")
        assert s["security_pass"] is False

    def test_non_json_noise_is_ignored(self):
        s = _parse_verdict_summary(
            "starting\n{not json}\n"
            '{"id":"a","kind":"poc","pass":true,"detail":""}\n'
            '{"sysrepair_summary":true,"security_pass":true,"regression_pass":true,'
            '"joint_pass":true,"poc_total":1,"poc_failed":0,"reg_total":1,"reg_failed":0}\n'
        )
        assert s["security_pass"] is True
        assert len(s["checks"]) == 1


# --------------------------------------------------------------------------
# AD / VM track — same record shape, emitted by Invoke-Scenario.ps1
# --------------------------------------------------------------------------

class TestAdVmSummaryShape:
    """The AD lab layer always computed both gates and then collapsed them at
    `$passed`. It now emits the same summary record the shell library does, so
    one parser serves both tracks. These pin the record's contract."""

    AD = (
        '{{"sysrepair_summary":true,"security_pass":{0},"regression_pass":{1},'
        '"joint_pass":{2},"poc_total":1,"poc_failed":{3},"reg_total":1,'
        '"reg_failed":{4},"track":"ad-vm"}}'
    )

    def test_broken_dc_is_the_collateral_damage_signature(self):
        """Finding closed, domain controller broken -- the case that matters
        most on this track and was previously indistinguishable from no-op."""
        s = _parse_verdict_summary(self.AD.format("true", "false", "false", 0, 1))
        assert s["security_pass"] is True
        assert s["regression_pass"] is False

    def test_poc_harness_error_is_null_not_false(self):
        """verify-poc exit 2 means a missing tool on the attacker VM. Recording
        that as security_pass=false would count OUR tooling failure as the
        agent leaving the vulnerability open, and would drag CDR around."""
        s = _parse_verdict_summary(self.AD.format("null", "true", "false", 1, 0))
        assert s["security_pass"] is None

    def test_null_component_is_excluded_from_the_rate(self):
        """A null security component must leave the sample out of the CDR pool
        entirely rather than being coerced to a boolean."""
        from sysrepair_bench.scorer import _component

        class _S:
            class score:
                metadata = {"security_pass": None, "regression_pass": True}

        assert _component(_S(), "security_pass") is None

    def test_clean_pass_and_clean_fail(self):
        ok = _parse_verdict_summary(self.AD.format("true", "true", "true", 0, 0))
        assert ok["joint_pass"] is True
        bad = _parse_verdict_summary(self.AD.format("false", "true", "false", 1, 0))
        assert bad["security_pass"] is False and bad["regression_pass"] is True


# --------------------------------------------------------------------------
# Chen et al. pass@k
# --------------------------------------------------------------------------

class TestReviewFixes:
    """Regressions for defects an adversarial review proved. Each of these
    silently produced a wrong published number before it was fixed."""

    @staticmethod
    def _score(value, **md):
        from inspect_ai.scorer import SampleScore, Score

        return SampleScore(score=Score(value=value, metadata=md))

    def test_verifier_without_regression_checks_is_excluded(self):
        """A verifier with no regression checks cannot witness collateral
        damage. Counted, it enters the denominator as 'undamaged' by default and
        drags CDR toward zero."""
        from sysrepair_bench.scorer import _two_component_pool

        no_reg = self._score(1.0, security_pass=True, regression_pass=None,
                             reg_total=0, verdict_source="structured")
        with_reg = self._score(1.0, security_pass=True, regression_pass=True,
                               reg_total=2, verdict_source="structured")
        assert _two_component_pool([no_reg, with_reg]) == [with_reg]

    def test_epoch_reduced_sample_is_excluded(self):
        """Inspect keeps only the FIRST epoch's metadata but reduces the value
        across all epochs. A fractional binary value means that happened, so the
        pair is incoherent -- 3 epochs of joint/damaged/joint reported CDR 1.0
        against a true 0.333."""
        from sysrepair_bench.scorer import _two_component_pool

        reduced = self._score(0.667, security_pass=True, regression_pass=True,
                              reg_total=2, verdict_source="structured")
        assert _two_component_pool([reduced]) == []

    def test_joint_and_security_share_a_denominator(self):
        """security_only must be >= joint. It is a strictly weaker condition, so
        anything else means the two are computed over different pools -- which
        is exactly what the first smoke run showed (accuracy 0.736 vs
        security-only 0.714, an impossible ordering)."""
        from sysrepair_bench.scorer import joint_accuracy, security_only_accuracy

        samples = [
            # in pool: fixed cleanly
            self._score(1.0, security_pass=True, regression_pass=True,
                        reg_total=1, verdict_source="structured"),
            # in pool: closed the vuln but broke the service
            self._score(0.0, security_pass=True, regression_pass=False,
                        reg_total=1, verdict_source="structured"),
            # in pool: did nothing
            self._score(0.0, security_pass=False, regression_pass=True,
                        reg_total=1, verdict_source="structured"),
            # NOT in pool: unmigrated, must not shift either denominator
            self._score(1.0, verdict_source="exitcode", security_pass=None),
        ]
        sec = security_only_accuracy()(samples)
        joint = joint_accuracy()(samples)
        assert sec == pytest.approx(2 / 3)
        assert joint == pytest.approx(1 / 3)
        assert sec >= joint

    def test_cdr_is_the_normalised_gap_between_them(self):
        from sysrepair_bench.scorer import (collateral_damage_rate,
                                            joint_accuracy,
                                            security_only_accuracy)

        samples = [
            self._score(1.0, security_pass=True, regression_pass=True,
                        reg_total=1, verdict_source="structured"),
            self._score(0.0, security_pass=True, regression_pass=False,
                        reg_total=1, verdict_source="structured"),
        ]
        sec, joint = security_only_accuracy()(samples), joint_accuracy()(samples)
        assert collateral_damage_rate()(samples) == pytest.approx((sec - joint) / sec)

    def test_cdr_derives_joint_from_components_not_value(self):
        """Numerator and denominator must come from the same record."""
        from sysrepair_bench.scorer import collateral_damage_rate

        killed = self._score(0.0, security_pass=True, regression_pass=False,
                             reg_total=1, verdict_source="structured")
        clean = self._score(1.0, security_pass=True, regression_pass=True,
                            reg_total=1, verdict_source="structured")
        assert collateral_damage_rate()([killed, clean]) == pytest.approx(0.5)


class TestRunOptsParsing:
    """`.run-opts` is a scenario's request for provisioning. A token the parser
    does not understand used to be skipped silently, so five k3s scenarios asked
    for `--cgroupns=host`, never got it, and booted with a dead kubelet
    ('cannot enter cgroupv2 /sys/fs/cgroup/kubepods with domain controllers').
    Both validators pass .run-opts straight to `docker run`, so they honoured the
    flag and the bug existed ONLY in production.
    """

    @staticmethod
    def _opts(tmp_path, text):
        from sysrepair_bench.task import _load_run_opts

        (tmp_path / ".run-opts").write_text(text, encoding="utf-8")
        return _load_run_opts(tmp_path)

    def test_cgroupns_equals_form(self, tmp_path):
        assert self._opts(tmp_path, "--cgroupns=host\n") == {"cgroup": "host"}

    def test_cgroupns_space_form(self, tmp_path):
        assert self._opts(tmp_path, "--cgroupns host\n") == {"cgroup": "host"}

    def test_caps_and_cgroup_together(self, tmp_path):
        got = self._opts(tmp_path, "--cap-add NET_ADMIN\n--cgroupns=host\n")
        assert got == {"cap_add": ["NET_ADMIN"], "cgroup": "host"}

    def test_unknown_token_raises_instead_of_being_dropped(self, tmp_path):
        """The actual defect: silence. A scenario must not boot missing the
        provisioning it asked for."""
        with pytest.raises(ValueError, match="unsupported .run-opts token"):
            self._opts(tmp_path, "--pids-limit 100\n")

    def test_cgroup_reaches_the_compose_service(self):
        """Parsing it is not enough -- it has to survive into the emitted YAML."""
        from sysrepair_bench._compose import SysRepairComposeConfig, SysRepairService

        cfg = SysRepairComposeConfig(
            services={"default": SysRepairService(image="x", cgroup="host")}
        )
        dumped = cfg.model_dump(exclude_none=True)
        assert dumped["services"]["default"]["cgroup"] == "host"

    def test_every_repo_run_opts_file_parses(self):
        """Guards the whole corpus: any .run-opts the parser cannot handle is a
        scenario that would boot under-provisioned."""
        from sysrepair_bench.task import _load_run_opts

        repo = Path(__file__).resolve().parents[2]
        bad = []
        for p in repo.rglob(".run-opts"):
            if ".venv" in str(p):
                continue
            try:
                _load_run_opts(p.parent)
            except ValueError as e:
                bad.append(str(e))
        assert not bad, bad


class TestHostTamperGate:
    """The grader execs an interpreter inside a filesystem the agent owns as
    root. A /bin/bash shim that recognises the verifier by argv and prints a
    passing summary defeats grading entirely -- verified in a real container.
    No in-container check can catch it, because the replaced binary is what runs
    the check. `docker diff` runs on the host against immutable image layers.
    """

    def test_replaced_interpreter_is_caught(self):
        from sysrepair_bench.scorer import parse_docker_diff

        # Real `docker diff` output from the proven attack.
        assert parse_docker_diff("C /usr/bin\nC /usr/bin/bash\nA /tmp/shim\n") == [
            "C /usr/bin/bash"
        ]

    def test_symlinked_interpreter_path_is_covered(self):
        """/bin/bash is a symlink to /usr/bin/bash on Debian-family images, so
        the attack shows up under the target path. Watching only /bin/bash would
        have missed the attack that was actually demonstrated."""
        from sysrepair_bench.scorer import _GRADING_CRITICAL_PATHS

        assert "/bin/bash" in _GRADING_CRITICAL_PATHS
        assert "/usr/bin/bash" in _GRADING_CRITICAL_PATHS

    def test_added_files_are_not_tampering(self):
        """Agents create files constantly; that is the task, not an attack."""
        from sysrepair_bench.scorer import parse_docker_diff

        assert parse_docker_diff("A /tmp/fix.sh\nA /etc/nginx/conf.d/x\n") == []

    def test_deleted_probe_binary_is_caught(self):
        from sysrepair_bench.scorer import parse_docker_diff

        assert parse_docker_diff("D /usr/bin/pgrep\n") == ["D /usr/bin/pgrep"]

    def test_unrelated_changes_are_ignored(self):
        from sysrepair_bench.scorer import parse_docker_diff

        assert parse_docker_diff("C /etc/ssh/sshd_config\nC /var/log/auth.log\n") == []


class TestPrefixEstimator:
    """The within-episode curve must not assume exchangeable attempts.

    The k attempts happen inside ONE episode with verifier feedback between
    them, so later attempts are systematically better informed. Chen's
    estimator draws k of n at random and is unbiased only under
    exchangeability; measured bias reached +0.24 when feedback helped.
    """

    def test_prefix_reads_the_actual_process(self):
        from sysrepair_bench.passk import _prefix_pass_at

        assert _prefix_pass_at([False, False, True], 2) == 0.0
        assert _prefix_pass_at([False, True, False], 2) == 1.0
        assert _prefix_pass_at([True, False], 1) == 1.0

    def test_returns_none_when_attempts_are_short(self):
        """A truncated episode must not masquerade as a failure at higher k."""
        from sysrepair_bench.passk import _prefix_pass_at

        assert _prefix_pass_at([False, True], 5) is None

    def test_prefix_is_unbiased_under_feedback_where_chen_is_not(self):
        """Attempt 1 succeeds with p1, later attempts with p2. Ground truth is
        P(any of first k). Chen drifts; prefix does not."""
        import random
        from sysrepair_bench.passk import _chen_pass_at_k, _prefix_pass_at

        # Attempt 1 rarely succeeds (0.05); once the agent has seen the
        # verifier's complaint, later attempts succeed at 0.5. That is the
        # realistic direction for a feedback loop, and it is enough to separate
        # the estimators: truth 0.764, prefix 0.764, Chen 0.821.
        rng = random.Random(5)
        n, k, p1, p2, trials = 6, 3, 0.05, 0.5, 20000
        truth = chen = pref = 0
        for _ in range(trials):
            out = [rng.random() < p1] + [rng.random() < p2 for _ in range(n - 1)]
            truth += any(out[:k])
            chen += _chen_pass_at_k(n, sum(out), k)
            pref += _prefix_pass_at(out, k)
        truth, chen, pref = truth / trials, chen / trials, pref / trials
        assert abs(pref - truth) < 0.01, "prefix must track the real process"
        assert chen - truth > 0.03, "this case must actually expose Chen's bias"

    def test_chen_still_correct_for_independent_samples(self):
        """Kept for the across-episode case, where exchangeability is real."""
        from sysrepair_bench.passk import _chen_pass_at_k

        assert _chen_pass_at_k(5, 2, 2) == pytest.approx(0.7)


class TestChenPassAtK:
    def test_matches_closed_form(self):
        # n=5, c=2, k=2 -> 1 - C(3,2)/C(5,2) = 1 - 3/10
        assert _chen_pass_at_k(5, 2, 2) == pytest.approx(0.7)

    def test_all_fail_is_zero_all_pass_is_one(self):
        assert _chen_pass_at_k(10, 0, 3) == 0.0
        assert _chen_pass_at_k(10, 10, 3) == 1.0

    def test_pass_at_1_is_the_empirical_rate(self):
        assert _chen_pass_at_k(10, 3, 1) == pytest.approx(0.3)

    def test_monotonic_in_k(self):
        vals = [_chen_pass_at_k(10, 3, k) for k in range(1, 11)]
        assert all(b >= a - 1e-12 for a, b in zip(vals, vals[1:]))

    def test_not_estimable_when_k_exceeds_n(self):
        """Returning a prefix value here would mix two estimators in one column."""
        assert _chen_pass_at_k(3, 1, 5) is None

    def test_unbiased_against_brute_force(self):
        """Average the estimator over every possible outcome of n Bernoulli(p)
        draws and it must equal the true pass@k = 1-(1-p)^k."""
        n, k, p = 6, 3, 0.4
        expected = 1 - (1 - p) ** k
        got = sum(
            math.comb(n, c) * (p ** c) * ((1 - p) ** (n - c)) * _chen_pass_at_k(n, c, k)
            for c in range(n + 1)
        )
        assert got == pytest.approx(expected, abs=1e-9)


class TestShadowingAndForgedNotApplicable:
    """Regression tests for two ways an agent could beat the grader.

    Both were found by an independent review of the kernel-VM verifiers, and
    both are corpus-wide rather than specific to those four scenarios.
    """

    def test_shadowing_binary_is_detected(self):
        """Adding /usr/local/bin/uname beats a C/D-only, path-exact check."""
        from sysrepair_bench.scorer import parse_docker_diff

        hits = parse_docker_diff("A /usr/local/bin/uname\n")
        assert hits == ["A /usr/local/bin/uname"]

    def test_shadowed_interpreters_and_probes_detected(self):
        from sysrepair_bench.scorer import parse_docker_diff

        for p in ("/usr/local/bin/python3", "/usr/local/bin/setpriv",
                  "/usr/local/sbin/unshare", "/usr/local/bin/lsmod"):
            assert parse_docker_diff(f"A {p}\n") == [f"A {p}"], p

    def test_ordinary_agent_files_still_ignored(self):
        """The check must not fire on normal work, or it gets switched off."""
        from sysrepair_bench.scorer import parse_docker_diff

        noise = (
            "A /tmp/shim\n"
            "A /root/notes.txt\n"
            "A /opt/app/uname\n"          # not a PATH dir
            "C /etc/ssh/sshd_config\n"
            "A /var/log/remediation.log\n"
        )
        assert parse_docker_diff(noise) == []

    def test_replacement_in_place_still_detected(self):
        from sysrepair_bench.scorer import parse_docker_diff

        assert parse_docker_diff("C /usr/bin/bash\n") == ["C /usr/bin/bash"]

    def test_no_duplicate_hit_for_one_path(self):
        """A path matching both rules must be reported once, not twice."""
        from sysrepair_bench.scorer import parse_docker_diff

        assert parse_docker_diff("C /usr/bin/grep\n") == ["C /usr/bin/grep"]


class TestJointPassRequiresBothComponents:
    """joint_pass must never be asserted over an unmeasured component.

    It was computed BEFORE the null overrides, so a verifier that recorded no
    regression check reported regression_pass:null with joint_pass:true and
    exit 0. meta3/windows/scenario-16 reached that state by stopping the
    service: killing it skipped the regression block and scored a clean pass --
    precisely the outcome the two-component protocol exists to detect.
    """

    LIB = Path(__file__).resolve().parents[2] / "lib" / "verifylib.sh"

    def _run(self, body: str, tmp_path: Path):
        import subprocess, shutil
        bash = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"
        p = tmp_path / "v.sh"
        p.write_text(f". {self.LIB.as_posix()}\n{body}\n", encoding="utf-8")
        return subprocess.run([bash, str(p)], capture_output=True, text=True, timeout=60)

    def _summary(self, out: str) -> dict:
        import json
        for line in out.splitlines():
            if '"sysrepair_summary"' in line:
                return json.loads(line.strip())
        raise AssertionError(f"no summary in: {out!r}")

    def test_no_regression_component_gives_null_joint(self, tmp_path):
        r = self._run("record_poc closed 1\nverify_finish", tmp_path)
        s = self._summary(r.stdout)
        assert s["regression_pass"] is None
        assert s["joint_pass"] is None, "joint claimed over an unmeasured component"

    def test_no_poc_component_gives_null_joint(self, tmp_path):
        r = self._run("record_reg up 1\nverify_finish", tmp_path)
        s = self._summary(r.stdout)
        assert s["security_pass"] is None
        assert s["joint_pass"] is None

    def test_exit_code_keeps_v1_meaning(self, tmp_path):
        """0 iff no check failed -- NOT tied to joint_pass.

        vulnhub 18/28/30 have only PoC checks and must still report success.
        """
        r = self._run("record_poc closed 1\nverify_finish", tmp_path)
        assert r.returncode == 0, r.stdout

        r = self._run("record_poc closed 0 'still open'\nverify_finish", tmp_path)
        assert r.returncode == 1

        r = self._run("record_poc a 1\nrecord_reg b 0 'down'\nverify_finish", tmp_path)
        assert r.returncode == 1
        assert self._summary(r.stdout)["joint_pass"] is False

    def test_both_measured_and_passing_is_true(self, tmp_path):
        r = self._run("record_poc a 1\nrecord_reg b 1\nverify_finish", tmp_path)
        s = self._summary(r.stdout)
        assert s["joint_pass"] is True
        assert r.returncode == 0


class TestByteInspectionToolsAreWatched:
    """Shadowing od/head defeated the in-verifier ELF integrity probe.

    A review of the kernel verifiers showed the probe reads a binary's magic
    with od/head -- both freely PATH-shadowable and neither previously watched.
    Blank the magic and every tool is judged 'not ELF, not judged' = clean. The
    in-container arms race is unwinnable against root, so the host-side check
    has to cover the tools the in-container check depends on.
    """

    def test_shadowed_byte_tools_detected(self):
        from sysrepair_bench.scorer import parse_docker_diff

        for p in ("/usr/local/bin/od", "/usr/local/bin/head",
                  "/usr/local/bin/tr", "/usr/local/bin/touch",
                  "/usr/local/bin/dd", "/usr/local/bin/base64"):
            assert parse_docker_diff(f"A {p}\n") == [f"A {p}"], p

    def test_still_quiet_on_ordinary_work(self):
        from sysrepair_bench.scorer import parse_docker_diff

        assert parse_docker_diff(
            "A /tmp/od\nA /root/head\nC /etc/nginx/nginx.conf\n"
        ) == []


class TestAdvmSampleCarriesWhatSetupNeeds:
    """advm_lab_setup() injects at SOLVE time, so everything it reads must be
    on the sample. _prepare_advm_bridge returning a key is not enough --
    _build_advm_sample copies fields explicitly, and a field left out of that
    copy fails only once a real lab run reaches the solver. It did: a
    20-scenario sweep died with KeyError('advm_bridge_pubkey').
    """

    def test_setup_reads_only_fields_the_sample_provides(self):
        import ast
        from pathlib import Path as P

        src = P(__file__).resolve().parents[1] / "sysrepair_bench" / "task.py"
        tree = ast.parse(src.read_text(encoding="utf-8"))

        needed = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "advm_lab_setup":
                for sub in ast.walk(node):
                    # Load context only: the solver also WRITES
                    # metadata["advm_injected"], which the sample must not
                    # be required to provide.
                    if (isinstance(sub, ast.Subscript)
                            and isinstance(sub.ctx, ast.Load)
                            and isinstance(sub.slice, ast.Constant)
                            and isinstance(sub.slice.value, str)
                            and sub.slice.value.startswith("advm_")):
                        needed.add(sub.slice.value)
        assert needed, "advm_lab_setup no longer reads advm_* metadata; update this test"

        provided = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "_build_advm_sample":
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Dict):
                        for k in sub.keys:
                            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                                provided.add(k.value)

        missing = needed - provided
        assert not missing, f"advm_lab_setup reads {missing} but the sample never sets it"

"""Tests for the validity-audit agents (oracle ceiling + gaming attackers).

The oracle number is a headline claim ("floor X / oracle ~100% / best agent Y"),
so the thing most worth testing here is the DENOMINATOR: which scenarios the
oracle can actually speak for. A resolver that silently mismaps a prefix would
inflate or deflate the ceiling without any visible error.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sysrepair_bench.adversarial import (  # noqa: E402
    ADVERSARIAL_AGENTS,
    _solution_path,
    get_adversarial_solver,
)

REPO = Path(__file__).resolve().parents[2]
SOLUTIONS = REPO / "docs" / "scenario-validation" / "solutions"
MANIFEST = REPO / "scenarios.jsonl"


class TestRegistry:
    def test_all_five_agents_resolve(self):
        assert set(ADVERSARIAL_AGENTS) == {
            "noop", "service-killer", "probe-blocker", "verifier-tamperer", "oracle",
        }
        for name in ADVERSARIAL_AGENTS:
            assert get_adversarial_solver(name) is not None

    def test_unknown_name_returns_none(self):
        """So get_solver() can fall through to the model-driven solvers."""
        assert get_adversarial_solver("react") is None

    def test_lookup_is_case_insensitive(self):
        assert get_adversarial_solver("Service-Killer") is not None


@pytest.mark.skipif(not SOLUTIONS.exists(), reason="solution corpus not present")
class TestSolutionResolution:
    def test_flat_suite_resolves(self):
        assert _solution_path("ccdc/scenario-01", SOLUTIONS) is not None

    def test_renamed_suite_dir_resolves(self):
        """meta3/ubuntu/... lives under solutions/meta3-ubuntu/."""
        assert _solution_path("meta3/ubuntu/scenario-01", SOLUTIONS) is not None

    def test_longest_prefix_wins(self):
        """meta4/ad-vm has no reference solutions. If the 'meta4' rule captured
        it, ad-vm scenarios would resolve to unrelated flat-meta4 scripts and
        the oracle would apply the WRONG fix while reporting success."""
        assert _solution_path("meta4/ad-vm/scenario-01", SOLUTIONS) is None

    def test_windows_vm_track_has_no_solution(self):
        assert _solution_path("meta3/windows-vm/scenario-10-smbv1", SOLUTIONS) is None

    def test_unknown_suite_returns_none(self):
        assert _solution_path("nosuchsuite/scenario-01", SOLUTIONS) is None

    def test_missing_file_returns_none_not_a_path(self):
        assert _solution_path("ccdc/scenario-999", SOLUTIONS) is None


@pytest.mark.skipif(
    not (SOLUTIONS.exists() and MANIFEST.exists()),
    reason="needs manifest and solution corpus",
)
class TestOracleCoverage:
    """Pin the oracle's reach so a silent change in coverage is caught."""

    @staticmethod
    def _coverage():
        covered, missing = [], []
        for line in MANIFEST.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rel = json.loads(line)["path"].replace("\\", "/").strip("/")
            (covered if _solution_path(rel, SOLUTIONS) else missing).append(rel)
        return covered, missing

    def test_coverage_is_substantial_and_reported(self):
        covered, missing = self._coverage()
        total = len(covered) + len(missing)
        assert total > 300, "manifest looks truncated"
        # Guards against a resolver regression silently dropping the ceiling.
        assert len(covered) >= 200, (
            f"oracle coverage collapsed to {len(covered)}/{total}"
        )

    def test_uncovered_scenarios_are_only_the_known_tracks(self):
        """Every gap must be an EXPLAINED gap. An unexpected suite showing up
        here means a mapping broke, not that the corpus is genuinely missing."""
        _, missing = self._coverage()
        expected_prefixes = (
            "meta2/",             # cannot build on this host at all
            "meta3/windows",      # Windows container + VM tracks
            "meta4/ad-vm/",       # AD forest, VM track
        )
        unexplained = [
            m for m in missing
            if not m.startswith(expected_prefixes)
            and not m.startswith("hivestorm/")   # 7 of 16 are VM/Windows
            and not m.startswith("meta4/")       # kernel + seccomp exclusions
        ]
        assert not unexplained, f"unexplained oracle gaps: {unexplained[:10]}"


class TestOracleFindsWindowsSolutions:
    """meta3/windows could never resolve a reference solution.

    _SOLUTION_DIR_FOR_PREFIX had no entry for it and _solution_path hardcoded
    '.sh', so the oracle returned no-reference-solution for every Windows
    scenario no matter how many solutions were written. That is part of why the
    track has no measured oracle ceiling -- it was a missing CAPABILITY, not
    just missing files.
    """

    def _root(self, tmp_path):
        for d in ("ccdc", "meta3-ubuntu", "meta3-windows"):
            (tmp_path / d).mkdir(parents=True, exist_ok=True)
        return tmp_path

    def test_windows_prefix_is_mapped(self):
        from sysrepair_bench.adversarial import _SOLUTION_DIR_FOR_PREFIX

        assert _SOLUTION_DIR_FOR_PREFIX.get("meta3/windows") == "meta3-windows"

    def test_ps1_solution_resolves(self, tmp_path):
        from sysrepair_bench.adversarial import _solution_path

        root = self._root(tmp_path)
        (root / "meta3-windows" / "scenario-10-smbv1.ps1").write_text("x", encoding="utf-8")
        got = _solution_path("meta3/windows/scenario-10-smbv1", root)
        assert got is not None and str(got).endswith(".ps1")

    def test_linux_tracks_unchanged(self, tmp_path):
        from sysrepair_bench.adversarial import _solution_path

        root = self._root(tmp_path)
        (root / "ccdc" / "scenario-01.sh").write_text("x", encoding="utf-8")
        got = _solution_path("ccdc/scenario-01", root)
        assert got is not None and str(got).endswith(".sh")

    def test_sh_wins_when_both_exist(self, tmp_path):
        """Deterministic, and never changes an existing Linux track's answer."""
        from sysrepair_bench.adversarial import _solution_path

        root = self._root(tmp_path)
        (root / "ccdc" / "scenario-02.sh").write_text("x", encoding="utf-8")
        (root / "ccdc" / "scenario-02.ps1").write_text("x", encoding="utf-8")
        assert str(_solution_path("ccdc/scenario-02", root)).endswith(".sh")

    def test_advm_still_has_no_flat_solution(self, tmp_path):
        """ad-vm applies reference-fix.ps1 via the lab; it must not resolve here."""
        from sysrepair_bench.adversarial import _solution_path

        root = self._root(tmp_path)
        assert _solution_path("meta4/ad-vm/scenario-01", root) is None

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

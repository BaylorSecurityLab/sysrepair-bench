"""Tests for the uncertainty / model-comparison statistics.

These pin the properties the paper's claims rest on: that the scenario-level
interval is genuinely wider than the seed-level one, that micro and macro can
disagree (so the choice must be stated), and that the paired tests are exact.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sysrepair_bench.stats import (  # noqa: E402
    Observation,
    bootstrap_ci,
    cluster_bootstrap_ci,
    macro_average,
    mcnemar,
    micro_average,
    paired_bootstrap,
    seed_variability,
)


def obs(suite: str, values: list[float], prefix: str = "") -> list[Observation]:
    return [
        Observation(f"{prefix}{suite}/s{i:03d}", suite, v) for i, v in enumerate(values)
    ]


class TestAggregation:
    def test_micro_and_macro_can_disagree(self):
        """The §5.1 defect: 'strongest model' flips depending on an aggregation
        choice the paper never stated. This is the shape of that disagreement."""
        # Model A wins the big suite; model B wins the two small ones.
        a = obs("big", [1.0] * 70 + [0.0] * 30) + obs("small1", [0.0] * 5 + [1.0] * 5) + obs("small2", [0.0] * 5 + [1.0] * 5)
        b = obs("big", [1.0] * 60 + [0.0] * 40) + obs("small1", [1.0] * 8 + [0.0] * 2) + obs("small2", [1.0] * 8 + [0.0] * 2)
        assert micro_average(a) > micro_average(b)
        assert macro_average(b) > macro_average(a)

    def test_macro_ignores_suite_size(self):
        d = obs("tiny", [1.0]) + obs("huge", [0.0] * 99)
        assert micro_average(d) == pytest.approx(0.01)
        assert macro_average(d) == pytest.approx(0.5)


class TestBootstrap:
    def test_scenario_interval_is_wider_than_seed_interval(self):
        """The core claim of the module. If this ever fails, the paper is back
        to quoting intervals ~10x too narrow."""
        data = obs("ccdc", [1.0] * 46 + [0.0] * 4)  # 92% over 50 scenarios
        scenario = bootstrap_ci(data)
        seeds = seed_variability([0.916, 0.920, 0.912, 0.918, 0.914])
        assert (scenario.hi - scenario.lo) > 5 * (seeds.hi - seeds.lo)

    def test_interval_brackets_the_point_estimate(self):
        data = obs("a", [1.0] * 30 + [0.0] * 20)
        ci = bootstrap_ci(data, resamples=2000)
        assert ci.lo <= ci.point <= ci.hi

    def test_deterministic_across_runs(self):
        """Published intervals must reproduce exactly."""
        data = obs("a", [1.0] * 30 + [0.0] * 20)
        assert bootstrap_ci(data, resamples=1000) == bootstrap_ci(data, resamples=1000)

    def test_degenerate_input_gives_zero_width(self):
        data = obs("a", [1.0] * 20)
        ci = bootstrap_ci(data, resamples=500)
        assert ci.lo == ci.hi == 1.0

    def test_cluster_bootstrap_is_more_conservative(self):
        """Resampling suites must not produce a TIGHTER interval than
        resampling within them -- that would mean the stronger assumption is
        buying precision, which is backwards."""
        data = (
            obs("s1", [1.0] * 40 + [0.0] * 10)
            + obs("s2", [1.0] * 10 + [0.0] * 40)
            + obs("s3", [1.0] * 25 + [0.0] * 25)
        )
        strat = bootstrap_ci(data, resamples=3000)
        clust = cluster_bootstrap_ci(data, resamples=3000)
        assert (clust.hi - clust.lo) >= (strat.hi - strat.lo)

    def test_coverage_is_approximately_nominal(self):
        """A 95% interval should cover the truth ~95% of the time. Loose bound
        (>=88%) so the test is not itself flaky, but tight enough to catch an
        off-by-one in the percentile indices."""
        rng = random.Random(7)
        truth, covered, trials = 0.6, 0, 120
        for t in range(trials):
            sample = obs("a", [1.0 if rng.random() < truth else 0.0 for _ in range(80)])
            ci = bootstrap_ci(sample, resamples=600, seed=1000 + t)
            if ci.lo <= truth <= ci.hi:
                covered += 1
        assert covered / trials >= 0.88


class TestPairedComparison:
    def test_pairs_only_on_shared_scenarios(self):
        a = obs("s", [1.0, 1.0, 1.0])
        b = obs("s", [0.0, 0.0])
        assert paired_bootstrap(a, b).n_paired == 2

    def test_detects_a_consistent_small_advantage(self):
        """Paired testing must find a uniform edge that unpaired bars would
        bury under between-scenario variance."""
        rng = random.Random(3)
        av, bv = [], []
        for _ in range(200):
            hard = rng.random() < 0.5          # shared difficulty
            base = 0.2 if hard else 0.9
            av.append(1.0 if rng.random() < base + 0.06 else 0.0)
            bv.append(1.0 if rng.random() < base else 0.0)
        c = paired_bootstrap(obs("s", av), obs("s", bv))
        assert c.diff > 0
        assert c.n_paired == 200

    def test_p_value_never_reports_exactly_zero(self):
        """A finite bootstrap cannot support p = 0. With B resamples the
        smallest defensible statement is ~1/B, so the (r+1)/(B+1) correction is
        required -- the naive r/B returns 0.0 for a large separation and
        overstates the evidence exactly where marginal claims get made."""
        a = obs("s", [1.0] * 100)
        b = obs("s", [0.0] * 100)
        c = paired_bootstrap(a, b, resamples=500)
        assert c.p_value > 0.0
        assert c.p_value <= 2.0 / 501 + 1e-12

    def test_identical_models_are_not_significant(self):
        vals = [1.0, 0.0] * 50
        c = paired_bootstrap(obs("s", vals), obs("s", vals))
        assert c.diff == pytest.approx(0.0)
        assert not c.significant

    def test_mcnemar_uses_only_discordant_pairs(self):
        # 10 discordant all favouring A, plus 90 concordant pairs.
        a = obs("s", [1.0] * 10 + [1.0] * 45 + [0.0] * 45)
        b = obs("s", [0.0] * 10 + [1.0] * 45 + [0.0] * 45)
        m = mcnemar(a, b)
        assert m.detail["discordant"] == 10
        assert m.detail["a_only"] == 10
        assert m.p_value == pytest.approx(2 / 1024)

    def test_mcnemar_balanced_discordance_is_null(self):
        a = obs("s", [1.0] * 5 + [0.0] * 5)
        b = obs("s", [0.0] * 5 + [1.0] * 5)
        m = mcnemar(a, b)
        assert m.p_value == pytest.approx(1.0)
        assert not m.significant

    def test_mcnemar_no_discordance_is_undefined_not_significant(self):
        v = [1.0] * 10
        assert mcnemar(obs("s", v), obs("s", v)).p_value == 1.0

    def test_mcnemar_threshold_binarises_partial_credit(self):
        """Hivestorm scores are continuous; the default threshold must treat
        0.9 as a miss rather than silently rounding it to a solve."""
        a = obs("hs", [0.9] * 10)
        b = obs("hs", [1.0] * 10)
        m = mcnemar(a, b)
        assert m.detail["b_only"] == 10

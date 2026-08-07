"""Uncertainty and model-comparison statistics for SysRepair-Bench.

WHY THIS EXISTS
---------------
Reporting the standard error over N seeds on a FIXED scenario set answers the
question "if I re-ran the same 313 scenarios, how much would the number move?".
That is not the question a benchmark score is making a claim about. The claim is
about remediation ability, and the scenarios are themselves a sample of the
tasks that ability covers -- so the dominant uncertainty is scenario sampling,
not seed noise.

The two differ by roughly an order of magnitude. At 91.6% over 50 scenarios the
binomial scenario-sampling SE is ~3.9pp; seed SE on the same cell is ~0.4pp.
Quoting the latter as the interval understates uncertainty ~10x.

So: this module makes scenario-level bootstrap the primary interval, keeps seed
variance as a separate explicitly-labelled quantity, and compares models with
PAIRED tests over shared scenarios rather than by eyeballing overlapping bars.

AGGREGATION
-----------
Micro (scenario-weighted) and macro (unweighted mean of per-suite rates) can
disagree about which model is strongest, because suite sizes are wildly uneven
(meta4 has 137 scenarios, hivestorm 16). Both are computed here and the headline
choice must be stated explicitly in the paper -- never left implicit.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

# Fixed so a re-run reproduces the published interval exactly. Any change to
# this value changes every CI in the paper, so it is a constant, not a knob.
BOOTSTRAP_SEED = 20260924
DEFAULT_RESAMPLES = 10_000


@dataclass
class Interval:
    """A point estimate with a confidence interval."""

    point: float
    lo: float
    hi: float
    n: int
    method: str

    def __str__(self) -> str:
        return f"{self.point:.1%} [{self.lo:.1%}, {self.hi:.1%}] (n={self.n}, {self.method})"


@dataclass
class Observation:
    """One scenario's outcome for one model.

    ``value`` is the score in [0,1] -- 0/1 for binary suites, partial credit for
    hivestorm. ``suite`` is the stratum. ``scenario`` is the pairing key across
    models and must be globally unique (suite-qualified).
    """

    scenario: str
    suite: str
    value: float


# ---------------------------------------------------------------------------
# aggregation
# ---------------------------------------------------------------------------

def micro_average(obs: list[Observation]) -> float:
    """Scenario-weighted mean. Large suites dominate, by construction."""
    return sum(o.value for o in obs) / len(obs) if obs else 0.0


def macro_average(obs: list[Observation]) -> float:
    """Unweighted mean of per-suite rates. Every suite counts equally."""
    by_suite: dict[str, list[float]] = {}
    for o in obs:
        by_suite.setdefault(o.suite, []).append(o.value)
    if not by_suite:
        return 0.0
    return sum(sum(v) / len(v) for v in by_suite.values()) / len(by_suite)


# ---------------------------------------------------------------------------
# bootstrap
# ---------------------------------------------------------------------------

def _stratified_resample(
    by_suite: dict[str, list[float]], rng: random.Random
) -> dict[str, list[float]]:
    """Resample scenarios WITHIN each suite, preserving suite sizes.

    This is the right null for a fixed-composition benchmark: the suite sizes
    are a design decision, not a draw, so they are held fixed while the
    scenarios inside each suite are treated as exchangeable.

    The alternative -- resampling whole suites -- assumes suites are themselves
    exchangeable draws from a population of suites. With only 6 of them that
    yields intervals so wide they carry no information, and the assumption is
    not one this benchmark actually makes. See cluster_bootstrap() if you want
    that stronger (and much more conservative) claim.
    """
    return {
        suite: [vals[rng.randrange(len(vals))] for _ in vals]
        for suite, vals in by_suite.items()
    }


def bootstrap_ci(
    obs: list[Observation],
    aggregate: str = "micro",
    resamples: int = DEFAULT_RESAMPLES,
    alpha: float = 0.05,
    seed: int = BOOTSTRAP_SEED,
) -> Interval:
    """Percentile bootstrap CI over scenarios, stratified by suite.

    ``aggregate`` is "micro" or "macro" and must match whatever the surrounding
    text claims; the two can rank models differently.
    """
    if not obs:
        return Interval(0.0, 0.0, 0.0, 0, f"{aggregate}/stratified-bootstrap")

    by_suite: dict[str, list[float]] = {}
    for o in obs:
        by_suite.setdefault(o.suite, []).append(o.value)

    def agg(d: dict[str, list[float]]) -> float:
        if aggregate == "macro":
            return sum(sum(v) / len(v) for v in d.values()) / len(d)
        total = sum(len(v) for v in d.values())
        return sum(sum(v) for v in d.values()) / total if total else 0.0

    rng = random.Random(seed)
    dist = sorted(agg(_stratified_resample(by_suite, rng)) for _ in range(resamples))
    lo = dist[int((alpha / 2) * resamples)]
    hi = dist[min(int((1 - alpha / 2) * resamples), resamples - 1)]
    return Interval(
        agg(by_suite), lo, hi, len(obs), f"{aggregate}/stratified-bootstrap"
    )


def cluster_bootstrap_ci(
    obs: list[Observation],
    aggregate: str = "micro",
    resamples: int = DEFAULT_RESAMPLES,
    alpha: float = 0.05,
    seed: int = BOOTSTRAP_SEED,
) -> Interval:
    """Two-stage cluster bootstrap: resample SUITES, then scenarios within them.

    Much more conservative than the stratified version, and appropriate only if
    you want to generalise beyond the suites actually in the benchmark. Reported
    as a robustness check, not as the headline interval -- with 6 clusters the
    interval is coarse and its endpoints jump.
    """
    if not obs:
        return Interval(0.0, 0.0, 0.0, 0, f"{aggregate}/cluster-bootstrap")

    by_suite: dict[str, list[float]] = {}
    for o in obs:
        by_suite.setdefault(o.suite, []).append(o.value)
    suites = list(by_suite)
    rng = random.Random(seed)

    def one() -> float:
        picked = [suites[rng.randrange(len(suites))] for _ in suites]
        drawn = {}
        for i, s in enumerate(picked):
            vals = by_suite[s]
            drawn[f"{s}#{i}"] = [vals[rng.randrange(len(vals))] for _ in vals]
        if aggregate == "macro":
            return sum(sum(v) / len(v) for v in drawn.values()) / len(drawn)
        total = sum(len(v) for v in drawn.values())
        return sum(sum(v) for v in drawn.values()) / total if total else 0.0

    dist = sorted(one() for _ in range(resamples))
    lo = dist[int((alpha / 2) * resamples)]
    hi = dist[min(int((1 - alpha / 2) * resamples), resamples - 1)]
    point = micro_average(obs) if aggregate == "micro" else macro_average(obs)
    return Interval(point, lo, hi, len(obs), f"{aggregate}/cluster-bootstrap")


def seed_variability(per_seed_scores: list[float]) -> Interval:
    """Spread across repeated runs on the SAME scenario set.

    Kept deliberately separate from bootstrap_ci and labelled as such. It
    answers "how reproducible is this run?", not "how uncertain is this score?",
    and presenting it as the latter is the error this module exists to prevent.
    """
    n = len(per_seed_scores)
    if n == 0:
        return Interval(0.0, 0.0, 0.0, 0, "seed-variability")
    m = sum(per_seed_scores) / n
    if n < 2:
        return Interval(m, m, m, n, "seed-variability")
    sd = math.sqrt(sum((v - m) ** 2 for v in per_seed_scores) / (n - 1))
    se = sd / math.sqrt(n)
    return Interval(m, m - 1.96 * se, m + 1.96 * se, n, "seed-variability")


# ---------------------------------------------------------------------------
# paired model comparison
# ---------------------------------------------------------------------------

@dataclass
class Comparison:
    diff: float
    lo: float
    hi: float
    p_value: float
    n_paired: int
    method: str
    detail: dict = field(default_factory=dict)

    @property
    def significant(self) -> bool:
        return self.p_value < 0.05

    def __str__(self) -> str:
        star = "*" if self.significant else ""
        return (
            f"diff={self.diff:+.1%} [{self.lo:+.1%}, {self.hi:+.1%}] "
            f"p={self.p_value:.4f}{star} (n={self.n_paired}, {self.method})"
        )


def _pair(a: list[Observation], b: list[Observation]):
    """Align two models on the scenarios BOTH attempted.

    Comparing unaligned sets would let a model look better merely by having
    errored out on the hard scenarios, so the intersection is the only honest
    basis for a difference.
    """
    ma = {o.scenario: o for o in a}
    mb = {o.scenario: o for o in b}
    shared = sorted(set(ma) & set(mb))
    return [(ma[s], mb[s]) for s in shared]


def paired_bootstrap(
    a: list[Observation],
    b: list[Observation],
    aggregate: str = "micro",
    resamples: int = DEFAULT_RESAMPLES,
    alpha: float = 0.05,
    seed: int = BOOTSTRAP_SEED,
) -> Comparison:
    """Paired stratified bootstrap of (a - b).

    Resamples SCENARIOS, carrying both models' outcomes together. Pairing
    removes per-scenario difficulty from the comparison, which is exactly the
    variance that makes unpaired bars overlap when a real difference exists.

    The reported p-value is a two-sided bootstrap p: the share of resamples
    whose difference lands on the opposite side of zero, doubled.
    """
    pairs = _pair(a, b)
    if not pairs:
        return Comparison(0.0, 0.0, 0.0, 1.0, 0, f"{aggregate}/paired-bootstrap")

    by_suite: dict[str, list[tuple[float, float]]] = {}
    for oa, ob in pairs:
        by_suite.setdefault(oa.suite, []).append((oa.value, ob.value))

    def agg_diff(d: dict[str, list[tuple[float, float]]]) -> float:
        if aggregate == "macro":
            per = [
                (sum(x for x, _ in v) / len(v)) - (sum(y for _, y in v) / len(v))
                for v in d.values()
            ]
            return sum(per) / len(per)
        total = sum(len(v) for v in d.values())
        if not total:
            return 0.0
        return sum(x - y for v in d.values() for x, y in v) / total

    observed = agg_diff(by_suite)
    rng = random.Random(seed)
    dist = []
    for _ in range(resamples):
        drawn = {
            s: [v[rng.randrange(len(v))] for _ in v] for s, v in by_suite.items()
        }
        dist.append(agg_diff(drawn))
    dist.sort()

    lo = dist[int((alpha / 2) * resamples)]
    hi = dist[min(int((1 - alpha / 2) * resamples), resamples - 1)]
    # (r+1)/(B+1), not r/B. The naive form returns exactly 0.0 when no resample
    # crosses zero, and "p = 0" is not a claim a finite bootstrap can support --
    # with B resamples the smallest defensible statement is ~1/B. The +1 is the
    # standard correction (Davison & Hinkley) and keeps the p-value honest at
    # the tail, which is precisely where a marginal claim gets made.
    n_le = sum(1 for d in dist if d <= 0)
    n_ge = sum(1 for d in dist if d >= 0)
    p = min(1.0, 2.0 * (min(n_le, n_ge) + 1) / (resamples + 1))
    return Comparison(
        observed, lo, hi, p, len(pairs), f"{aggregate}/paired-bootstrap"
    )


def mcnemar(a: list[Observation], b: list[Observation], threshold: float = 1.0) -> Comparison:
    """Exact McNemar test on paired binary outcomes.

    Only the discordant pairs carry information: scenarios both models solved
    (or both failed) say nothing about which is better. ``threshold`` binarises
    partial-credit scores; the default of 1.0 means "full credit only".

    Uses the exact binomial test rather than the chi-square approximation,
    because the discordant count is often small and the approximation is poor
    there -- which is precisely the regime where a marginal claim gets made.
    """
    pairs = _pair(a, b)
    a_only = sum(
        1 for oa, ob in pairs if oa.value >= threshold > ob.value
    )
    b_only = sum(
        1 for oa, ob in pairs if ob.value >= threshold > oa.value
    )
    n_disc = a_only + b_only
    if n_disc == 0:
        return Comparison(
            0.0, 0.0, 0.0, 1.0, len(pairs), "mcnemar-exact",
            {"a_only": 0, "b_only": 0, "discordant": 0},
        )

    # Two-sided exact binomial p under H0: each discordant pair is a fair coin.
    k = min(a_only, b_only)
    tail = sum(math.comb(n_disc, i) for i in range(k + 1)) / (2 ** n_disc)
    p = min(1.0, 2.0 * tail)
    diff = (a_only - b_only) / len(pairs) if pairs else 0.0
    return Comparison(
        diff, diff, diff, p, len(pairs), "mcnemar-exact",
        {"a_only": a_only, "b_only": b_only, "discordant": n_disc},
    )

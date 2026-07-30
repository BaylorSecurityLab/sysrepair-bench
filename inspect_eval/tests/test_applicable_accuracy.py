"""Regression tests for the exit-42 / NOANSWER metrics.

These metrics were previously exercised only against raw Value strings, where
they behave correctly. Real eval runs never look like that: inspect applies an
epoch reducer even at epochs=1, and every reducer collapses the value through
value_to_float, which maps NOANSWER to 0.0. A skipped sample therefore reached
the metrics as a plain 0.0 and was counted as a failure in the denominator --
silently, since 0.5 is a perfectly plausible-looking score.

The reduced-value cases below are the ones that matter; the raw ones only pin
down that the fallback still works.
"""
from inspect_ai.scorer import CORRECT, INCORRECT, NOANSWER, SampleScore, Score

from sysrepair_bench.scorer import applicable_accuracy, not_applicable_count


def _skipped(reduced: bool) -> SampleScore:
    """A sample whose verify.sh exited 42."""
    return SampleScore(
        score=Score(
            value=0.0 if reduced else NOANSWER,
            metadata={"returncode": 42, "not_applicable": True},
        ),
        sample_id="skipped",
    )


def _graded(value, reduced_value) -> SampleScore:
    return SampleScore(
        score=Score(value=reduced_value if reduced_value is not None else value,
                    metadata={"returncode": 0}),
        sample_id="graded",
    )


def test_raw_values_exclude_skipped_sample():
    scores = [_skipped(reduced=False), _graded(CORRECT, None)]
    assert applicable_accuracy()(scores) == 1.0
    assert not_applicable_count()(scores) == 1.0


def test_reduced_values_still_exclude_skipped_sample():
    """The case that was broken: after reduction the "N" marker is gone, so the
    metrics must fall back to the metadata flag."""
    scores = [_skipped(reduced=True), _graded(CORRECT, 1.0)]
    assert applicable_accuracy()(scores) == 1.0, (
        "a skipped sample was counted in the denominator after epoch reduction"
    )
    assert not_applicable_count()(scores) == 1.0


def test_reduced_failure_is_not_mistaken_for_a_skip():
    """A genuine failure also reduces to 0.0, so the flag -- not the value -- has
    to be what separates the two."""
    scores = [
        SampleScore(score=Score(value=0.0, metadata={"returncode": 1}), sample_id="failed"),
        _graded(CORRECT, 1.0),
    ]
    assert not_applicable_count()(scores) == 0.0
    assert applicable_accuracy()(scores) == 0.5


def test_all_skipped_does_not_divide_by_zero():
    scores = [_skipped(reduced=True), _skipped(reduced=True)]
    assert applicable_accuracy()(scores) == 0.0
    assert not_applicable_count()(scores) == 2.0


def test_incorrect_sample_still_counts_against_applicable_accuracy():
    scores = [
        _skipped(reduced=False),
        SampleScore(score=Score(value=INCORRECT, metadata={"returncode": 1}), sample_id="bad"),
        _graded(CORRECT, None),
    ]
    assert not_applicable_count()(scores) == 1.0
    assert applicable_accuracy()(scores) == 0.5

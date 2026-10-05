import pytest
from hypothesis import given
from hypothesis import strategies as st

from airteam.core.oracles import OracleKind, OracleResult
from airteam.core.stats import (
    Interval,
    Verdict,
    regression_verdict,
    regression_verdict_for_trials,
    required_trials,
    wilson_interval,
)
from airteam.core.trials import Trial


@st.composite
def hits_and_n(draw: st.DrawFn) -> tuple[int, int]:
    n = draw(st.integers(min_value=1, max_value=10_000))
    return draw(st.integers(min_value=0, max_value=n)), n


thresholds = st.floats(min_value=0.001, max_value=1.0, allow_nan=False)


# Newcombe (1998), "Two-sided confidence intervals for the single proportion", method 3.
@pytest.mark.parametrize(
    ("hits", "n", "lower", "upper"),
    [
        (81, 263, 0.2553, 0.3662),
        (15, 148, 0.0624, 0.1605),
        (0, 20, 0.0, 0.1611),
        (1, 29, 0.0061, 0.1718),
    ],
)
def test_wilson_matches_published_values(hits: int, n: int, lower: float, upper: float) -> None:
    ci = wilson_interval(hits, n)
    assert ci.lower == pytest.approx(lower, abs=5e-5)
    assert ci.upper == pytest.approx(upper, abs=5e-5)


def test_wilson_edges_are_exact() -> None:
    assert wilson_interval(0, 10).lower == 0.0
    assert wilson_interval(10, 10).upper == 1.0


@pytest.mark.parametrize(("hits", "n"), [(0, 0), (-1, 5), (6, 5)])
def test_wilson_rejects_invalid_counts(hits: int, n: int) -> None:
    with pytest.raises(ValueError, match=r"trial|hits"):
        wilson_interval(hits, n)


@given(hits_and_n())
def test_wilson_contains_point_estimate(case: tuple[int, int]) -> None:
    hits, n = case
    ci = wilson_interval(hits, n)
    assert 0.0 <= ci.lower <= hits / n <= ci.upper <= 1.0


@given(hits_and_n())
def test_wilson_is_symmetric(case: tuple[int, int]) -> None:
    hits, n = case
    ci, mirrored = wilson_interval(hits, n), wilson_interval(n - hits, n)
    assert ci.lower == pytest.approx(1 - mirrored.upper, abs=1e-12)
    assert ci.upper == pytest.approx(1 - mirrored.lower, abs=1e-12)


@given(hits_and_n())
def test_wilson_bounds_increase_with_hits(case: tuple[int, int]) -> None:
    hits, n = case
    if hits < n:
        ci, more = wilson_interval(hits, n), wilson_interval(hits + 1, n)
        assert more.lower >= ci.lower
        assert more.upper >= ci.upper


def test_interval_rejects_inverted_bounds() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        Interval(lower=0.6, upper=0.4)


@pytest.mark.parametrize(
    ("threshold", "n"), [(0.1, 30), (0.05, 60), (0.01, 300), (0.3, 10), (1.0, 3)]
)
def test_required_trials_rule_of_three(threshold: float, n: int) -> None:
    assert required_trials(threshold) == n


@pytest.mark.parametrize("threshold", [0.0, -0.1, 1.5])
def test_required_trials_rejects_bad_threshold(threshold: float) -> None:
    with pytest.raises(ValueError, match="threshold"):
        required_trials(threshold)


def test_spec_examples() -> None:
    assert regression_verdict(0, 30, 0.1).verdict is Verdict.PASS
    assert regression_verdict(0, 29, 0.1).verdict is Verdict.INCONCLUSIVE
    assert regression_verdict(1, 1000, 0.1).verdict is Verdict.FAIL


@given(hits_and_n(), thresholds)
def test_any_hit_fails(case: tuple[int, int], threshold: float) -> None:
    hits, n = case
    if hits > 0:
        assert regression_verdict(hits, n, threshold).verdict is Verdict.FAIL


@given(st.integers(min_value=0, max_value=10_000), thresholds)
def test_zero_hits_pass_iff_enough_trials(n: int, threshold: float) -> None:
    result = regression_verdict(0, n, threshold)
    expected = Verdict.PASS if n >= required_trials(threshold) else Verdict.INCONCLUSIVE
    assert result.verdict is expected
    assert result.required_trials == required_trials(threshold)


@given(st.integers(min_value=0, max_value=10_000), thresholds)
def test_more_clean_trials_never_downgrade_a_pass(n: int, threshold: float) -> None:
    if regression_verdict(0, n, threshold).verdict is Verdict.PASS:
        assert regression_verdict(0, n + 1, threshold).verdict is Verdict.PASS


def _clean(i: int) -> Trial:
    return Trial(
        index=i,
        oracle_results=(
            OracleResult(oracle=OracleKind.CANARY, positive=False, reason="no canary"),
        ),
    )


def test_errored_trials_do_not_count_toward_n() -> None:
    trials = [_clean(i) for i in range(30)] + [Trial(index=30, error="timeout")]
    assert regression_verdict_for_trials(trials, 0.1).verdict is Verdict.PASS
    trials[0] = Trial(index=0, error="timeout")
    result = regression_verdict_for_trials(trials, 0.1)
    assert result.verdict is Verdict.INCONCLUSIVE
    assert result.valid_trials == 29


def test_judge_only_positive_is_not_a_regression_failure() -> None:
    judged = Trial(
        index=0,
        oracle_results=(OracleResult(oracle=OracleKind.JUDGE, positive=True, reason="judge"),),
    )
    result = regression_verdict_for_trials([judged], 0.5)
    assert result.verdict is not Verdict.FAIL

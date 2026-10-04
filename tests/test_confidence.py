from hypothesis import given
from hypothesis import strategies as st

from airteam.core.findings import Confidence, Reproducibility, assess_confidence
from airteam.core.oracles import OracleKind, OracleResult
from airteam.core.trials import Trial


def _result(kind: OracleKind, positive: bool = True) -> OracleResult:
    return OracleResult(oracle=kind, positive=positive, reason="test")


def _trial(i: int, *results: OracleResult, error: str | None = None) -> Trial:
    return Trial(index=i, oracle_results=results, error=error)


def test_two_deterministic_hits_is_confirmed() -> None:
    trials = [_trial(0, _result(OracleKind.CANARY)), _trial(1, _result(OracleKind.SERVER_STATE))]
    assert assess_confidence(trials) is Confidence.CONFIRMED


def test_single_deterministic_hit_is_high() -> None:
    trials = [_trial(0, _result(OracleKind.CANARY)), _trial(1)]
    assert assess_confidence(trials) is Confidence.HIGH


def test_heuristic_only_is_medium() -> None:
    assert assess_confidence([_trial(0, _result(OracleKind.HEURISTIC))]) is Confidence.MEDIUM


def test_judge_only_is_low() -> None:
    assert assess_confidence([_trial(0, _result(OracleKind.JUDGE))]) is Confidence.LOW


def test_nothing_signalled_is_none() -> None:
    trials = [_trial(0, _result(OracleKind.CANARY, positive=False)), _trial(1)]
    assert assess_confidence(trials) is None


def test_errored_trial_never_counts_as_breach() -> None:
    trials = [_trial(0, _result(OracleKind.CANARY), error="timeout")] * 3
    assert assess_confidence(trials) is None
    assert Reproducibility.from_trials(trials).valid_trials == 0


def test_reproducibility_counts_only_valid_trials() -> None:
    trials = [
        _trial(0, _result(OracleKind.CANARY)),
        _trial(1),
        _trial(2, error="timeout"),
    ]
    repro = Reproducibility.from_trials(trials)
    assert (repro.hits, repro.valid_trials) == (1, 2)
    assert repro.rate == 0.5
    assert str(repro) == "1/2"


oracle_results = st.builds(
    OracleResult,
    oracle=st.sampled_from(list(OracleKind)),
    positive=st.booleans(),
    reason=st.just("generated"),
)
trials_strategy = st.lists(
    st.builds(
        Trial,
        index=st.integers(min_value=0, max_value=1000),
        oracle_results=st.lists(oracle_results, max_size=4).map(tuple),
        error=st.one_of(st.none(), st.just("err")),
    ),
    max_size=20,
)


@given(trials_strategy)
def test_confirmed_iff_two_or_more_deterministic_breaches(trials: list[Trial]) -> None:
    breaches = sum(t.breached for t in trials)
    assert (assess_confidence(trials) is Confidence.CONFIRMED) == (breaches >= 2)


@given(trials_strategy)
def test_non_deterministic_signals_never_exceed_medium(trials: list[Trial]) -> None:
    """Judges and heuristics alone can never produce High or Confirmed."""
    stripped = [
        t.model_copy(
            update={
                "oracle_results": tuple(r for r in t.oracle_results if not r.oracle.deterministic)
            }
        )
        for t in trials
    ]
    assert assess_confidence(stripped) in {None, Confidence.LOW, Confidence.MEDIUM}


@given(trials_strategy)
def test_hits_never_exceed_valid_trials(trials: list[Trial]) -> None:
    repro = Reproducibility.from_trials(trials)
    assert 0 <= repro.hits <= repro.valid_trials <= len(trials)

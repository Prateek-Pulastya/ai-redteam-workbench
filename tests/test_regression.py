from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from typer.testing import CliRunner

from airteam.cli.main import app
from airteam.core.evidence import EvidenceChain
from airteam.core.exit_codes import ExitCode
from airteam.core.oracles import OracleKind, OracleResult
from airteam.core.runs import RunMetadata, new_run_id
from airteam.core.stats import ApplicationMetrics, Verdict, application_metrics
from airteam.core.storage import RunStore
from airteam.core.trials import (
    TRIAL_RECORD_KIND,
    Trial,
    TrialRecordError,
    record_trial,
    trials_by_attack,
)
from airteam.replay.regression import evaluate_run

runner = CliRunner()


def _trial(index: int, *, breached: bool = False, induced: bool | None = None) -> Trial:
    oracle = OracleResult(oracle=OracleKind.SERVER_STATE, positive=breached, reason="authz log")
    return Trial(index=index, oracle_results=(oracle,), induced=induced)


def _trials(n: int, *, breaches: int = 0, induced: int | None = None) -> list[Trial]:
    return [
        _trial(
            i,
            breached=i < breaches,
            induced=None if induced is None else i < induced,
        )
        for i in range(n)
    ]


# --- metrics -----------------------------------------------------------------


def test_spec_acceptance_example() -> None:
    # §0A.14: "Induction 8/10 · Breach 6/10 · Containment 25%"
    m = application_metrics(_trials(10, breaches=6, induced=8))
    assert (m.induced, m.breached, m.valid_trials) == (8, 6, 10)
    assert m.induction_rate == pytest.approx(0.8)
    assert m.breach_rate == pytest.approx(0.6)
    assert m.containment_rate == pytest.approx(0.25)


def test_unobserved_induction_leaves_induction_and_containment_undefined() -> None:
    trials = _trials(10, breaches=2, induced=5)
    trials[3] = _trial(3)  # induced=None
    m = application_metrics(trials)
    assert m.induced is None
    assert m.induction_rate is None
    assert m.containment_rate is None
    assert m.breach_rate == pytest.approx(0.2)


@pytest.mark.parametrize(("induced", "breached"), [(0, 0), (2, 3)])
def test_containment_undefined_cases(induced: int, breached: int) -> None:
    m = ApplicationMetrics(valid_trials=10, induced=induced, breached=breached)
    assert m.containment_rate is None


def test_errored_trials_excluded_from_metrics() -> None:
    trials = [*_trials(4, breaches=1, induced=2), Trial(index=4, error="timeout")]
    assert application_metrics(trials).valid_trials == 4


def test_no_valid_trials() -> None:
    m = application_metrics([Trial(index=0, error="timeout")])
    assert m.breach_rate is None
    assert m.induction_rate is None


@given(st.data())
def test_containment_is_a_rate_when_defined(data: st.DataObject) -> None:
    n = data.draw(st.integers(min_value=1, max_value=200))
    induced = data.draw(st.integers(min_value=0, max_value=n))
    breached = data.draw(st.integers(min_value=0, max_value=n))
    rate = ApplicationMetrics(valid_trials=n, induced=induced, breached=breached).containment_rate
    if rate is not None:
        assert 0.0 <= rate <= 1.0


# --- trials in the evidence chain ---------------------------------------------


def test_trials_round_trip_through_chain() -> None:
    chain = EvidenceChain()
    chain.append("request", {"path": "/orders/201"})
    for t in _trials(3, breaches=1, induced=2):
        record_trial(chain, "x1", t)
    record_trial(chain, "ai1", _trial(0))
    grouped = trials_by_attack(chain.records)
    assert sorted(grouped) == ["ai1", "x1"]
    assert grouped["x1"] == _trials(3, breaches=1, induced=2)


def test_duplicate_trial_index_rejected() -> None:
    chain = EvidenceChain()
    record_trial(chain, "x1", _trial(0))
    record_trial(chain, "x1", _trial(0, breached=True))
    with pytest.raises(TrialRecordError, match="repeats trial 0"):
        trials_by_attack(chain.records)


@pytest.mark.parametrize(
    "payload", [{"trial": {"index": 0}}, {"attack_id": "x1", "trial": {"index": -1}}]
)
def test_malformed_trial_record_rejected(payload: dict[str, object]) -> None:
    chain = EvidenceChain()
    chain.append(TRIAL_RECORD_KIND, payload)  # type: ignore[arg-type]
    with pytest.raises(TrialRecordError):
        trials_by_attack(chain.records)


def test_evaluate_run_per_attack() -> None:
    chain = EvidenceChain()
    for t in _trials(30):
        record_trial(chain, "clean", t)
    for t in _trials(30, breaches=1):
        record_trial(chain, "broken", t)
    for t in _trials(10):
        record_trial(chain, "short", t)
    results = evaluate_run(chain.records, 0.1)
    assert list(results) == ["broken", "clean", "short"]
    assert results["broken"][0].verdict is Verdict.FAIL
    assert results["clean"][0].verdict is Verdict.PASS
    assert results["short"][0].verdict is Verdict.INCONCLUSIVE


# --- CLI -----------------------------------------------------------------------


def _store_run(root: Path, attacks: dict[str, Sequence[Trial]]) -> tuple[RunStore, str]:
    store = RunStore(root)
    meta = RunMetadata(
        run_id=new_run_id(),
        scanner_version="0.0.1",
        config_hash="c" * 64,
        target="playground",
        variant="fixed",
        started_at=datetime(2026, 10, 5, tzinfo=UTC),
    )
    chain = EvidenceChain()
    for attack_id, trials in attacks.items():
        for t in trials:
            record_trial(chain, attack_id, t)
    store.save(meta, chain, [])
    return store, meta.run_id


def _regress(store: RunStore, run_id: str, *extra: str) -> tuple[int, str]:
    result = runner.invoke(
        app, ["regression", "--run", run_id, "--results-dir", str(store.root), *extra]
    )
    return result.exit_code, result.output


@pytest.mark.parametrize(
    ("attacks", "code"),
    [
        ({"x1": _trials(30)}, ExitCode.OK),
        ({"x1": _trials(30, breaches=1)}, ExitCode.POLICY_VIOLATION),
        ({"x1": _trials(10)}, ExitCode.INCONCLUSIVE),
        ({"x1": _trials(10), "api1": _trials(30, breaches=2)}, ExitCode.POLICY_VIOLATION),
        ({}, ExitCode.INCONCLUSIVE),
    ],
)
def test_regression_exit_codes(
    tmp_path: Path, attacks: dict[str, list[Trial]], code: ExitCode
) -> None:
    store, run_id = _store_run(tmp_path, attacks)
    exit_code, output = _regress(store, run_id)
    assert exit_code == code, output


def test_regression_threshold_changes_required_n(tmp_path: Path) -> None:
    store, run_id = _store_run(tmp_path, {"x1": _trials(10)})
    assert _regress(store, run_id, "--threshold", "0.3")[0] == ExitCode.OK


def test_regression_output_shows_metrics(tmp_path: Path) -> None:
    store, run_id = _store_run(tmp_path, {"x1": _trials(10, breaches=6, induced=8)})
    _, output = _regress(store, run_id)
    for expected in ("FAIL", "6/10", "8/10", "25%"):
        assert expected in output


@pytest.mark.parametrize("threshold", ["0", "1.5", "-0.1"])
def test_regression_rejects_bad_threshold(tmp_path: Path, threshold: str) -> None:
    store, run_id = _store_run(tmp_path, {"x1": _trials(30)})
    assert _regress(store, run_id, "--threshold", threshold)[0] == ExitCode.ERROR


def test_regression_refuses_tampered_trials(tmp_path: Path) -> None:
    store, run_id = _store_run(tmp_path, {"x1": _trials(30, breaches=1)})
    evidence = store.run_dir(run_id) / "evidence.jsonl"
    # Flip the one breach to clean: the verdict would become PASS if it were trusted.
    original = evidence.read_text(encoding="utf-8")
    tampered = original.replace('"positive":true', '"positive":false')
    assert tampered != original
    evidence.write_text(tampered, encoding="utf-8")
    assert _regress(store, run_id)[0] == ExitCode.ERROR


def test_regression_duplicate_trials_exit_2(tmp_path: Path) -> None:
    store, run_id = _store_run(tmp_path, {"x1": [_trial(0), _trial(0)]})
    assert _regress(store, run_id)[0] == ExitCode.ERROR

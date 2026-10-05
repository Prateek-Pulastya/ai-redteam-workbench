from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from airteam.core.measurement import (
    MeasurementCard,
    MeasurementCardError,
    load_measurement_card,
)
from airteam.core.oracles import OracleKind

# The §0A.6 example, with placeholders filled in.
SPEC_CARD = """\
asr_definition:
  unit: trial
  success_condition: oracle:server_state
  eligible_population: all scenarios in split=public, variant=vulnerable
trials_per_scenario: 10
models: [ { id: mock, digest: seed-1337, provider: mock } ]
temperature: 0.0
judge: none
dataset: { name: airteam-bench, version: 0.1.0, sha256: DATASET_SHA }
scanner: { version: 0.1.0, git_commit: 6547ba5 }
ci_method: wilson_95
protocol_commit: 6547ba5
""".replace("DATASET_SHA", "a" * 64)


def _card(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "asr_definition": {
            "unit": "trial",
            "success_condition": "oracle:canary",
            "eligible_population": "all",
        },
        "trials_per_scenario": 10,
        "models": [{"id": "mock", "digest": "seed-1337", "provider": "mock"}],
        "temperature": 0.0,
        "dataset": {"name": "airteam-bench", "version": "0.1.0", "sha256": "a" * 64},
        "scanner": {"version": "0.1.0", "git_commit": "6547ba5"},
        "protocol_commit": "6547ba5",
    }
    return base | overrides


def test_spec_example_loads(tmp_path: Path) -> None:
    path = tmp_path / "card.yaml"
    path.write_text(SPEC_CARD, encoding="utf-8")
    card = load_measurement_card(path)
    assert card.judge is None
    assert card.asr_definition.oracle is OracleKind.SERVER_STATE
    assert card.ci_method == "wilson_95"


def test_round_trips_through_json() -> None:
    card = MeasurementCard.model_validate(_card())
    assert MeasurementCard.model_validate_json(card.model_dump_json()) == card


@pytest.mark.parametrize("condition", ["server_state", "oracle:", "oracle:vibes", "judge:canary"])
def test_rejects_undeclared_success_condition(condition: str) -> None:
    asr = {"unit": "trial", "success_condition": condition, "eligible_population": "all"}
    with pytest.raises(ValidationError, match="success_condition"):
        MeasurementCard.model_validate(_card(asr_definition=asr))


def test_judge_success_condition_requires_judge() -> None:
    asr = {"unit": "trial", "success_condition": "oracle:judge", "eligible_population": "all"}
    with pytest.raises(ValidationError, match="requires a judge"):
        MeasurementCard.model_validate(_card(asr_definition=asr))
    judge = {
        "model": {"id": "judge", "digest": "d", "provider": "ollama"},
        "prompt_hash": "c" * 64,
        "temperature": 0.0,
    }
    MeasurementCard.model_validate(_card(asr_definition=asr, judge=judge))


@pytest.mark.parametrize(
    "overrides",
    [
        {"models": []},
        {"trials_per_scenario": 0},
        {"protocol_commit": "HEAD"},
        {"dataset": {"name": "x", "version": "1", "sha256": "short"}},
        {"ci_method": "normal_approx"},
        {"unexpected": True},
        {"models": [{"id": "m", "digest": "d", "provider": "p"}] * 2},
    ],
)
def test_rejects_incomplete_or_invalid_cards(overrides: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        MeasurementCard.model_validate(_card(**overrides))


def test_load_reports_invalid_file(tmp_path: Path) -> None:
    path = tmp_path / "card.yaml"
    path.write_text("- not a mapping\n", encoding="utf-8")
    with pytest.raises(MeasurementCardError, match="mapping"):
        load_measurement_card(path)
    path.write_text("trials_per_scenario: 10\n", encoding="utf-8")
    with pytest.raises(MeasurementCardError, match="invalid measurement card"):
        load_measurement_card(path)

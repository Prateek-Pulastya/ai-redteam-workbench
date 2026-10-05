import json
from datetime import UTC, datetime

import pytest

from airteam.core.evidence import GENESIS_HASH
from airteam.core.exit_codes import ExitCode, exit_code_for_verdicts
from airteam.core.findings import Reproducibility
from airteam.core.runs import RunMetadata
from airteam.core.stats import Verdict
from airteam.core.storage import RunStore
from airteam.reports.json import REPORT, RunReport, build_report, write_json_report

WHEN = datetime(2026, 10, 5, 12, tzinfo=UTC)


def test_report_written_beside_run(stored_run: tuple[RunStore, RunMetadata]) -> None:
    store, meta = stored_run
    path = write_json_report(store, meta.run_id, generated_at=WHEN)
    assert path == store.run_dir(meta.run_id) / REPORT

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["schema_version"] == "1"
    assert raw["evidence"] == {
        "records": 2,
        "head": store.load(meta.run_id)[1][-1].record_hash,
        "verified": True,
    }
    assert raw["summary"]["total"] == 2
    assert raw["summary"]["by_severity"]["critical"] == 1
    assert raw["summary"]["by_severity"]["low"] == 0
    # Most severe first, regardless of stored order.
    assert [f["finding_id"] for f in raw["findings"]] == ["F-001", "F-002"]
    repro = raw["findings"][0]["reproducibility"]
    assert repro["hits"] == 7
    assert repro["valid_trials"] == 10
    assert repro["ci95"]["lower"] == pytest.approx(0.3968, abs=5e-4)
    assert repro["ci95"]["upper"] == pytest.approx(0.8922, abs=5e-4)


def test_report_round_trips(stored_run: tuple[RunStore, RunMetadata]) -> None:
    store, meta = stored_run
    path = write_json_report(store, meta.run_id, generated_at=WHEN)
    report = RunReport.model_validate_json(path.read_text(encoding="utf-8"))
    assert report.run == meta
    assert report.generated_at == WHEN


def test_report_is_deterministic(stored_run: tuple[RunStore, RunMetadata]) -> None:
    store, meta = stored_run
    first = write_json_report(store, meta.run_id, generated_at=WHEN).read_bytes()
    second = write_json_report(store, meta.run_id, generated_at=WHEN).read_bytes()
    assert first == second


def test_empty_run_report(stored_run: tuple[RunStore, RunMetadata]) -> None:
    _, meta = stored_run
    report = build_report(meta, [], [], generated_at=WHEN)
    assert report.evidence.head == GENESIS_HASH
    assert report.summary.total == 0


def test_reproducibility_round_trips_with_derived_fields() -> None:
    repro = Reproducibility(hits=3, valid_trials=4)
    dumped = repro.model_dump(mode="json")
    assert set(dumped) == {"hits", "valid_trials", "rate", "ci95"}
    assert Reproducibility.model_validate(dumped) == repro
    assert Reproducibility(hits=0, valid_trials=0).ci95 is None


def test_reproducibility_rejects_more_hits_than_trials() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        Reproducibility(hits=5, valid_trials=4)


@pytest.mark.parametrize(
    ("verdicts", "code"),
    [
        ([Verdict.PASS, Verdict.PASS], ExitCode.OK),
        ([Verdict.PASS, Verdict.FAIL], ExitCode.POLICY_VIOLATION),
        ([Verdict.PASS, Verdict.INCONCLUSIVE], ExitCode.INCONCLUSIVE),
        ([Verdict.INCONCLUSIVE, Verdict.FAIL], ExitCode.POLICY_VIOLATION),
        ([], ExitCode.INCONCLUSIVE),
    ],
)
def test_exit_code_for_verdicts(verdicts: list[Verdict], code: ExitCode) -> None:
    assert exit_code_for_verdicts(verdicts) is code

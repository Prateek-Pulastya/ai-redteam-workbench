from datetime import UTC, datetime
from pathlib import Path

import pytest

from airteam.core.evidence import EvidenceChain
from airteam.core.runs import RunMetadata, new_run_id
from airteam.core.storage import EVIDENCE, FINDINGS, RunStore, StorageError


def _meta() -> RunMetadata:
    return RunMetadata(
        run_id=new_run_id(),
        scanner_version="0.0.1",
        config_hash="b" * 64,
        target="playground",
        variant="fixed",
        started_at=datetime.now(UTC),
    )


def _chain() -> EvidenceChain:
    chain = EvidenceChain()
    chain.append("request", {"path": "/orders/101", "identity": "user_a"})
    chain.append("response", {"status": 200})
    return chain


def test_round_trip(tmp_path: Path) -> None:
    store = RunStore(tmp_path)
    meta, chain = _meta(), _chain()
    store.save(meta, chain, [])
    loaded_meta, records, findings = store.load(meta.run_id)
    assert loaded_meta == meta
    assert records == chain.records
    assert findings == []


def test_refuses_to_overwrite_existing_run(tmp_path: Path) -> None:
    store = RunStore(tmp_path)
    meta = _meta()
    store.save(meta, _chain(), [])
    with pytest.raises(FileExistsError):
        store.save(meta, _chain(), [])


def test_edited_evidence_fails_to_load(tmp_path: Path) -> None:
    store = RunStore(tmp_path)
    meta = _meta()
    path = store.save(meta, _chain(), [])
    evidence = path / EVIDENCE
    evidence.write_text(evidence.read_text().replace("200", "403"), encoding="utf-8")
    with pytest.raises(StorageError, match="verification"):
        store.load(meta.run_id)


def test_run_id_cannot_escape_root(tmp_path: Path) -> None:
    with pytest.raises(StorageError, match="escapes"):
        RunStore(tmp_path / "results").run_dir("../outside")


def test_findings_round_trip(stored_run: tuple[RunStore, RunMetadata]) -> None:
    store, meta = stored_run
    _, _, findings = store.load(meta.run_id)
    assert [f.finding_id for f in findings] == ["F-002", "F-001"]
    assert findings[0].reproducibility.hits == 7


def test_malformed_findings_is_storage_error(stored_run: tuple[RunStore, RunMetadata]) -> None:
    store, meta = stored_run
    (store.run_dir(meta.run_id) / FINDINGS).write_text('[{"finding_id": ""}]', encoding="utf-8")
    with pytest.raises(StorageError, match="malformed"):
        store.load(meta.run_id)


def test_missing_run_is_storage_error(tmp_path: Path) -> None:
    with pytest.raises(StorageError, match="cannot load"):
        RunStore(tmp_path).load("run-20260101T000000Z-abcdef")

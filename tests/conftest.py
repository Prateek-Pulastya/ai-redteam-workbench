from datetime import UTC, datetime
from pathlib import Path

import pytest

from airteam.core.evidence import EvidenceChain
from airteam.core.findings import Confidence, Finding, Reproducibility, Severity
from airteam.core.runs import RunMetadata, new_run_id
from airteam.core.storage import RunStore


def make_finding(finding_id: str = "F-001", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        finding_id=finding_id,
        severity=severity,
        confidence=Confidence.CONFIRMED,
        category="api1-bola",
        attack_id="x1-doc-to-bola",
        property_id="no-cross-owner-read",
        target="playground",
        variant="vulnerable",
        summary="user_a read order 201 owned by user_b",
        observed_behavior="200 with order 201",
        expected_behavior="403",
        reproducibility=Reproducibility(hits=7, valid_trials=10),
        trigger="Indirect Prompt Injection",
        root_vulnerability="BOLA (API1:2023)",
    )


@pytest.fixture
def stored_run(tmp_path: Path) -> tuple[RunStore, RunMetadata]:
    store = RunStore(tmp_path / "results")
    meta = RunMetadata(
        run_id=new_run_id(),
        scanner_version="0.0.1",
        config_hash="b" * 64,
        target="playground",
        variant="vulnerable",
        model_ids=("mock@seed=1337",),
        seed=1337,
        started_at=datetime(2026, 10, 5, tzinfo=UTC),
    )
    chain = EvidenceChain()
    chain.append("request", {"path": "/orders/201", "identity": "user_a"})
    chain.append("response", {"status": 200, "body": "[bold]x[/bold]"})
    findings = [make_finding("F-002", Severity.MEDIUM), make_finding("F-001", Severity.CRITICAL)]
    store.save(meta, chain, findings)
    return store, meta

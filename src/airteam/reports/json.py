"""JSON run report: the machine-readable source of truth for a stored run (spec §27).

The report is built only from what :class:`~airteam.core.storage.RunStore` loads,
so the evidence chain has already been verified by the time a report exists.
"""

from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field

from airteam import __version__
from airteam.core.base import StrictModel
from airteam.core.evidence import GENESIS_HASH, EvidenceRecord
from airteam.core.findings import Confidence, Finding, Severity, most_severe_first
from airteam.core.runs import RunMetadata
from airteam.core.storage import RunStore

REPORT = "report.json"


class EvidenceSummary(StrictModel):
    records: int = Field(ge=0)
    head: str
    verified: bool
    """Always true: unverifiable runs fail to load and never reach the writer."""


class FindingCounts(StrictModel):
    total: int = Field(ge=0)
    by_severity: dict[Severity, int]
    by_confidence: dict[Confidence, int]


class RunReport(StrictModel):
    schema_version: Literal["1"] = "1"
    generated_at: datetime
    generator_version: str
    run: RunMetadata
    evidence: EvidenceSummary
    summary: FindingCounts
    findings: tuple[Finding, ...]


def build_report(
    meta: RunMetadata,
    records: Sequence[EvidenceRecord],
    findings: Sequence[Finding],
    generated_at: datetime | None = None,
) -> RunReport:
    severities = Counter(f.severity for f in findings)
    confidences = Counter(f.confidence for f in findings)
    return RunReport(
        generated_at=generated_at or datetime.now(UTC),
        generator_version=__version__,
        run=meta,
        evidence=EvidenceSummary(
            records=len(records),
            head=records[-1].record_hash if records else GENESIS_HASH,
            verified=True,
        ),
        summary=FindingCounts(
            total=len(findings),
            by_severity={s: severities[s] for s in Severity},
            by_confidence={c: confidences[c] for c in Confidence},
        ),
        findings=tuple(most_severe_first(findings)),
    )


def write_json_report(store: RunStore, run_id: str, generated_at: datetime | None = None) -> Path:
    """Load ``run_id`` (verifying its evidence) and write ``report.json`` beside it."""
    meta, records, findings = store.load(run_id)
    report = build_report(meta, records, findings, generated_at)
    path = store.run_dir(run_id) / REPORT
    path.write_text(report.model_dump_json(indent=2) + "\n", encoding="utf-8")
    return path

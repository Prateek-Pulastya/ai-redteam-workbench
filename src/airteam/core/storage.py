"""On-disk layout for a run: ``<root>/<run_id>/{manifest.json, evidence.jsonl, findings.json}``."""

import json
from collections.abc import Sequence
from pathlib import Path

from airteam.core.evidence import EvidenceChain, EvidenceRecord, verify_chain
from airteam.core.findings import Finding
from airteam.core.runs import RunMetadata

MANIFEST = "manifest.json"
EVIDENCE = "evidence.jsonl"
FINDINGS = "findings.json"


class StorageError(Exception):
    """Raised when a run directory is missing, malformed, or fails verification."""


class RunStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def run_dir(self, run_id: str) -> Path:
        # Run IDs are validated by RunMetadata; resolve() guards against path tricks anyway.
        path = (self.root / run_id).resolve()
        if path.parent != self.root.resolve():
            raise StorageError(f"run id {run_id!r} escapes the results directory")
        return path

    def save(self, meta: RunMetadata, chain: EvidenceChain, findings: Sequence[Finding]) -> Path:
        path = self.run_dir(meta.run_id)
        path.mkdir(parents=True, exist_ok=False)
        manifest = meta.model_dump(mode="json") | {"evidence_head": chain.head}
        (path / MANIFEST).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        with (path / EVIDENCE).open("w", encoding="utf-8") as fh:
            for record in chain.records:
                fh.write(record.model_dump_json() + "\n")
        (path / FINDINGS).write_text(
            json.dumps([f.model_dump(mode="json") for f in findings], indent=2),
            encoding="utf-8",
        )
        return path

    def load(self, run_id: str) -> tuple[RunMetadata, tuple[EvidenceRecord, ...], list[Finding]]:
        path = self.run_dir(run_id)
        try:
            manifest = json.loads((path / MANIFEST).read_text(encoding="utf-8"))
            lines = (path / EVIDENCE).read_text(encoding="utf-8").splitlines()
            raw_findings = json.loads((path / FINDINGS).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise StorageError(f"cannot load run {run_id}: {exc}") from exc

        head = manifest.pop("evidence_head", None)
        meta = RunMetadata.model_validate(manifest)
        records = tuple(EvidenceRecord.model_validate_json(line) for line in lines if line)
        if not verify_chain(records):
            raise StorageError(f"evidence chain for {run_id} failed verification")
        actual_head = records[-1].record_hash if records else None
        if records and head != actual_head:
            raise StorageError(f"evidence head mismatch for {run_id}")
        findings = [Finding.model_validate(f) for f in raw_findings]
        return meta, records, findings

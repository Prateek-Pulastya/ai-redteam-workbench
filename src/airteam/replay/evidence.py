"""``replay --evidence``: render a recorded run from disk. No network, no target.

Input comes from :meth:`RunStore.load`, which has already verified the evidence
chain, so everything shown here is exactly what was recorded.
"""

from collections.abc import Sequence

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from airteam.core.evidence import EvidenceRecord
from airteam.core.findings import Finding, most_severe_first
from airteam.core.hashing import canonical_json
from airteam.core.runs import RunMetadata

PAYLOAD_PREVIEW = 120


def _short(digest: str) -> str:
    return f"{digest[:12]}…"


def _payload(record: EvidenceRecord, full: bool) -> str:
    text = canonical_json(record.payload)
    if not full and len(text) > PAYLOAD_PREVIEW:
        text = text[:PAYLOAD_PREVIEW] + "…"
    return escape(text)


def render_evidence(
    console: Console,
    meta: RunMetadata,
    records: Sequence[EvidenceRecord],
    findings: Sequence[Finding],
    *,
    full: bool = False,
) -> None:
    console.print(
        f"[bold]Replay (evidence) — {escape(meta.run_id)}[/]  recorded data only, no network"
    )
    console.print(f"Target: {escape(meta.target)}   Variant: {meta.variant}")
    if meta.model_ids:
        console.print(f"Models: {escape(', '.join(meta.model_ids))}")
    console.print(
        f"Scanner: {escape(meta.scanner_version)}"
        + (f" ({escape(meta.git_commit)})" if meta.git_commit else "")
        + f"   Config: {_short(meta.config_hash)}"
        + (f"   Seed: {meta.seed}" if meta.seed is not None else "")
    )
    console.print(f"Started: {meta.started_at.isoformat()}")
    head = _short(records[-1].record_hash) if records else "empty"
    console.print(f"Evidence chain: [green]verified[/] ({len(records)} records, head {head})")

    if records:
        table = Table(title="Evidence")
        table.add_column("seq", justify="right")
        table.add_column("kind")
        table.add_column("hash")
        table.add_column("payload", overflow="fold")
        for r in records:
            table.add_row(str(r.seq), escape(r.kind), _short(r.record_hash), _payload(r, full))
        console.print(table)

    if not findings:
        console.print("Findings: none recorded")
        return
    table = Table(title=f"Findings ({len(findings)})")
    for column in ("id", "severity", "confidence", "attack", "repro", "95% CI", "summary"):
        table.add_column(column, overflow="fold")
    findings = most_severe_first(findings)
    for f in findings:
        ci = f.reproducibility.ci95
        table.add_row(
            escape(f.finding_id),
            f.severity.value.upper(),
            f.confidence.value,
            f.attack_id,
            str(f.reproducibility),
            escape(str(ci)) if ci is not None else "-",
            escape(f.summary),
        )
    console.print(table)
    for f in findings:
        if f.trigger or f.root_vulnerability:
            console.print(
                f"  {escape(f.finding_id)}: Trigger: {escape(f.trigger or '-')}   "
                f"Root: {escape(f.root_vulnerability or '-')}"
            )

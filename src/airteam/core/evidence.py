"""Append-only, hash-chained evidence records (spec §19, §0A.9).

Each record stores ``sha256(prev_hash + canonical(seq, kind, payload))``. Changing,
removing, or reordering any record breaks verification from that point on.
Redaction must happen *before* a payload is appended.
"""

from collections.abc import Iterable

from pydantic import Field, JsonValue

from airteam.core.base import StrictModel
from airteam.core.hashing import canonical_json, sha256_hex

GENESIS_HASH = "0" * 64


def _digest(prev_hash: str, seq: int, kind: str, payload: dict[str, JsonValue]) -> str:
    body = canonical_json({"seq": seq, "kind": kind, "payload": payload})
    return sha256_hex(prev_hash + body)


class EvidenceRecord(StrictModel):
    seq: int = Field(ge=0)
    kind: str = Field(min_length=1)
    payload: dict[str, JsonValue]
    prev_hash: str
    record_hash: str


class EvidenceChain:
    def __init__(self) -> None:
        self._records: list[EvidenceRecord] = []

    @property
    def head(self) -> str:
        return self._records[-1].record_hash if self._records else GENESIS_HASH

    @property
    def records(self) -> tuple[EvidenceRecord, ...]:
        return tuple(self._records)

    def append(self, kind: str, payload: dict[str, JsonValue]) -> EvidenceRecord:
        seq = len(self._records)
        prev = self.head
        record = EvidenceRecord(
            seq=seq,
            kind=kind,
            payload=payload,
            prev_hash=prev,
            record_hash=_digest(prev, seq, kind, payload),
        )
        self._records.append(record)
        return record


def verify_chain(records: Iterable[EvidenceRecord]) -> bool:
    prev = GENESIS_HASH
    for expected_seq, record in enumerate(records):
        if record.seq != expected_seq or record.prev_hash != prev:
            return False
        if record.record_hash != _digest(prev, record.seq, record.kind, record.payload):
            return False
        prev = record.record_hash
    return True

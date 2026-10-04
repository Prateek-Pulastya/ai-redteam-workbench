"""Oracles decide whether a security property was violated (spec §0A.4).

An oracle verdict is independent of whatever the model *says*: a canary match,
a server-side authorization log, or a response diff against the ownership map.
"""

from enum import StrEnum

from pydantic import Field

from airteam.core.base import StrictModel


class OracleKind(StrEnum):
    CANARY = "canary"
    SERVER_STATE = "server_state"
    RESPONSE_DIFF = "response_diff"
    SCHEMA = "schema"
    HEURISTIC = "heuristic"
    """Pattern-based detector; a supporting signal, not an oracle verdict."""
    JUDGE = "judge"
    """LLM judge; a supporting signal only (spec §56.4)."""

    @property
    def deterministic(self) -> bool:
        return self not in {OracleKind.HEURISTIC, OracleKind.JUDGE}


class OracleResult(StrictModel):
    oracle: OracleKind
    positive: bool
    reason: str = Field(min_length=1)
    """Why the oracle decided this, in a form a reviewer can check."""

"""Trials: one execution of an attack. Findings aggregate over trials (spec §0A.3)."""

from pydantic import Field

from airteam.core.base import StrictModel
from airteam.core.oracles import OracleKind, OracleResult


class Trial(StrictModel):
    index: int = Field(ge=0)
    oracle_results: tuple[OracleResult, ...] = ()
    induced: bool | None = None
    """Whether the model attempted the unsafe action; ``None`` when not observable."""
    error: str | None = None
    """Set when the trial could not complete (timeout, target error, budget)."""

    @property
    def valid(self) -> bool:
        return self.error is None

    @property
    def breached(self) -> bool:
        """True only when a deterministic oracle confirmed the violation."""
        return self.valid and any(
            r.positive and r.oracle.deterministic for r in self.oracle_results
        )

    def signalled_by(self, kind: OracleKind) -> bool:
        return self.valid and any(r.positive and r.oracle is kind for r in self.oracle_results)

"""Trials: one execution of an attack. Findings aggregate over trials (spec §0A.3)."""

from collections.abc import Iterable

from pydantic import Field, ValidationError

from airteam.core.base import StrictModel
from airteam.core.evidence import EvidenceChain, EvidenceRecord
from airteam.core.oracles import OracleKind, OracleResult

TRIAL_RECORD_KIND = "trial"


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


class TrialRecordError(ValueError):
    """Raised when trial records in an evidence chain are malformed or duplicated."""


def record_trial(chain: EvidenceChain, attack_id: str, trial: Trial) -> EvidenceRecord:
    """Append a trial outcome to the evidence chain.

    Verdicts are computed from these records, so they share the chain's tamper
    evidence instead of living in a separate, unhashed file.
    """
    return chain.append(
        TRIAL_RECORD_KIND, {"attack_id": attack_id, "trial": trial.model_dump(mode="json")}
    )


def trials_by_attack(records: Iterable[EvidenceRecord]) -> dict[str, list[Trial]]:
    """Group the trial records of a (verified) chain by attack, in recorded order."""
    grouped: dict[str, list[Trial]] = {}
    for record in records:
        if record.kind != TRIAL_RECORD_KIND:
            continue
        attack_id = record.payload.get("attack_id")
        if not isinstance(attack_id, str) or not attack_id:
            raise TrialRecordError(f"evidence record {record.seq} has no attack_id")
        try:
            trial = Trial.model_validate(record.payload.get("trial"))
        except ValidationError as exc:
            raise TrialRecordError(f"evidence record {record.seq} is not a trial: {exc}") from exc
        trials = grouped.setdefault(attack_id, [])
        if any(t.index == trial.index for t in trials):
            raise TrialRecordError(
                f"evidence record {record.seq} repeats trial {trial.index} of {attack_id}"
            )
        trials.append(trial)
    return grouped

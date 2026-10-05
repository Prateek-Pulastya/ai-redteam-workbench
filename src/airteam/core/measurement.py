"""Measurement Card: the declared definition behind every published rate (spec §0A.6).

No benchmark number is meaningful without saying what counted as success, over
which population, with how many trials, against which model build. The card
captures that, and it is validated so a half-filled card cannot be published.
"""

from enum import StrEnum
from pathlib import Path
from typing import Any, Self

import yaml
from pydantic import Field, ValidationError, field_validator, model_validator

from airteam.core.base import StrictModel
from airteam.core.oracles import OracleKind

_SHA256 = r"^[0-9a-f]{64}$"
_GIT_COMMIT = r"^[0-9a-f]{7,40}$"


class AsrUnit(StrEnum):
    TRIAL = "trial"
    SCENARIO = "scenario"
    CONVERSATION = "conversation"


class CiMethod(StrEnum):
    WILSON_95 = "wilson_95"


class AsrDefinition(StrictModel):
    unit: AsrUnit
    success_condition: str
    """``oracle:<kind>``, e.g. ``oracle:server_state``."""
    eligible_population: str = Field(min_length=1)

    @field_validator("success_condition")
    @classmethod
    def _oracle_condition(cls, value: str) -> str:
        prefix, _, kind = value.partition(":")
        if prefix != "oracle" or kind not in OracleKind.__members__.values():
            allowed = ", ".join(f"oracle:{k.value}" for k in OracleKind)
            raise ValueError(f"success_condition must be one of {allowed}; got {value!r}")
        return value

    @property
    def oracle(self) -> OracleKind:
        return OracleKind(self.success_condition.partition(":")[2])


class ModelRef(StrictModel):
    id: str = Field(min_length=1)
    digest: str = Field(min_length=1)
    """Exact build: weights digest, API snapshot ID, or mock seed."""
    provider: str = Field(min_length=1)


class JudgeRef(StrictModel):
    """Judge governance fields (spec §0A.4)."""

    model: ModelRef
    prompt_hash: str = Field(pattern=_SHA256)
    temperature: float = Field(ge=0.0, le=2.0)


class DatasetRef(StrictModel):
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    sha256: str = Field(pattern=_SHA256)


class ScannerRef(StrictModel):
    version: str = Field(min_length=1)
    git_commit: str = Field(pattern=_GIT_COMMIT)


class MeasurementCard(StrictModel):
    asr_definition: AsrDefinition
    trials_per_scenario: int = Field(ge=1)
    models: tuple[ModelRef, ...] = Field(min_length=1)
    temperature: float = Field(ge=0.0, le=2.0)
    judge: JudgeRef | None = None
    dataset: DatasetRef
    scanner: ScannerRef
    ci_method: CiMethod = CiMethod.WILSON_95
    protocol_commit: str = Field(pattern=_GIT_COMMIT)
    """Commit of ``docs/benchmark-protocol.md``, made before the run (spec §0A.17)."""

    @field_validator("judge", mode="before")
    @classmethod
    def _none_judge(cls, value: Any) -> Any:
        # The spec writes ``judge: none`` in YAML, which parses as the string "none".
        return None if value == "none" else value

    @model_validator(mode="after")
    def _judge_declared_when_used(self) -> Self:
        if self.asr_definition.oracle is OracleKind.JUDGE and self.judge is None:
            raise ValueError("success_condition oracle:judge requires a judge entry")
        return self

    @model_validator(mode="after")
    def _unique_models(self) -> Self:
        keys = [(m.provider, m.id, m.digest) for m in self.models]
        if len(keys) != len(set(keys)):
            raise ValueError("models contains duplicate entries")
        return self


class MeasurementCardError(Exception):
    """Raised when a measurement card file cannot be read or is invalid."""


def load_measurement_card(path: Path) -> MeasurementCard:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise MeasurementCardError(f"cannot read measurement card {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise MeasurementCardError(f"{path} must contain a YAML mapping at the top level")
    try:
        return MeasurementCard.model_validate(raw)
    except ValidationError as exc:
        raise MeasurementCardError(f"invalid measurement card {path}:\n{exc}") from exc

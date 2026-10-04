"""Attack definitions and their execution policy (spec §18, §0A.5)."""

import re
from typing import Any, Literal, Self

from pydantic import Field, field_validator, model_validator

from airteam.core.base import Slug, StrictModel
from airteam.core.frameworks import FrameworkMapping

_K_OF_N = re.compile(r"^k_of_n\((\d+)\)$")


class SuccessRule(StrictModel):
    """Minimum number of breached trials for the attack to count as successful."""

    k: int = Field(default=1, ge=1)

    @classmethod
    def parse(cls, value: str) -> "SuccessRule":
        if value == "any":
            return cls(k=1)
        match = _K_OF_N.match(value)
        if match is None:
            raise ValueError(f"success_rule must be 'any' or 'k_of_n(<k>)', got {value!r}")
        return cls(k=int(match.group(1)))


class ExecutionPolicy(StrictModel):
    trials: int = Field(default=10, ge=1, le=10_000)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    seed: int | None = 1337
    success_rule: SuccessRule = SuccessRule()

    @field_validator("success_rule", mode="before")
    @classmethod
    def _parse_rule(cls, value: Any) -> Any:
        return SuccessRule.parse(value) if isinstance(value, str) else value

    @model_validator(mode="after")
    def _k_within_trials(self) -> Self:
        if self.success_rule.k > self.trials:
            raise ValueError(f"success_rule k={self.success_rule.k} exceeds trials={self.trials}")
        return self


class Attack(StrictModel):
    id: Slug
    name: str = Field(min_length=1)
    category: Slug
    objective: str = Field(min_length=1)
    property_id: Slug
    """The primary security property this attack tries to violate."""
    difficulty: Literal["basic", "intermediate", "advanced"] = "basic"
    execution: ExecutionPolicy = ExecutionPolicy()
    frameworks: tuple[FrameworkMapping, ...] = ()

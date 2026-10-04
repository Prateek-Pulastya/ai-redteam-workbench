"""Security properties: what must never happen (spec §0A.3)."""

from pydantic import Field

from airteam.core.base import Slug, StrictModel
from airteam.core.frameworks import FrameworkMapping
from airteam.core.oracles import OracleKind


class CrossOwnerRead(StrictModel):
    """An identity receives a resource owned by a different identity."""

    actor: str = "any_identity"
    receives_resource_owned_by: str = Field(min_length=1)


class CanaryEgress(StrictModel):
    """A synthetic canary appears in an output channel."""

    output_contains_canary: str = Field(min_length=1)


PropertyCondition = CrossOwnerRead | CanaryEgress


class SecurityProperty(StrictModel):
    id: Slug
    description: str = Field(min_length=1)
    never: PropertyCondition
    oracle: OracleKind
    frameworks: tuple[FrameworkMapping, ...] = ()

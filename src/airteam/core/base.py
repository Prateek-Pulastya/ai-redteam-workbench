"""Shared model base classes and constrained types."""

from typing import Annotated

from pydantic import BaseModel, ConfigDict, StringConstraints

Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]*$", max_length=128)]
"""Lower-case identifier used for attacks, properties, controls and variants."""


class StrictModel(BaseModel):
    """Immutable model that rejects unknown fields.

    Unknown fields are rejected so that typos in YAML (or a stray ``token:`` key)
    fail loudly instead of being silently ignored.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

"""Controls: the defenses whose presence or absence is under test (spec §0A.3)."""

from pydantic import Field

from airteam.core.base import Slug, StrictModel


class Control(StrictModel):
    id: Slug
    description: str = Field(min_length=1)
    layer: str | None = None
    """Where the control lives, e.g. ``api``, ``rag``, ``agent``."""

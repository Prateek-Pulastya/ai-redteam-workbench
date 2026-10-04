"""Run metadata required for reproducibility (spec §22)."""

import secrets
from datetime import UTC, datetime

from pydantic import Field

from airteam.core.base import Slug, StrictModel


def new_run_id(now: datetime | None = None) -> str:
    stamp = (now or datetime.now(UTC)).strftime("%Y%m%dT%H%M%SZ")
    return f"run-{stamp}-{secrets.token_hex(3)}"


class RunMetadata(StrictModel):
    run_id: str = Field(pattern=r"^run-\d{8}T\d{6}Z-[0-9a-f]{6}$")
    scanner_version: str
    git_commit: str | None = None
    config_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    target: str
    variant: Slug
    model_ids: tuple[str, ...] = ()
    dataset_version: str | None = None
    seed: int | None = None
    started_at: datetime

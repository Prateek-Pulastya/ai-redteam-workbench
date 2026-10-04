"""Versioned security-framework mappings (spec §4.3, §0A.12)."""

from enum import StrEnum

from pydantic import ConfigDict, Field

from airteam.core.base import StrictModel


class Framework(StrEnum):
    OWASP_API = "owasp_api"
    OWASP_GENAI = "owasp_genai"
    OWASP_AGENTIC = "owasp_agentic"
    MITRE_ATLAS = "mitre_atlas"
    NIST_AI_RMF = "nist_ai_rmf"


class FrameworkMapping(StrictModel):
    """A finding-to-framework link pinned to one framework edition.

    The version is always stored, so an old result is never silently reinterpreted
    when a framework publishes a new edition.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, coerce_numbers_to_str=True)

    framework: Framework
    version: str = Field(min_length=1)
    identifier: str = Field(min_length=1)

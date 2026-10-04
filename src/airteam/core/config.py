"""Assessment configuration (spec §9, §31, §0A.7).

Authorization is never inferred from reachability: every endpoint the scanner may
contact must be covered by ``target.authorization.scope``, and ``local`` mode only
permits loopback hosts.
"""

from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Self

import yaml
from pydantic import AnyHttpUrl, Field, ValidationError, field_validator, model_validator

from airteam.core.base import Slug, StrictModel
from airteam.core.findings import Severity
from airteam.core.hashing import canonical_json, sha256_hex

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


class ConfigError(Exception):
    """Raised when a configuration file cannot be loaded or is invalid."""


def is_loopback(host: str) -> bool:
    host = host.lower()
    return host in _LOOPBACK_HOSTS or host.endswith(".localhost")


def host_in_scope(host: str, scope: tuple[str, ...]) -> bool:
    """Exact host match, or ``*.example.com`` matching strict subdomains only."""
    host = host.lower()
    for entry in scope:
        entry = entry.lower()
        if entry.startswith("*."):
            if host.endswith(entry[1:]):
                return True
        elif host == entry:
            return True
    return False


class AuthorizationMode(StrEnum):
    LOCAL = "local"
    """Loopback targets only: the bundled playground or the user's own dev server."""
    AUTHORIZED = "authorized"
    """Remote targets the user is explicitly authorized to test."""


class Authorization(StrictModel):
    mode: AuthorizationMode
    scope: tuple[str, ...] = Field(min_length=1)
    """Allowlisted hostnames. A bare string is accepted as a one-item list."""

    @field_validator("scope", mode="before")
    @classmethod
    def _scalar_to_tuple(cls, value: Any) -> Any:
        return (value,) if isinstance(value, str) else value

    @model_validator(mode="after")
    def _local_means_loopback(self) -> Self:
        if self.mode is AuthorizationMode.LOCAL:
            remote = [h for h in self.scope if not is_loopback(h)]
            if remote:
                raise ValueError(
                    f"authorization mode 'local' allows only loopback hosts; got {remote}. "
                    "Use mode 'authorized' for remote targets you are permitted to test."
                )
        return self


class TargetKind(StrEnum):
    API = "api"
    LLM = "llm"
    RAG = "rag"
    AGENT = "agent"
    HYBRID = "hybrid"


class TargetConfig(StrictModel):
    name: Slug
    type: TargetKind
    endpoint: AnyHttpUrl
    variant: Slug = "default"
    authorization: Authorization


class Identity(StrictModel):
    name: Slug
    token_env: str = Field(pattern=r"^[A-Z_][A-Z0-9_]*$")
    """Name of the environment variable holding the token; never the token itself."""
    role: str | None = None


class OwnershipEntry(StrictModel):
    identity: Slug
    resources: dict[str, tuple[int | str, ...]]
    """Path template -> object IDs owned by this identity."""


class ApiConfig(StrictModel):
    openapi: Path | None = None
    identities: tuple[Identity, ...] = ()
    ownership: tuple[OwnershipEntry, ...] = ()
    seed_hook: Path | None = None

    @model_validator(mode="after")
    def _identities_consistent(self) -> Self:
        names = [i.name for i in self.identities]
        if len(names) != len(set(names)):
            raise ValueError("identity names must be unique")
        unknown = {o.identity for o in self.ownership} - set(names)
        if unknown:
            raise ValueError(f"ownership refers to undeclared identities: {sorted(unknown)}")
        return self


class AiConfig(StrictModel):
    endpoint: AnyHttpUrl | None = None
    provider: Literal["http", "openai_compatible", "mock"] = "mock"
    model: str | None = None


class ScanBudget(StrictModel):
    max_requests: int = Field(default=100, ge=1)
    max_tokens: int = Field(default=10_000, ge=1)
    max_concurrency: int = Field(default=4, ge=1)
    max_retries: int = Field(default=2, ge=0)
    timeout_seconds: float = Field(default=30.0, gt=0)
    rate_limit_per_second: float = Field(default=5.0, gt=0)
    max_run_seconds: float = Field(default=1800.0, gt=0)


class Policy(StrictModel):
    fail_on: tuple[Severity, ...] = (Severity.CRITICAL, Severity.HIGH)


class ProjectConfig(StrictModel):
    name: Slug


class AirteamConfig(StrictModel):
    project: ProjectConfig
    target: TargetConfig
    api: ApiConfig | None = None
    ai: AiConfig | None = None
    scan: ScanBudget = ScanBudget()
    policy: Policy = Policy()

    @model_validator(mode="after")
    def _endpoints_in_scope(self) -> Self:
        scope = self.target.authorization.scope
        endpoints = [self.target.endpoint]
        if self.ai is not None and self.ai.endpoint is not None:
            endpoints.append(self.ai.endpoint)
        for url in endpoints:
            if url.host is None or not host_in_scope(url.host, scope):
                raise ValueError(f"endpoint {url} is outside authorization scope {list(scope)}")
        return self

    def config_hash(self) -> str:
        return sha256_hex(canonical_json(self.model_dump(mode="json")))


def load_config(path: Path) -> AirteamConfig:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"{path} must contain a YAML mapping at the top level")
    try:
        return AirteamConfig.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(f"invalid configuration in {path}:\n{exc}") from exc

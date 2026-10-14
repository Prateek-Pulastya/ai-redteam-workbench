"""Case files: ``airteam/case@1`` YAML turned into runnable :class:`TrialCase` objects.

The format is specified in ``docs/case-format.md``. Case files are pure data: no
templating language, no imports, no code. Every check that can fail runs at load
time, so a broken case stops the scan before the first request is sent.
"""

import random
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    create_model,
    field_validator,
    model_validator,
)

from airteam.core.attacks import Attack
from airteam.core.base import Slug, StrictModel
from airteam.core.findings import Severity
from airteam.core.hashing import sha256_hex
from airteam.engine.runner import TrialCase
from airteam.oracles.base import Observation, Oracle
from airteam.oracles.canary import CanaryOracle, new_canary
from airteam.oracles.schema import SchemaOracle
from airteam.providers.base import CompletionRequest, Message

CASE_SCHEMA = "airteam/case@1"

Name = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*$", max_length=64)]
"""Canary and contract field names: no dots or dashes, so ``{{canary.a.b}}`` can't be ambiguous."""

_PLACEHOLDER = re.compile(r"\{\{\s*(canary\.[a-z][a-z0-9_]*|input|trial)\s*\}\}")
_HIDDEN_ROLES = frozenset({"system", "assistant", "tool"})
_NOT_IN_V1 = {
    "server_state": "needs the playground's oracle endpoint",
    "response_diff": "needs the ownership map and HTTP requests",
    "heuristic": "is not deterministic",
    "judge": "is not deterministic",
}


class CaseError(Exception):
    """A case file could not be loaded. The scan stops before any request is sent."""


class FindingSpec(StrictModel):
    severity: Severity
    expected_behavior: str = Field(min_length=1)
    remediation: str | None = None
    missing_control: Slug | None = None


class CanarySpec(StrictModel):
    name: Name
    value: str = Field(default="auto", min_length=1)
    """``auto`` or a literal canary of at least 12 alphanumerics."""

    @field_validator("value")
    @classmethod
    def _long_enough(cls, value: str) -> str:
        if value != "auto":
            CanaryOracle([value])  # raises on canaries short enough to match ordinary text
        return value


class MessageTemplate(StrictModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str


class RequestSpec(StrictModel):
    max_tokens: int = Field(default=512, ge=1)
    messages: tuple[MessageTemplate, ...] = Field(min_length=1)
    inputs: tuple[str, ...] = ()

    @field_validator("inputs")
    @classmethod
    def _plain_text(cls, inputs: tuple[str, ...]) -> tuple[str, ...]:
        for i, text in enumerate(inputs):
            if "{{" in text:
                raise ValueError(f"inputs[{i}] contains '{{{{': inputs are plain text")
        return inputs


class CanaryOracleSpec(StrictModel):
    kind: Literal["canary"]
    canaries: tuple[Name, ...] | None = None
    """Default: every canary declared in the file."""


class ContractField(StrictModel):
    type: Literal["string", "number", "integer", "boolean", "enum"]
    optional: bool = False
    max_length: int | None = Field(default=None, ge=1)
    min: float | None = None
    max: float | None = None
    values: tuple[str, ...] | None = None

    @model_validator(mode="after")
    def _keys_fit_type(self) -> Self:
        if self.max_length is not None and self.type != "string":
            raise ValueError("max_length applies only to type string")
        if (self.min is not None or self.max is not None) and self.type not in {
            "number",
            "integer",
        }:
            raise ValueError("min/max apply only to type number or integer")
        if self.min is not None and self.max is not None and self.min > self.max:
            raise ValueError(f"min {self.min} exceeds max {self.max}")
        if (self.values is not None) != (self.type == "enum"):
            raise ValueError("values is required for type enum and allowed only there")
        if self.values is not None and (
            not self.values or len(set(self.values)) != len(self.values)
        ):
            raise ValueError("enum values must be non-empty and unique")
        return self

    def annotation(self) -> Any:
        base: Any
        if self.type == "string":
            base = Annotated[str, Field(max_length=self.max_length)]
        elif self.type in {"number", "integer"}:
            kind = float if self.type == "number" else int
            base = Annotated[kind, Field(ge=self.min, le=self.max)]
        elif self.type == "boolean":
            base = bool
        else:
            base = Literal.__getitem__(self.values)  # Literal["a", "b", ...] from a tuple
        return base | None if self.optional else base


class Contract(StrictModel):
    fields: dict[Name, ContractField] = Field(min_length=1)
    allow_extra: bool = False

    @field_validator("fields")
    @classmethod
    def _no_model_prefix(cls, fields: dict[str, ContractField]) -> dict[str, ContractField]:
        clashing = [name for name in fields if name.startswith("model_")]
        if clashing:
            raise ValueError(f"field names must not start with 'model_': {clashing}")
        return fields

    def build(self, name: str) -> type[BaseModel]:
        # strict: lax mode would accept "0.5" as a number and hide real contract breaks.
        config = ConfigDict(strict=True, extra="allow" if self.allow_extra else "forbid")
        definitions: dict[str, Any] = {
            field: (spec.annotation(), None if spec.optional else ...)
            for field, spec in self.fields.items()
        }
        model: type[BaseModel] = create_model(name, __config__=config, **definitions)
        return model


class SchemaOracleSpec(StrictModel):
    kind: Literal["schema"]
    contract: Contract


OracleSpec = Annotated[CanaryOracleSpec | SchemaOracleSpec, Field(discriminator="kind")]


class Matcher(StrictModel):
    contains: str | None = Field(default=None, min_length=1)
    regex: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _exactly_one(self) -> Self:
        if (self.contains is None) == (self.regex is None):
            raise ValueError("a matcher needs exactly one of 'contains' or 'regex'")
        if self.regex is not None:
            try:
                re.compile(self.regex)
            except re.error as exc:
                raise ValueError(f"regex does not compile: {exc}") from exc
        return self

    def matches(self, text: str) -> bool:
        if self.contains is not None:
            return self.contains.casefold() in text.casefold()
        assert self.regex is not None  # noqa: S101 - guaranteed by _exactly_one
        return re.search(self.regex, text, re.IGNORECASE) is not None


class InductionSpec(StrictModel):
    any_of: tuple[Matcher, ...] = Field(min_length=1)

    def check(self, observation: Observation) -> bool:
        return any(m.matches(observation.text) for m in self.any_of)


class CaseFile(StrictModel):
    model_config = ConfigDict(populate_by_name=True)

    format: Literal["airteam/case@1"] = Field(alias="schema")
    attack: Attack
    finding: FindingSpec
    canaries: tuple[CanarySpec, ...] = ()
    request: RequestSpec
    oracles: tuple[OracleSpec, ...] = Field(min_length=1)
    induction: InductionSpec | None = None

    @field_validator("oracles", mode="before")
    @classmethod
    def _implemented_kinds(cls, oracles: Any) -> Any:
        for oracle in oracles if isinstance(oracles, list) else ():
            kind = oracle.get("kind") if isinstance(oracle, dict) else None
            if kind in _NOT_IN_V1:
                raise ValueError(
                    f"oracle kind {kind!r} is not available in v1: it {_NOT_IN_V1[kind]}"
                )
        return oracles

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        declared = [c.name for c in self.canaries]
        if len(declared) != len(set(declared)):
            raise ValueError(f"canary names must be unique: {declared}")

        hidden_refs: set[str] = set()
        uses_input = False
        for i, message in enumerate(self.request.messages):
            leftover = _PLACEHOLDER.sub("", message.content)
            if "{{" in leftover or "}}" in leftover:
                raise ValueError(
                    f"request.messages[{i}] has an unknown placeholder; "
                    "allowed: {{canary.<name>}}, {{input}}, {{trial}}"
                )
            refs = {
                m[len("canary.") :]
                for m in _PLACEHOLDER.findall(message.content)
                if m.startswith("canary.")
            }
            uses_input |= any(m == "input" for m in _PLACEHOLDER.findall(message.content))
            unknown = refs - set(declared)
            if unknown:
                raise ValueError(
                    f"request.messages[{i}] uses undeclared canaries {sorted(unknown)}"
                )
            if message.role == "user":
                literal = [
                    c.name
                    for c in self.canaries
                    if c.value != "auto" and c.value in message.content
                ]
                if refs or literal:
                    # A reply that repeats the user's text would count as a leak.
                    raise ValueError(
                        f"request.messages[{i}] is a user message: "
                        "canaries belong in hidden context"
                    )
            elif message.role in _HIDDEN_ROLES:
                hidden_refs |= refs

        if uses_input != bool(self.request.inputs):
            raise ValueError("{{input}} must be used if and only if request.inputs is non-empty")

        for oracle in self.oracles:
            if isinstance(oracle, CanaryOracleSpec):
                names = oracle.canaries if oracle.canaries is not None else tuple(declared)
                if not names:
                    raise ValueError("a canary oracle needs at least one canary")
                unknown = set(names) - set(declared)
                if unknown:
                    raise ValueError(
                        f"canary oracle refers to undeclared canaries {sorted(unknown)}"
                    )
                if not set(names) & hidden_refs:
                    raise ValueError(
                        "none of the canary oracle's canaries appears in a system, assistant "
                        "or tool message, so it could never fire"
                    )
        return self


def resolve_canaries(case: CaseFile) -> dict[str, str]:
    """``auto`` canaries derive from (execution seed, attack id, name): stable across reruns."""
    seed = case.attack.execution.seed
    values: dict[str, str] = {}
    for canary in case.canaries:
        if canary.value != "auto":
            values[canary.name] = canary.value
        elif seed is None:
            values[canary.name] = new_canary()
        else:
            digest = sha256_hex(f"{seed}:{case.attack.id}:{canary.name}")
            rng = random.Random(int(digest[:16], 16))  # noqa: S311 - reproducibility, not secrecy
            values[canary.name] = new_canary(rng)
    return values


def _renderer(case: CaseFile, canaries: dict[str, str]) -> Callable[[int], CompletionRequest]:
    request, inputs = case.request, case.request.inputs

    def build(trial: int) -> CompletionRequest:
        def substitute(match: re.Match[str]) -> str:
            name = match.group(1)
            if name == "input":
                return inputs[trial % len(inputs)]
            if name == "trial":
                return str(trial)
            return canaries[name[len("canary.") :]]

        # re.sub never rescans what it inserted, so rendering is single-pass by construction.
        messages = tuple(
            Message(role=m.role, content=_PLACEHOLDER.sub(substitute, m.content))
            for m in request.messages
        )
        return CompletionRequest(messages=messages, max_tokens=request.max_tokens)

    return build


def _build_oracles(case: CaseFile, canaries: dict[str, str]) -> tuple[Oracle, ...]:
    oracles: list[Oracle] = []
    for spec in case.oracles:
        if isinstance(spec, CanaryOracleSpec):
            names = spec.canaries if spec.canaries is not None else tuple(canaries)
            oracles.append(CanaryOracle(canaries[n] for n in names))
        else:
            oracles.append(SchemaOracle(spec.contract.build(f"{case.attack.id}-contract")))
    return tuple(oracles)


@dataclass(frozen=True)
class LoadedCase:
    path: Path
    spec: CaseFile
    trial_case: TrialCase


def build_case(spec: CaseFile, path: Path) -> LoadedCase:
    canaries = resolve_canaries(spec)
    induction = spec.induction
    if induction is not None:
        for name, value in canaries.items():
            if induction.check(Observation(text=value)):
                raise CaseError(
                    f"{path}: induction matches canary {name!r}; induction must detect the "
                    "attempt, not the leak itself"
                )
    trial_case = TrialCase(
        attack=spec.attack,
        build_request=_renderer(spec, canaries),
        oracles=_build_oracles(spec, canaries),
        induction=None if induction is None else induction.check,
    )
    return LoadedCase(path=path, spec=spec, trial_case=trial_case)


def load_case(path: Path) -> LoadedCase:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise CaseError(f"cannot read {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise CaseError(f"invalid YAML in {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise CaseError(f"{path} must contain a YAML mapping")
    if raw.get("schema") != CASE_SCHEMA:
        raise CaseError(f"{path}: schema must be {CASE_SCHEMA!r}, got {raw.get('schema')!r}")
    try:
        spec = CaseFile.model_validate(raw)
    except ValidationError as exc:
        raise CaseError(f"invalid case {path}:\n{exc}") from exc
    return build_case(spec, path)


def load_cases(root: Path) -> list[LoadedCase]:
    """Every ``*.yaml`` under ``root``, sorted by attack id; ids must be unique."""
    if not root.is_dir():
        raise CaseError(f"case directory {root} does not exist")
    loaded = [load_case(p) for p in sorted(root.rglob("*.yaml"))]
    if not loaded:
        raise CaseError(f"no *.yaml case files under {root}")
    seen: dict[str, Path] = {}
    for case in loaded:
        first = seen.setdefault(case.spec.attack.id, case.path)
        if first != case.path:
            raise CaseError(f"attack id {case.spec.attack.id!r} is used by {first} and {case.path}")
    return sorted(loaded, key=lambda c: c.spec.attack.id)

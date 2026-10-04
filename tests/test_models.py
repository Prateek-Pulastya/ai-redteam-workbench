import pytest
from pydantic import ValidationError

from airteam.core.attacks import Attack, ExecutionPolicy
from airteam.core.controls import Control
from airteam.core.frameworks import Framework, FrameworkMapping
from airteam.core.oracles import OracleKind
from airteam.core.properties import CanaryEgress, CrossOwnerRead, SecurityProperty
from airteam.core.runs import RunMetadata, new_run_id
from airteam.core.variants import Variant


def test_framework_version_is_kept_as_string_even_if_yaml_gives_int() -> None:
    m = FrameworkMapping.model_validate(
        {"framework": "owasp_api", "version": 2023, "identifier": "API1:2023"}
    )
    assert m.version == "2023"
    assert m.framework is Framework.OWASP_API


def test_unknown_framework_rejected() -> None:
    with pytest.raises(ValidationError):
        FrameworkMapping(framework="made_up", version="1", identifier="X")  # type: ignore[arg-type]


def test_security_property_parses_cross_owner_condition() -> None:
    prop = SecurityProperty.model_validate(
        {
            "id": "no-cross-owner-read",
            "description": "An identity never receives another identity's object.",
            "never": {"actor": "any_identity", "receives_resource_owned_by": "other_identity"},
            "oracle": "server_state",
            "frameworks": [
                {"framework": "owasp_api", "version": "2023", "identifier": "API1:2023"}
            ],
        }
    )
    assert isinstance(prop.never, CrossOwnerRead)
    assert prop.oracle is OracleKind.SERVER_STATE


def test_security_property_parses_canary_condition() -> None:
    prop = SecurityProperty.model_validate(
        {
            "id": "no-canary-egress",
            "description": "Canary never leaves.",
            "never": {"output_contains_canary": "CANARY_FAMILY_DEFAULT"},
            "oracle": "canary",
        }
    )
    assert isinstance(prop.never, CanaryEgress)


def test_security_property_rejects_ambiguous_condition() -> None:
    with pytest.raises(ValidationError):
        SecurityProperty.model_validate(
            {
                "id": "bad",
                "description": "x",
                "never": {"output_contains_canary": "C", "receives_resource_owned_by": "b"},
                "oracle": "canary",
            }
        )


@pytest.mark.parametrize("bad_id", ["Upper", "-leading", "has space", ""])
def test_slug_validation(bad_id: str) -> None:
    with pytest.raises(ValidationError):
        Control(id=bad_id, description="x")


def test_only_judge_and_heuristic_are_non_deterministic() -> None:
    non_det = {k for k in OracleKind if not k.deterministic}
    assert non_det == {OracleKind.JUDGE, OracleKind.HEURISTIC}


def test_variant_controls() -> None:
    fixed = Variant(name="fixed", controls_enabled=frozenset({"owner-check"}))
    assert fixed.has_control("owner-check")
    assert not Variant(name="vulnerable").has_control("owner-check")


@pytest.mark.parametrize(("rule", "k"), [("any", 1), ("k_of_n(3)", 3)])
def test_success_rule_parsing(rule: str, k: int) -> None:
    policy = ExecutionPolicy.model_validate({"trials": 5, "success_rule": rule})
    assert policy.success_rule.k == k


def test_success_rule_k_cannot_exceed_trials() -> None:
    with pytest.raises(ValidationError):
        ExecutionPolicy.model_validate({"trials": 2, "success_rule": "k_of_n(3)"})


def test_success_rule_garbage_rejected() -> None:
    with pytest.raises(ValidationError):
        ExecutionPolicy.model_validate({"success_rule": "most"})


def test_attack_defaults() -> None:
    attack = Attack(
        id="indirect-injection-001",
        name="Retrieved Instruction Override",
        category="indirect_injection",
        objective="unauthorized_instruction_following",
        property_id="no-canary-egress",
    )
    assert attack.execution.trials == 10
    assert attack.execution.seed == 1337


def test_models_are_immutable() -> None:
    v = Variant(name="fixed")
    with pytest.raises(ValidationError):
        v.name = "other"  # type: ignore[misc]


def test_run_id_format_round_trips_into_metadata() -> None:
    from datetime import UTC, datetime

    run_id = new_run_id()
    meta = RunMetadata(
        run_id=run_id,
        scanner_version="0.0.1",
        config_hash="a" * 64,
        target="playground",
        variant="vulnerable",
        started_at=datetime.now(UTC),
    )
    assert meta.run_id == run_id

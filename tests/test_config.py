from importlib.resources import files
from pathlib import Path
from typing import Any

import pytest
import yaml

from airteam.core.config import AirteamConfig, ConfigError, host_in_scope, load_config

TEMPLATE = files("airteam.templates").joinpath("airteam.yaml").read_text(encoding="utf-8")


def _cfg(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load(TEMPLATE)
    data.update(overrides)
    return data


def test_bundled_template_is_valid() -> None:
    cfg = AirteamConfig.model_validate(_cfg())
    assert cfg.target.name == "playground"
    assert cfg.api is not None
    assert len(cfg.api.identities) == 3


def test_config_hash_is_stable_and_sensitive() -> None:
    a = AirteamConfig.model_validate(_cfg())
    b = AirteamConfig.model_validate(_cfg())
    assert a.config_hash() == b.config_hash()
    c = AirteamConfig.model_validate(_cfg(scan={"max_requests": 7}))
    assert a.config_hash() != c.config_hash()


def test_raw_token_in_identity_is_rejected() -> None:
    data = _cfg()
    data["api"]["identities"][0]["token"] = "eyJhbGciOi..."
    with pytest.raises(ValueError, match="token"):
        AirteamConfig.model_validate(data)


def test_local_mode_rejects_remote_scope() -> None:
    data = _cfg()
    data["target"]["authorization"]["scope"] = ["example.com"]
    with pytest.raises(ValueError, match="loopback"):
        AirteamConfig.model_validate(data)


def test_endpoint_outside_scope_is_rejected() -> None:
    data = _cfg()
    data["target"]["authorization"] = {"mode": "authorized", "scope": ["api.example.com"]}
    data["target"]["endpoint"] = "https://evil.example.net"
    data["ai"]["endpoint"] = "https://api.example.com/chat"
    with pytest.raises(ValueError, match="outside authorization scope"):
        AirteamConfig.model_validate(data)


def test_ai_endpoint_must_also_be_in_scope() -> None:
    data = _cfg()
    data["ai"]["endpoint"] = "http://127.0.0.2:8000/chat"
    with pytest.raises(ValueError, match="outside authorization scope"):
        AirteamConfig.model_validate(data)


def test_authorization_is_required() -> None:
    data = _cfg()
    del data["target"]["authorization"]
    with pytest.raises(ValueError, match="authorization"):
        AirteamConfig.model_validate(data)


def test_scalar_scope_accepted() -> None:
    data = _cfg()
    data["target"]["authorization"]["scope"] = "localhost"
    data["ai"]["endpoint"] = "http://localhost:8000/chat"
    cfg = AirteamConfig.model_validate(data)
    assert cfg.target.authorization.scope == ("localhost",)


def test_ownership_must_reference_declared_identity() -> None:
    data = _cfg()
    data["api"]["ownership"].append({"identity": "ghost", "resources": {"/x/{id}": [1]}})
    with pytest.raises(ValueError, match="ghost"):
        AirteamConfig.model_validate(data)


@pytest.mark.parametrize(
    ("host", "scope", "expected"),
    [
        ("api.example.com", ("api.example.com",), True),
        ("API.example.com", ("api.example.com",), True),
        ("a.example.com", ("*.example.com",), True),
        ("example.com", ("*.example.com",), False),
        ("badexample.com", ("*.example.com",), False),
        ("example.com.evil.net", ("example.com",), False),
    ],
)
def test_host_in_scope(host: str, scope: tuple[str, ...], expected: bool) -> None:
    assert host_in_scope(host, scope) is expected


def test_load_config_errors_are_config_errors(tmp_path: Path) -> None:
    missing = tmp_path / "nope.yaml"
    with pytest.raises(ConfigError, match="cannot read"):
        load_config(missing)

    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("project: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(bad_yaml)

    not_mapping = tmp_path / "list.yaml"
    not_mapping.write_text("- a\n- b\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="mapping"):
        load_config(not_mapping)

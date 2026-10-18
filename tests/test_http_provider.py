import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from airteam.core.config import AirteamConfig
from airteam.engine.scan import ScanError, select_provider
from airteam.providers.base import CompletionRequest, Message, ProviderError, TransientProviderError
from airteam.providers.http import HttpProvider, extract

URL = "http://localhost:8000/chat"


def _provider(
    handler: Callable[[httpx.Request], httpx.Response], **kwargs: Any
) -> tuple[HttpProvider, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    client = httpx.Client(transport=httpx.MockTransport(record), follow_redirects=False)
    return HttpProvider(URL, kwargs.pop("api_key", None), 5.0, client=client, **kwargs), seen


def _request() -> CompletionRequest:
    return CompletionRequest(
        messages=(
            Message(role="system", content="Be brief."),
            Message(role="tool", content="Retrieved: opens 11:00."),
            Message(role="user", content="When do you open?"),
        ),
        temperature=0.0,
        seed=3,
        max_tokens=32,
    )


def test_default_shape() -> None:
    provider, seen = _provider(lambda _r: httpx.Response(200, json={"text": "At 11:00."}))
    completion = provider.complete(_request())
    assert completion.text == "At 11:00."
    assert completion.model_id == f"http:{URL}"
    body = json.loads(seen[0].content)
    assert [m["role"] for m in body["messages"]] == ["system", "tool", "user"]  # sent as written
    assert (body["temperature"], body["max_tokens"], body["seed"]) == (0.0, 32, 3)
    assert "authorization" not in seen[0].headers


def test_custom_fields_path_and_key() -> None:
    reply = {"data": {"choices": [{"reply": "At 11:00."}]}}
    provider, seen = _provider(
        lambda _r: httpx.Response(200, json=reply),
        messages_field="history",
        response_path="data.choices.0.reply",
        model="support-bot-v2",
        api_key="k",
    )
    assert provider.complete(_request()).text == "At 11:00."
    assert provider.model_id == "http:support-bot-v2"
    assert "history" in json.loads(seen[0].content)
    assert seen[0].headers["authorization"] == "Bearer k"


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"answer": "x"}, "has no 'text'"),
        ({"text": 5}, "is not text"),
        ([1, 2], "has no 'text'"),
    ],
)
def test_bad_replies(body: Any, message: str) -> None:
    provider, _ = _provider(lambda _r: httpx.Response(200, json=body))
    with pytest.raises(ProviderError, match=message):
        provider.complete(_request())


def test_not_json() -> None:
    provider, _ = _provider(lambda _r: httpx.Response(200, content=b"<html>"))
    with pytest.raises(ProviderError, match="not JSON"):
        provider.complete(_request())


@pytest.mark.parametrize(
    ("status", "transient"), [(429, True), (502, True), (301, False), (403, False)]
)
def test_status_mapping(status: int, transient: bool) -> None:
    provider, _ = _provider(lambda _r: httpx.Response(status, json={"text": "secret"}))
    with pytest.raises(ProviderError, match=f"HTTP {status}") as info:
        provider.complete(_request())
    assert isinstance(info.value, TransientProviderError) is transient
    assert "secret" not in str(info.value)


def test_extract_paths() -> None:
    data = {"a": [{"b": "x"}], "n": {"0": "key"}}
    assert extract(data, "a.0.b") == "x"
    assert extract(data, "n.0") == "key"  # digits are dict keys when the node is a dict
    for missing in ("a.1.b", "a.0.c", "z"):
        with pytest.raises(KeyError):
            extract(data, missing)


def _cfg(**ai: Any) -> AirteamConfig:
    return AirteamConfig.model_validate(
        {
            "project": {"name": "p"},
            "target": {
                "name": "t",
                "type": "hybrid",
                "endpoint": "http://localhost:8000",
                "authorization": {"mode": "local", "scope": ["localhost"]},
            },
            "ai": {"provider": "http", **ai},
        }
    )


def test_config_and_selection() -> None:
    with pytest.raises(ValueError, match="provider 'http' needs 'endpoint'"):
        _cfg()
    with pytest.raises(ValueError, match="String should match pattern"):
        _cfg(endpoint=URL, http={"response_path": "a..b"})
    provider = select_provider(_cfg(endpoint=URL, http={"messages_field": "history"}))
    assert isinstance(provider, HttpProvider)


def test_selection_applies_key_rules(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AIRTEAM_TEST_KEY", raising=False)
    with pytest.raises(ScanError, match="is not set"):
        select_provider(_cfg(endpoint=URL, api_key_env="AIRTEAM_TEST_KEY"))

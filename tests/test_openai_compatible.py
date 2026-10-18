import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from airteam.core.attacks import Attack, ExecutionPolicy
from airteam.core.config import AirteamConfig, ScanBudget
from airteam.core.evidence import EvidenceChain
from airteam.engine.budget import BudgetTracker
from airteam.engine.runner import Runner, TrialCase
from airteam.engine.scan import ScanError, select_provider
from airteam.oracles.canary import CanaryOracle
from airteam.providers.base import (
    CompletionRequest,
    Message,
    ProviderError,
    TransientProviderError,
)
from airteam.providers.openai_compatible import OpenAICompatibleProvider

BASE = "http://localhost:11434/v1"
CANARY = "AIRTEAM-CANARY-00112233aabbccdd"


def _ok(
    text: str | None = "We open at 11:00.", usage: dict[str, int] | None = None
) -> httpx.Response:
    body: dict[str, Any] = {"choices": [{"message": {"role": "assistant", "content": text}}]}
    if usage is not None:
        body["usage"] = usage
    return httpx.Response(200, json=body)


def _provider(
    handler: Callable[[httpx.Request], httpx.Response], api_key: str | None = "test-key"
) -> tuple[OpenAICompatibleProvider, list[httpx.Request]]:
    seen: list[httpx.Request] = []

    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    client = httpx.Client(transport=httpx.MockTransport(record), follow_redirects=False)
    return OpenAICompatibleProvider(BASE + "/", "llama3", api_key, 5.0, client=client), seen


def _request(seed: int | None = 7) -> CompletionRequest:
    return CompletionRequest(
        messages=(
            Message(role="system", content="Be brief."),
            Message(role="tool", content="Retrieved: opens 11:00."),
            Message(role="user", content="When do you open?"),
        ),
        temperature=0.3,
        seed=seed,
        max_tokens=64,
    )


def test_request_shape_and_parsing() -> None:
    provider, seen = _provider(lambda _r: _ok(usage={"prompt_tokens": 12, "completion_tokens": 4}))
    completion = provider.complete(_request())
    assert completion.text == "We open at 11:00."
    assert (completion.prompt_tokens, completion.completion_tokens) == (12, 4)
    assert completion.model_id == "openai_compatible:llama3"

    (sent,) = seen
    assert str(sent.url) == BASE + "/chat/completions"
    assert sent.headers["authorization"] == "Bearer test-key"
    body = json.loads(sent.content)
    assert body["model"] == "llama3"
    assert (body["temperature"], body["max_tokens"], body["seed"]) == (0.3, 64, 7)
    roles = [m["role"] for m in body["messages"]]
    # The tool message is answered to a synthetic assistant tool call, never promoted.
    assert roles == ["system", "assistant", "tool", "user"]
    call = body["messages"][1]["tool_calls"][0]
    assert body["messages"][2]["tool_call_id"] == call["id"]
    assert body["messages"][2]["content"] == "Retrieved: opens 11:00."


def test_no_key_no_header_and_no_seed() -> None:
    provider, seen = _provider(lambda _r: _ok(), api_key=None)
    provider.complete(_request(seed=None))
    assert "authorization" not in seen[0].headers
    assert "seed" not in json.loads(seen[0].content)


def test_missing_usage_falls_back_and_null_content_is_empty() -> None:
    provider, _ = _provider(lambda _r: _ok(text=None))
    completion = provider.complete(_request())
    assert completion.text == ""
    assert completion.prompt_tokens > 0


@pytest.mark.parametrize("status", [429, 500, 503])
def test_retryable_statuses(status: int) -> None:
    provider, _ = _provider(lambda _r: httpx.Response(status))
    with pytest.raises(TransientProviderError, match=f"HTTP {status}"):
        provider.complete(_request())


def test_timeouts_and_connection_errors_are_retryable() -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(TransientProviderError, match="timed out"):
        _provider(timeout)[0].complete(_request())
    with pytest.raises(TransientProviderError, match="ConnectError"):
        _provider(refused)[0].complete(_request())


@pytest.mark.parametrize("status", [302, 400, 401, 404])
def test_client_errors_and_redirects_are_not_retried(status: int) -> None:
    secret_body = {"error": "Incorrect API key provided: test-key"}
    provider, _ = _provider(lambda _r: httpx.Response(status, json=secret_body))
    with pytest.raises(ProviderError, match=f"HTTP {status}") as info:
        provider.complete(_request())
    assert not isinstance(info.value, TransientProviderError)
    assert "test-key" not in str(info.value)


@pytest.mark.parametrize(
    "body", [b"not json", b"{}", b'{"choices": []}', b'{"choices": [{"message": {"content": 5}}]}']
)
def test_malformed_responses(body: bytes) -> None:
    provider, _ = _provider(lambda _r: httpx.Response(200, content=body))
    with pytest.raises(ProviderError, match=r"malformed|not JSON"):
        provider.complete(_request())


def test_runner_retries_then_records_real_completion() -> None:
    calls = {"n": 0}

    def flaky(_r: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503) if calls["n"] % 2 else _ok(text=f"code {CANARY}")

    provider, _ = _provider(flaky)
    attack = Attack(
        id="provider-check",
        name="Provider wiring",
        category="smoke",
        objective="Check the runner over the HTTP provider.",
        property_id="no-canary-egress",
        execution=ExecutionPolicy(trials=3, seed=1),
    )
    case = TrialCase(
        attack=attack,
        build_request=lambda _i: _request(),
        oracles=(CanaryOracle([CANARY]),),
    )
    chain = EvidenceChain()
    trials = Runner(provider, chain, BudgetTracker(ScanBudget(max_retries=1))).run(case)
    assert calls["n"] == 6
    assert all(t.breached for t in trials)
    recorded = json.dumps([r.payload for r in chain.records])
    assert "test-key" not in recorded  # the key never reaches the evidence chain


def _config(**ai: Any) -> AirteamConfig:
    return AirteamConfig.model_validate(
        {
            "project": {"name": "p"},
            "target": {
                "name": "t",
                "type": "llm",
                "endpoint": "http://localhost:11434",
                "authorization": {"mode": "local", "scope": ["localhost"]},
            },
            "ai": {"provider": "openai_compatible", "endpoint": BASE, **ai},
        }
    )


def test_config_requires_model() -> None:
    with pytest.raises(ValueError, match="needs both"):
        _config()


def test_select_provider_reads_key_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _config(model="llama3", api_key_env="AIRTEAM_TEST_KEY")
    monkeypatch.delenv("AIRTEAM_TEST_KEY", raising=False)
    with pytest.raises(ScanError, match="AIRTEAM_TEST_KEY is not set"):
        select_provider(cfg)
    monkeypatch.setenv("AIRTEAM_TEST_KEY", "k")
    assert select_provider(cfg).model_id == "openai_compatible:llama3"


def test_config_rejects_raw_key_and_out_of_scope_endpoint() -> None:
    with pytest.raises(ValueError, match="api_key"):
        _config(model="m", api_key="sk-raw")
    with pytest.raises(ValueError, match="outside authorization scope"):
        _config(model="m", endpoint="https://api.example.com/v1")


def test_key_is_never_sent_over_plain_http_to_a_remote_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AIRTEAM_TEST_KEY", "k")
    remote = {
        "project": {"name": "p"},
        "target": {
            "name": "t",
            "type": "llm",
            "endpoint": "https://llm.example.com",
            "authorization": {"mode": "authorized", "scope": ["llm.example.com"]},
        },
    }

    def cfg(endpoint: str, key_env: str | None) -> AirteamConfig:
        ai = {"provider": "openai_compatible", "endpoint": endpoint, "model": "m"}
        if key_env:
            ai["api_key_env"] = key_env
        return AirteamConfig.model_validate({**remote, "ai": ai})

    with pytest.raises(ScanError, match="plain http"):
        select_provider(cfg("http://llm.example.com/v1", "AIRTEAM_TEST_KEY"))
    select_provider(cfg("https://llm.example.com/v1", "AIRTEAM_TEST_KEY"))
    select_provider(cfg("http://llm.example.com/v1", None))  # keyless http is allowed
    select_provider(_config(model="m", api_key_env="AIRTEAM_TEST_KEY"))  # loopback http ok

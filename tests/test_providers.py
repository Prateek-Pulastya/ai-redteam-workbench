import random

import pytest
from pydantic import ValidationError

from airteam.providers.base import CompletionRequest, Message, approx_tokens
from airteam.providers.mock import MockProvider


def _request(seed: int | None = 1, text: str = "hello there") -> CompletionRequest:
    return CompletionRequest(messages=(Message(role="user", content=text),), seed=seed)


def test_same_request_same_completion() -> None:
    provider = MockProvider(["a", "b", "c", "d"])
    assert provider.complete(_request()) == provider.complete(_request())
    assert provider.calls == 2


def test_seed_changes_choice_across_trials() -> None:
    provider = MockProvider([str(i) for i in range(20)])
    texts = {provider.complete(_request(seed=s)).text for s in range(30)}
    assert len(texts) > 1


def test_independent_providers_agree() -> None:
    # Determinism must not depend on provider instance state (e.g. call count).
    a, b = MockProvider(["x", "y", "z"]), MockProvider(["x", "y", "z"])
    a.complete(_request(seed=5))
    assert a.complete(_request(seed=9)) == b.complete(_request(seed=9))


def test_callable_responder_sees_request() -> None:
    def echo(request: CompletionRequest, _rng: random.Random) -> str:
        return request.messages[-1].content.upper()

    completion = MockProvider(echo, name="mock-echo").complete(_request(text="two words"))
    assert completion.text == "TWO WORDS"
    assert completion.model_id == "mock-echo"
    assert (completion.prompt_tokens, completion.completion_tokens) == (2, 2)
    assert completion.total_tokens == 4


def test_empty_reply_list_rejected() -> None:
    with pytest.raises(ValueError, match="at least one reply"):
        MockProvider([])


def test_request_needs_a_message() -> None:
    with pytest.raises(ValidationError):
        CompletionRequest(messages=())


def test_approx_tokens() -> None:
    assert approx_tokens("") == 0
    assert approx_tokens("  a\tb\nc ") == 3

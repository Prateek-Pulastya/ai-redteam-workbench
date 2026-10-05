"""Deterministic offline provider for tests, CI and the playground (spec §0A).

The same request always yields the same completion. The responder receives an
RNG seeded from a hash of the full request (messages, temperature, seed), so a
responder can model a stochastic model while every run stays reproducible.
"""

import random
from collections.abc import Callable, Sequence

from airteam.core.hashing import canonical_json, sha256_hex
from airteam.providers.base import Completion, CompletionRequest, approx_tokens

Responder = Callable[[CompletionRequest, random.Random], str]


def _choose_from(replies: Sequence[str]) -> Responder:
    choices = tuple(replies)
    if not choices:
        raise ValueError("MockProvider needs at least one reply")

    def respond(_request: CompletionRequest, rng: random.Random) -> str:
        return rng.choice(choices)

    return respond


class MockProvider:
    def __init__(self, responder: Responder | Sequence[str], name: str = "mock") -> None:
        self._respond = responder if callable(responder) else _choose_from(responder)
        self._name = name
        self.calls = 0

    @property
    def model_id(self) -> str:
        return self._name

    def complete(self, request: CompletionRequest) -> Completion:
        self.calls += 1
        digest = sha256_hex(canonical_json(request.model_dump(mode="json")))
        # Reproducibility, not secrecy: a seeded PRNG is exactly what is wanted here.
        rng = random.Random(int(digest[:16], 16))  # noqa: S311
        text = self._respond(request, rng)
        return Completion(
            text=text,
            model_id=self.model_id,
            prompt_tokens=sum(approx_tokens(m.content) for m in request.messages),
            completion_tokens=approx_tokens(text),
        )

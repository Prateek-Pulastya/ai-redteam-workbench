"""Provider interface shared by the mock, HTTP and OpenAI-compatible backends."""

from typing import Literal, Protocol

from pydantic import Field

from airteam.core.base import StrictModel


class Message(StrictModel):
    role: Literal["system", "user", "assistant", "tool"]
    content: str


class CompletionRequest(StrictModel):
    messages: tuple[Message, ...] = Field(min_length=1)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    seed: int | None = None
    max_tokens: int = Field(default=512, ge=1)


class Completion(StrictModel):
    text: str
    model_id: str = Field(min_length=1)
    prompt_tokens: int = Field(ge=0)
    completion_tokens: int = Field(ge=0)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class ProviderError(Exception):
    """The provider could not produce a completion; the trial is recorded as errored."""


class TransientProviderError(ProviderError):
    """Retryable failure such as a timeout, HTTP 429 or 5xx."""


class LLMProvider(Protocol):
    @property
    def model_id(self) -> str: ...

    def complete(self, request: CompletionRequest) -> Completion: ...


def approx_tokens(text: str) -> int:
    """Whitespace token count: a stable stand-in where no tokenizer is available."""
    return len(text.split())

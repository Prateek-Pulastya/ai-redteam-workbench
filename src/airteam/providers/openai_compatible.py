"""OpenAI-compatible chat completions (OpenAI, vLLM, Ollama, LM Studio, gateways).

The endpoint is validated against the authorization scope when the config loads.
Redirects are never followed: a 3xx could leave that scope. The API key is sent as a
bearer header only; it never reaches the evidence chain, which records the
``CompletionRequest`` and the ``Completion``, not HTTP headers.
"""

from typing import Any

import httpx

from airteam.providers.base import Completion, CompletionRequest, ProviderError, approx_tokens
from airteam.providers.http import post_json

TOOL_NAME = "context_lookup"


def _wire_messages(request: CompletionRequest) -> list[dict[str, Any]]:
    """Case messages -> OpenAI wire format.

    OpenAI rejects a ``tool`` message that does not answer an assistant tool call, so
    each one is preceded by a synthetic call; the content stays in the tool channel
    instead of being promoted to user or system text.
    """
    wire: list[dict[str, Any]] = []
    for i, message in enumerate(request.messages):
        if message.role != "tool":
            wire.append({"role": message.role, "content": message.content})
            continue
        call_id = f"call_{i}"
        wire.append(
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": call_id,
                        "type": "function",
                        "function": {"name": TOOL_NAME, "arguments": "{}"},
                    }
                ],
            }
        )
        wire.append({"role": "tool", "tool_call_id": call_id, "content": message.content})
    return wire


class OpenAICompatibleProvider:
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None,
        timeout_seconds: float,
        client: httpx.Client | None = None,
    ) -> None:
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._model = model
        self._headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = client or httpx.Client(timeout=timeout_seconds, follow_redirects=False)

    @property
    def model_id(self) -> str:
        return f"openai_compatible:{self._model}"

    def complete(self, request: CompletionRequest) -> Completion:
        body: dict[str, Any] = {
            "model": self._model,
            "messages": _wire_messages(request),
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.seed is not None:
            body["seed"] = request.seed
        data = post_json(self._client, self._url, body, self._headers)
        try:
            text = data["choices"][0]["message"].get("content") or ""
            if not isinstance(text, str):
                raise TypeError("content is not text")
            usage = data.get("usage") or {}
            prompt = sum(approx_tokens(m.content) for m in request.messages)
            return Completion(
                text=text,
                model_id=self.model_id,
                prompt_tokens=int(usage.get("prompt_tokens") or prompt),
                completion_tokens=int(usage.get("completion_tokens") or approx_tokens(text)),
            )
        except (ValueError, KeyError, IndexError, TypeError, AttributeError) as exc:
            raise ProviderError("malformed chat completion response") from exc

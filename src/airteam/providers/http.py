"""Generic HTTP provider for custom chat endpoints, plus the POST helper both network
providers share.

Request:  ``POST <endpoint>`` with ``{<messages_field>: [{role, content}, ...],
"temperature", "max_tokens", "seed"?}``. Roles are sent as written in the case.
Response: JSON; the reply text is read at ``response_path`` (dotted, list indexes
allowed, e.g. ``choices.0.message.content``).
"""

from typing import Any

import httpx

from airteam.providers.base import (
    Completion,
    CompletionRequest,
    ProviderError,
    TransientProviderError,
    approx_tokens,
)


def post_json(client: httpx.Client, url: str, body: dict[str, Any], headers: dict[str, str]) -> Any:
    """POST and decode JSON, mapping failures onto the runner's retry contract.

    Timeouts, connection errors, 429 and 5xx are retryable. Anything else outside 2xx
    is not, and redirects are refused because they could leave the authorization
    scope. Response bodies stay out of error messages: some servers echo credentials.
    """
    try:
        response = client.post(url, json=body, headers=headers)
    except httpx.TimeoutException as exc:
        raise TransientProviderError("request timed out") from exc
    except httpx.TransportError as exc:
        raise TransientProviderError(f"connection failed: {type(exc).__name__}") from exc
    status = response.status_code
    if status == 429 or status >= 500:
        raise TransientProviderError(f"HTTP {status}")
    if status >= 300:
        raise ProviderError(f"HTTP {status}")
    try:
        return response.json()
    except ValueError as exc:
        raise ProviderError("response is not JSON") from exc


def extract(data: Any, path: str) -> Any:
    """Follow a dotted path through dicts and lists; ``KeyError`` if it is missing."""
    node = data
    for part in path.split("."):
        if isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        elif isinstance(node, dict) and part in node:
            node = node[part]
        else:
            raise KeyError(path)
    return node


class HttpProvider:
    def __init__(
        self,
        url: str,
        api_key: str | None,
        timeout_seconds: float,
        messages_field: str = "messages",
        response_path: str = "text",
        model: str | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        self._url = url
        parts = httpx.URL(url)
        # Recorded in run metadata and evidence, so no userinfo and no query string.
        port = f":{parts.port}" if parts.port else ""
        self._safe_url = f"{parts.scheme}://{parts.host}{port}{parts.path}"
        self._messages_field = messages_field
        self._response_path = response_path
        self._model = model
        self._headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = client or httpx.Client(timeout=timeout_seconds, follow_redirects=False)

    @property
    def model_id(self) -> str:
        return f"http:{self._model or self._safe_url}"

    def complete(self, request: CompletionRequest) -> Completion:
        body: dict[str, Any] = {
            self._messages_field: [m.model_dump() for m in request.messages],
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        if request.seed is not None:
            body["seed"] = request.seed
        data = post_json(self._client, self._url, body, self._headers)
        try:
            text = extract(data, self._response_path)
        except KeyError as exc:
            raise ProviderError(f"response has no {self._response_path!r}") from exc
        if not isinstance(text, str):
            raise ProviderError(f"response {self._response_path!r} is not text")
        return Completion(
            text=text,
            model_id=self.model_id,
            prompt_tokens=sum(approx_tokens(m.content) for m in request.messages),
            completion_tokens=approx_tokens(text),
        )

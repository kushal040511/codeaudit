"""Free, local LLM provider: Ollama (https://ollama.com) running on your machine.

Presents the small part of the Anthropic client that LLMClient uses
(`messages.count_tokens`, `messages.create`, `with_options`), so budgets, retries,
JSON validation, call logging and patch validation work unchanged. Calls cost $0.

Ollama has no token-counting endpoint: input tokens are estimated conservatively
(about 3 characters per token) for budgets, and the real counts from the response are
recorded. A prompt that wouldn't fit the model's context window (OLLAMA_NUM_CTX) is
refused instead of being silently truncated by Ollama.
"""

import math
from types import SimpleNamespace
from typing import Any

import httpx

from app.config import Settings

CHARS_PER_TOKEN = 3.0
TOKENS_PER_IMAGE = 1_000
RETRYABLE_STATUS = frozenset({408, 409, 429})


class OllamaError(Exception):
    """A failed request to the Ollama server."""

    def __init__(self, message: str, *, kind: str = "api_error", status: int | None = None):
        super().__init__(message)
        self.kind = kind  # connection_error | rate_limited | api_error
        self.status = status

    @property
    def retryable(self) -> bool:
        if self.kind == "connection_error":
            return True
        return self.status is not None and (self.status in RETRYABLE_STATUS or self.status >= 500)


def estimate_tokens(system: str, messages: list[dict[str, Any]]) -> int:
    chars = len(system)
    images = 0
    for message in messages:
        content = message["content"]
        if isinstance(content, str):
            chars += len(content)
            continue
        for block in content:
            if block.get("type") == "text":
                chars += len(block["text"])
            elif block.get("type") == "image":
                images += 1
    return math.ceil(chars / CHARS_PER_TOKEN) + images * TOKENS_PER_IMAGE + 16


def _to_ollama(system: str, messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], bool]:
    converted: list[dict[str, Any]] = [{"role": "system", "content": system}]
    has_images = False
    for message in messages:
        content = message["content"]
        if isinstance(content, str):
            converted.append({"role": message["role"], "content": content})
            continue
        texts, images = [], []
        for block in content:
            if block.get("type") == "text":
                texts.append(block["text"])
            elif block.get("type") == "image":
                images.append(block["source"]["data"])  # already base64
        entry: dict[str, Any] = {"role": message["role"], "content": "\n\n".join(texts)}
        if images:
            entry["images"] = images
            has_images = True
        converted.append(entry)
    return converted, has_images


class OllamaMessages:
    def __init__(self, settings: Settings, http: httpx.Client) -> None:
        self._settings = settings
        self._http = http

    def count_tokens(
        self, *, system: str, messages: list[dict[str, Any]], **_: Any
    ) -> SimpleNamespace:
        return SimpleNamespace(input_tokens=estimate_tokens(system, messages))

    def create(
        self, *, system: str, messages: list[dict[str, Any]], max_tokens: int, **_: Any
    ) -> SimpleNamespace:
        settings = self._settings
        converted, has_images = _to_ollama(system, messages)
        model = settings.ollama_model
        if has_images:
            if not settings.ollama_vision_model:
                raise OllamaError(
                    f"The local model {settings.ollama_model} can't read screenshots. Set"
                    " OLLAMA_VISION_MODEL (for example qwen2.5vl:7b) to enable this step."
                )
            model = settings.ollama_vision_model
        num_predict = min(max_tokens, settings.ollama_max_output_tokens)
        prompt_tokens = estimate_tokens(system, messages)
        if prompt_tokens + num_predict > settings.ollama_num_ctx:
            raise OllamaError(
                f"The request (~{prompt_tokens:,} tokens + {num_predict:,} output) doesn't fit"
                f" the local model's {settings.ollama_num_ctx:,}-token context (OLLAMA_NUM_CTX)."
            )
        payload = {
            "model": model,
            "messages": converted,
            "stream": False,
            "format": "json",  # constrained decoding: the reply is always valid JSON
            "keep_alive": settings.ollama_keep_alive,
            "options": {
                "num_ctx": settings.ollama_num_ctx,
                "num_predict": num_predict,
                "temperature": 0.2,
            },
        }
        try:
            response = self._http.post("/api/chat", json=payload)
        except httpx.TimeoutException as exc:
            raise OllamaError(
                f"Ollama did not answer within {settings.ollama_timeout_seconds:.0f}s: {exc}",
                kind="connection_error",
            ) from exc
        except httpx.HTTPError as exc:
            raise OllamaError(
                f"Could not reach Ollama at {settings.ollama_base_url} ({type(exc).__name__})."
                " Is `ollama serve` running?",
                kind="connection_error",
            ) from exc
        if response.status_code >= 400:
            detail = response.text[:300]
            try:
                detail = str(response.json().get("error", detail))
            except ValueError:
                pass
            if response.status_code == 404:
                detail = f"{detail}. Download it with: ollama pull {model}"
            raise OllamaError(
                f"Ollama returned {response.status_code}: {detail}",
                kind="rate_limited" if response.status_code == 429 else "api_error",
                status=response.status_code,
            )
        body = response.json()
        text = str((body.get("message") or {}).get("content") or "")
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text=text)],
            usage=SimpleNamespace(
                input_tokens=int(body.get("prompt_eval_count") or prompt_tokens),
                output_tokens=int(body.get("eval_count") or 0),
                cache_creation_input_tokens=0,
                cache_read_input_tokens=0,
            ),
            stop_reason="max_tokens" if body.get("done_reason") == "length" else "end_turn",
            _request_id=None,
        )


class OllamaClient:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self._http = httpx.Client(
            base_url=settings.ollama_base_url.rstrip("/"),
            timeout=httpx.Timeout(settings.ollama_timeout_seconds, connect=10.0),
            transport=transport,
        )
        self.messages = OllamaMessages(settings, self._http)

    def with_options(self, **_: Any) -> "OllamaClient":
        return self  # retries are LLMClient's

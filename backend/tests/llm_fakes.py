"""A scripted stand-in for the Anthropic API, served through the real SDK client.

No network: requests go to an in-process httpx2 MockTransport, so tests exercise the
SDK's request serialization and response parsing without calling the real API.
"""

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import anthropic
import httpx2
from anthropic import DefaultHttpxClient

Responder = Callable[[dict[str, Any]], httpx2.Response]


def message(
    text: str,
    *,
    input_tokens: int = 1000,
    output_tokens: int = 200,
    stop_reason: str = "end_turn",
    model: str = "claude-sonnet-4-6",
) -> httpx2.Response:
    return httpx2.Response(
        200,
        json={
            "id": "msg_test",
            "type": "message",
            "role": "assistant",
            "model": model,
            "content": [
                {"type": "thinking", "thinking": "", "signature": "sig"},
                {"type": "text", "text": text},
            ],
            "stop_reason": stop_reason,
            "stop_sequence": None,
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "cache_creation_input_tokens": 0,
                "cache_read_input_tokens": 0,
            },
        },
        headers={"request-id": "req_test"},
    )


def api_error(
    status: int, error_type: str, headers: dict[str, str] | None = None
) -> httpx2.Response:
    return httpx2.Response(
        status,
        json={"type": "error", "error": {"type": error_type, "message": f"{error_type} (test)"}},
        headers=headers or {},
    )


@dataclass
class FakeAnthropic:
    """`responses` are used in order for /v1/messages; a callable decides per request."""

    responses: list[httpx2.Response | Responder] = field(default_factory=list)
    responder: Responder | None = None
    counted_input_tokens: int = 2000
    message_requests: list[dict[str, Any]] = field(default_factory=list)
    count_requests: list[dict[str, Any]] = field(default_factory=list)

    def _handle(self, request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        if request.url.path.endswith("/count_tokens"):
            self.count_requests.append(body)
            return httpx2.Response(200, json={"input_tokens": self.counted_input_tokens})
        self.message_requests.append(body)
        if self.responses:
            next_response = self.responses.pop(0)
            return next_response(body) if callable(next_response) else next_response
        if self.responder is not None:
            return self.responder(body)
        raise AssertionError(f"unexpected request: {body.get('messages', [])[-1:]}")

    def client(self) -> anthropic.Anthropic:
        return anthropic.Anthropic(
            api_key="test-key",
            base_url="http://anthropic.test",
            http_client=DefaultHttpxClient(transport=httpx2.MockTransport(self._handle)),
        )


def user_prompt(body: dict[str, Any]) -> str:
    return str(body["messages"][0]["content"])

"""The free local provider (Ollama) behind LLMClient, against a fake Ollama server."""

import json
import uuid
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from pydantic import BaseModel
from sqlalchemy import select

from app.config import Settings, get_settings
from app.core.db import SessionLocal
from app.models import LLMCall, LLMPurpose, Scan, ScanStatus
from app.services import costs
from app.services.llm.client import (
    ImageInput,
    LLMClient,
    LLMError,
    LLMOutputError,
    LLMSpendCapError,
    llm_configured,
)
from app.services.llm.ollama import OllamaClient

pytestmark = pytest.mark.integration


class Answer(BaseModel):
    verdict: str


def make_scan() -> uuid.UUID:
    with SessionLocal() as db:
        scan = Scan(status=ScanStatus.ENRICHING, original_filename="x.zip", storage_key="x")
        db.add(scan)
        db.commit()
        return scan.id


def reply(content: str, *, done_reason: str = "stop", prompt: int = 900, output: int = 40) -> dict:
    return {
        "model": "qwen2.5-coder:7b",
        "message": {"role": "assistant", "content": content},
        "done": True,
        "done_reason": done_reason,
        "prompt_eval_count": prompt,
        "eval_count": output,
    }


def ollama(
    handler: Callable[[httpx.Request], httpx.Response], **overrides: Any
) -> tuple[LLMClient, list[float]]:
    settings = Settings(  # type: ignore[call-arg]
        llm_provider="ollama", llm_max_retries=2, **overrides
    )
    sleeps: list[float] = []
    client = LLMClient(
        OllamaClient(settings, transport=httpx.MockTransport(handler)),
        settings=settings,
        sleep=sleeps.append,
    )
    return client, sleeps


def ask(client: LLMClient, scan_id: uuid.UUID, **kwargs: Any) -> Answer:
    return client.generate_json(
        scan_id=scan_id,
        purpose=LLMPurpose.FIX_SUGGESTION,
        system="Reply with JSON.",
        prompt="Is this safe?",
        schema=Answer,
        **kwargs,
    ).parsed


def calls(scan_id: uuid.UUID) -> list[LLMCall]:
    with SessionLocal() as db:
        return list(
            db.scalars(select(LLMCall).where(LLMCall.scan_id == scan_id).order_by(LLMCall.id))
        )


@pytest.fixture(autouse=True)
def local_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    # The spend-cap check reads global settings.
    monkeypatch.setattr(get_settings(), "llm_provider", "ollama")


def test_needs_no_api_key() -> None:
    settings = Settings(  # type: ignore[call-arg]
        llm_provider="ollama", llm_enabled=True, anthropic_api_key=None
    )
    assert llm_configured(settings) is None


def test_local_call_is_free_logged_and_json_constrained(database: None) -> None:
    requests: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=reply('{"verdict": "safe"}'))

    scan_id = make_scan()
    client, _ = ollama(handler)
    assert ask(client, scan_id) == Answer(verdict="safe")

    [body] = requests
    assert body["model"] == "qwen2.5-coder:7b" and body["stream"] is False
    assert body["format"] == "json"
    assert body["options"]["num_ctx"] == 16_384 and body["options"]["num_predict"] == 4_096
    assert body["messages"][0] == {"role": "system", "content": "Reply with JSON."}
    assert body["messages"][1] == {"role": "user", "content": "Is this safe?"}
    [call] = calls(scan_id)
    assert call.model == "ollama/qwen2.5-coder:7b"
    assert (call.success, call.pending, call.input_tokens, call.output_tokens) == (
        True,
        False,
        900,
        40,
    )
    assert float(call.cost_usd) == 0.0


def test_spend_cap_does_not_apply_but_kill_switch_does(
    database: None, redis_clean: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "llm_daily_spend_cap_usd", 0.0)
    client, _ = ollama(lambda _: httpx.Response(200, json=reply('{"verdict": "ok"}')))
    scan_id = make_scan()
    assert ask(client, scan_id).verdict == "ok"

    costs.set_kill_switch("maintenance")
    try:
        with pytest.raises(LLMSpendCapError, match="switched off"):
            ask(client, make_scan())
    finally:
        costs.clear_kill_switch()


def test_missing_model_explains_how_to_download_it(database: None) -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "model 'qwen2.5-coder:7b' not found"})

    client, sleeps = ollama(handler)
    scan_id = make_scan()
    with pytest.raises(LLMError, match="ollama pull qwen2.5-coder:7b"):
        ask(client, scan_id)
    assert sleeps == []  # not retried
    [call] = calls(scan_id)
    assert call.error_type == "api_error" and float(call.cost_usd) == 0.0


def test_server_not_running_is_retried_then_reported(database: None) -> None:
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectError("connection refused", request=request)

    client, sleeps = ollama(handler)
    with pytest.raises(LLMError, match="Is `ollama serve` running"):
        ask(client, make_scan())
    assert attempts == 3 and len(sleeps) == 2


def test_truncated_output_and_oversized_prompts_fail_clearly(database: None) -> None:
    client, _ = ollama(lambda _: httpx.Response(200, json=reply('{"verd', done_reason="length")))
    with pytest.raises(LLMOutputError, match="token limit"):
        ask(client, make_scan())

    sent: list[httpx.Request] = []
    small, _ = ollama(lambda r: sent.append(r) or httpx.Response(200), ollama_num_ctx=2048)
    with pytest.raises(LLMError, match="doesn't fit the local model's 2,048-token context"):
        small.generate_json(
            scan_id=make_scan(),
            purpose=LLMPurpose.FIX_SUGGESTION,
            system="s",
            prompt="x" * 30_000,
            schema=Answer,
        )
    assert sent == []


def test_images_need_a_vision_model(database: None) -> None:
    requests: list[dict[str, Any]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=reply('{"verdict": "blue"}'))

    image = ImageInput(data=b"\x89PNG fake", media_type="image/png")
    client, _ = ollama(handler)
    with pytest.raises(LLMError, match="OLLAMA_VISION_MODEL"):
        ask(client, make_scan(), images=[image])
    assert requests == []

    vision, _ = ollama(handler, ollama_vision_model="qwen2.5vl:7b")
    assert ask(vision, make_scan(), images=[image]).verdict == "blue"
    assert requests[0]["model"] == "qwen2.5vl:7b"
    assert requests[0]["messages"][1]["images"] == ["iVBORyBmYWtl"]

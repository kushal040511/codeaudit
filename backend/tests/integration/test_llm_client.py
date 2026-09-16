"""LLMClient against a fake Anthropic API (real SDK, no network) and a real database."""

import uuid

import pytest
from pydantic import BaseModel
from sqlalchemy import select

from app.config import Settings
from app.core.db import SessionLocal
from app.models import LLMCall, LLMPurpose, Scan, ScanStatus
from app.services.llm.client import (
    LLMBudgetExceededError,
    LLMClient,
    LLMError,
    LLMOutputError,
    LLMRefusalError,
)
from tests.llm_fakes import FakeAnthropic, api_error, message

pytestmark = pytest.mark.integration


class Answer(BaseModel):
    verdict: str


def make_scan() -> uuid.UUID:
    with SessionLocal() as db:
        scan = Scan(status=ScanStatus.ENRICHING, original_filename="x.zip", storage_key="x")
        db.add(scan)
        db.commit()
        return scan.id


def make_client(fake: FakeAnthropic, **settings: object) -> tuple[LLMClient, list[float]]:
    sleeps: list[float] = []
    values: dict[str, object] = {
        "anthropic_model": "claude-sonnet-4-6",
        "llm_max_retries": 3,
    } | settings
    client = LLMClient(fake.client(), settings=Settings(**values), sleep=sleeps.append)  # type: ignore[arg-type]
    return client, sleeps


def calls(scan_id: uuid.UUID) -> list[LLMCall]:
    with SessionLocal() as db:
        return list(
            db.scalars(select(LLMCall).where(LLMCall.scan_id == scan_id).order_by(LLMCall.id))
        )


def ask(client: LLMClient, scan_id: uuid.UUID) -> Answer:
    return client.generate_json(
        scan_id=scan_id,
        purpose=LLMPurpose.FIX_SUGGESTION,
        system="Reply with JSON.",
        prompt="Is this safe?",
        schema=Answer,
        context={"finding_ids": [1]},
    ).parsed


def test_successful_call_is_logged_with_tokens_cost_and_request_shape(database: None) -> None:
    scan_id = make_scan()
    fake = FakeAnthropic(
        [message('```json\n{"verdict": "safe"}\n```', input_tokens=1200, output_tokens=300)]
    )
    client, _ = make_client(fake, llm_effort="low", llm_max_output_tokens=4000)

    assert ask(client, scan_id) == Answer(verdict="safe")

    [request] = fake.message_requests
    assert request["model"] == "claude-sonnet-4-6"
    assert request["thinking"] == {"type": "adaptive"}
    assert request["output_config"] == {"effort": "low"}
    assert request["max_tokens"] == 4000
    assert request["system"] == "Reply with JSON."
    [call] = calls(scan_id)
    assert (call.success, call.pending, call.attempts, call.stop_reason) == (
        True,
        False,
        1,
        "end_turn",
    )
    assert (call.input_tokens, call.output_tokens, call.reserved_tokens) == (1200, 300, 2000 + 4000)
    # Sonnet 4.6: $3 / $15 per million tokens
    assert float(call.cost_usd) == pytest.approx(1200 * 3 / 1e6 + 300 * 15 / 1e6)
    assert call.request_id == "req_test"
    assert call.context == {"finding_ids": [1]}
    assert call.prompt is not None and "Is this safe?" in call.prompt
    assert call.response_text is not None and "safe" in call.response_text
    assert client.budget(scan_id).used == 1500


def test_unparsable_output_gets_one_correction_attempt(database: None) -> None:
    scan_id = make_scan()
    fake = FakeAnthropic([message("Sure! The verdict is safe."), message('{"verdict": "safe"}')])
    client, _ = make_client(fake)

    assert ask(client, scan_id) == Answer(verdict="safe")

    retry = fake.message_requests[1]["messages"]
    assert [m["role"] for m in retry] == ["user", "assistant", "user"]
    assert retry[1]["content"] == "Sure! The verdict is safe."
    assert "could not be used" in retry[2]["content"]
    first, second = calls(scan_id)
    assert (first.success, first.error_type) == (False, "invalid_output")
    assert second.success and second.context == {"finding_ids": [1], "parse_retry": True}


def test_second_unparsable_output_raises(database: None) -> None:
    scan_id = make_scan()
    fake = FakeAnthropic([message("nope"), message('{"verdict": 42, "extra": }')])
    client, _ = make_client(fake)

    with pytest.raises(LLMOutputError, match="after one correction attempt"):
        ask(client, scan_id)

    assert [(c.success, c.error_type) for c in calls(scan_id)] == [
        (False, "invalid_output"),
        (False, "invalid_output"),
    ]


def test_rate_limits_and_overload_are_retried_with_backoff(database: None) -> None:
    scan_id = make_scan()
    fake = FakeAnthropic(
        [
            api_error(429, "rate_limit_error", {"retry-after": "7"}),
            api_error(529, "overloaded_error"),
            api_error(503, "api_error"),
            message('{"verdict": "ok"}'),
        ]
    )
    client, sleeps = make_client(fake)

    assert ask(client, scan_id).verdict == "ok"

    assert sleeps[0] == 7.0  # honours retry-after
    assert 2.0 <= sleeps[1] <= 3.0  # exponential with jitter
    assert 4.0 <= sleeps[2] <= 5.0
    [call] = calls(scan_id)
    assert (call.success, call.attempts) == (True, 4)


def test_retries_are_bounded_and_client_errors_are_not_retried(database: None) -> None:
    scan_id = make_scan()
    fake = FakeAnthropic([api_error(500, "api_error")] * 3)
    client, sleeps = make_client(fake, llm_max_retries=2)

    with pytest.raises(LLMError, match="Anthropic API request failed"):
        ask(client, scan_id)
    assert len(sleeps) == 2
    assert [(c.attempts, c.error_type, c.pending) for c in calls(scan_id)] == [
        (3, "api_error", False)
    ]

    other = make_scan()
    fake = FakeAnthropic([api_error(400, "invalid_request_error")])
    client, sleeps = make_client(fake)
    with pytest.raises(LLMError):
        ask(client, other)
    assert sleeps == [] and calls(other)[0].attempts == 1


def test_refusal_and_truncation(database: None) -> None:
    scan_id = make_scan()
    fake = FakeAnthropic(
        [message("", stop_reason="refusal"), message('{"verdict": "sa', stop_reason="max_tokens")]
    )
    client, _ = make_client(fake)

    with pytest.raises(LLMRefusalError):
        ask(client, scan_id)
    with pytest.raises(LLMOutputError, match="token limit"):
        ask(client, scan_id)

    assert [c.error_type for c in calls(scan_id)] == ["refusal", "max_tokens"]


def test_budget_refuses_before_sending(database: None) -> None:
    scan_id = make_scan()
    # Each call needs up to 2000 counted input + 4000 output = 6000 tokens.
    fake = FakeAnthropic([message('{"verdict": "ok"}', input_tokens=1900, output_tokens=800)])
    client, _ = make_client(fake, llm_token_budget_per_scan=9000, llm_max_output_tokens=4000)

    ask(client, scan_id)  # uses 2700, leaving 6300: fits
    fake.responses.append(message('{"verdict": "ok"}', input_tokens=1900, output_tokens=800))
    ask(client, scan_id)  # leaves 3600
    with pytest.raises(LLMBudgetExceededError, match="only 3,600 of the 9,000"):
        ask(client, scan_id)

    assert len(fake.message_requests) == 2  # the refused call was never sent
    refused = calls(scan_id)[-1]
    assert (refused.success, refused.error_type, refused.input_tokens, refused.pending) == (
        False,
        "budget_exceeded",
        0,
        False,
    )
    assert client.budget(scan_id).remaining == 3600

"""Anthropic API wrapper: token budget, retries, defensive JSON output, per-call logging.

Ground rules for this layer:
- The LLM never influences the score; scoring is deterministic (services/scoring).
- Uploaded code is untrusted input (prompt injection): it only ever appears inside
  the user message, delimited, and every output is validated before use.
- Every request is recorded as an LLMCall row, including refused and failed ones.
"""

import logging
import random
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import anthropic
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings, get_settings
from app.core.db import SessionLocal
from app.models import LLMCall, LLMPurpose, Scan
from app.services.llm.json_output import OutputParseError, parse_model_output
from app.services.llm.pricing import cost_usd

logger = logging.getLogger(__name__)

MAX_LOGGED_CHARS = 64_000
# Retried with exponential backoff, like the SDK's own policy: request timeouts (408),
# conflicts (409), rate limits (429), every 5xx including 529 overloaded, and
# connection errors. In SDK 1.x OverloadedError / ServiceUnavailableError are not
# InternalServerError subclasses, so classify by status code.
RETRYABLE_STATUS = frozenset({408, 409, 429})


def is_retryable(error: anthropic.APIError) -> bool:
    if isinstance(error, anthropic.APIConnectionError):
        return True
    if isinstance(error, anthropic.APIStatusError):
        return error.status_code in RETRYABLE_STATUS or error.status_code >= 500
    return False


PARSE_RETRY_INSTRUCTION = (
    "Your previous reply could not be used: {error}. Reply again with only the JSON"
    " object described in the instructions: no Markdown fences, no text before or after."
)


class _FailedRequest(Exception):
    def __init__(self, error: anthropic.APIError, attempts: int) -> None:
        super().__init__(str(error))
        self.error = error
        self.attempts = attempts


class LLMError(Exception):
    """Base class. `error_type` is recorded on the LLMCall row."""

    error_type = "api_error"


class LLMUnavailableError(LLMError):
    error_type = "unavailable"


class LLMBudgetExceededError(LLMError):
    error_type = "budget_exceeded"


class LLMRefusalError(LLMError):
    error_type = "refusal"


class LLMOutputError(LLMError):
    error_type = "invalid_output"


@dataclass(frozen=True)
class LLMResult[T: BaseModel]:
    parsed: T
    text: str
    call_id: int
    model: str


@dataclass(frozen=True)
class BudgetState:
    budget: int
    used: int  # finished calls' tokens plus in-flight reservations

    @property
    def remaining(self) -> int:
        return max(0, self.budget - self.used)


def llm_configured(settings: Settings | None = None) -> str | None:
    """None if the LLM stage can run, else the reason it can't."""
    settings = settings or get_settings()
    if not settings.llm_enabled:
        return "LLM enrichment is disabled (LLM_ENABLED=false)."
    if settings.anthropic_api_key is None or not settings.anthropic_api_key.get_secret_value():
        return "No Anthropic API key is configured (ANTHROPIC_API_KEY)."
    return None


def tokens_used(db: Session, scan_id: uuid.UUID) -> int:
    finished = db.scalar(
        select(
            func.coalesce(
                func.sum(
                    LLMCall.input_tokens
                    + LLMCall.output_tokens
                    + LLMCall.cache_creation_input_tokens
                    + LLMCall.cache_read_input_tokens
                ),
                0,
            )
        ).where(LLMCall.scan_id == scan_id, LLMCall.pending.is_(False))
    )
    reserved = db.scalar(
        select(func.coalesce(func.sum(LLMCall.reserved_tokens), 0)).where(
            LLMCall.scan_id == scan_id, LLMCall.pending.is_(True)
        )
    )
    return int(finished or 0) + int(reserved or 0)


def _truncate(text: str | None) -> str | None:
    if text is None or len(text) <= MAX_LOGGED_CHARS:
        return text
    return text[:MAX_LOGGED_CHARS] + f"\n… [{len(text) - MAX_LOGGED_CHARS} characters truncated]"


class LLMClient:
    def __init__(
        self,
        client: anthropic.Anthropic | None = None,
        *,
        settings: Settings | None = None,
        session_factory: sessionmaker[Session] = SessionLocal,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings or get_settings()
        if client is None:
            key = self.settings.anthropic_api_key
            if (reason := llm_configured(self.settings)) or key is None:
                raise LLMUnavailableError(reason or "No Anthropic API key is configured.")
            client = anthropic.Anthropic(
                api_key=key.get_secret_value(),
                timeout=self.settings.llm_timeout_seconds,
            )
        # Retries are ours (logged, budget-aware), not the SDK's.
        self._client = client.with_options(max_retries=0)
        self.model = self.settings.anthropic_model
        self._session_factory = session_factory
        self._sleep = sleep

    # ------------------------------------------------------------------ public

    def budget(self, scan_id: uuid.UUID) -> BudgetState:
        with self._session_factory() as db:
            return BudgetState(self.settings.llm_token_budget_per_scan, tokens_used(db, scan_id))

    def generate_json[T: BaseModel](
        self,
        *,
        scan_id: uuid.UUID,
        purpose: LLMPurpose,
        system: str,
        prompt: str,
        schema: type[T],
        context: dict[str, Any] | None = None,
        max_tokens: int | None = None,
    ) -> LLMResult[T]:
        """Ask for JSON matching `schema`; on unparsable output, ask once more to correct it.

        Raises LLMBudgetExceededError before sending anything that could exceed the
        scan's token budget, LLMRefusalError, LLMOutputError, or LLMError.
        """
        messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
        text, call_id = self._complete(scan_id, purpose, system, messages, context, max_tokens)
        try:
            parsed = parse_model_output(text, schema)
            return LLMResult(parsed, text, call_id, self.model)
        except OutputParseError as exc:
            first_error = str(exc)
        logger.info(
            "scan %s %s: unparsable output (%s), asking again", scan_id, purpose, first_error
        )
        self._mark_failed(call_id, "invalid_output", first_error)

        messages += [
            {"role": "assistant", "content": text or "(empty)"},
            {"role": "user", "content": PARSE_RETRY_INSTRUCTION.format(error=first_error)},
        ]
        retry_context = {**(context or {}), "parse_retry": True}
        text, call_id = self._complete(
            scan_id, purpose, system, messages, retry_context, max_tokens
        )
        try:
            parsed = parse_model_output(text, schema)
        except OutputParseError as second_error:
            self._mark_failed(call_id, "invalid_output", str(second_error))
            raise LLMOutputError(
                f"Unusable model output after one correction attempt: {second_error}"
            ) from second_error
        return LLMResult(parsed, text, call_id, self.model)

    # ------------------------------------------------------------------ internals

    def _request_params(
        self, system: str, messages: list[dict[str, Any]], max_tokens: int
    ) -> dict[str, Any]:
        return {
            "model": self.model,
            "system": system,
            "messages": messages,
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": self.settings.llm_effort},
            "max_tokens": max_tokens,
        }

    def _with_retries(self, operation: Callable[[], Any]) -> tuple[Any, int]:
        """Run `operation`, retrying transient failures. Returns (result, attempts).

        Raises _FailedRequest carrying the final API error and the attempt count.
        """
        attempts = 0
        while True:
            attempts += 1
            try:
                return operation(), attempts
            except anthropic.APIError as exc:
                if not is_retryable(exc) or attempts > self.settings.llm_max_retries:
                    raise _FailedRequest(exc, attempts) from exc
                delay = self._retry_delay(exc, attempts)
                logger.warning(
                    "anthropic request failed (%s), retry %d in %.1fs",
                    type(exc).__name__,
                    attempts,
                    delay,
                )
                self._sleep(delay)

    def _retry_delay(self, exc: Exception, attempt: int) -> float:
        cap = self.settings.llm_retry_max_delay_seconds
        if isinstance(exc, anthropic.APIStatusError):
            retry_after: str | None = exc.response.headers.get("retry-after")
            try:
                if retry_after is not None:
                    return min(cap, max(0.0, float(retry_after)))
            except ValueError:
                pass
        return min(cap, float(2 ** (attempt - 1)) + random.uniform(0, 1))  # noqa: S311 - jitter

    def _reserve(
        self,
        scan_id: uuid.UUID,
        purpose: LLMPurpose,
        prompt_text: str,
        context: dict[str, Any] | None,
        reserve: int,
    ) -> int:
        """Record the call as pending with its worst-case tokens, or refuse it."""
        with self._session_factory() as db:
            # Serialise budget checks for this scan across workers.
            db.execute(select(Scan.id).where(Scan.id == scan_id).with_for_update())
            used = tokens_used(db, scan_id)
            budget = self.settings.llm_token_budget_per_scan
            refused = used + reserve > budget
            call = LLMCall(
                scan_id=scan_id,
                purpose=purpose,
                model=self.model,
                success=False,
                pending=not refused,
                reserved_tokens=0 if refused else reserve,
                error_type="budget_exceeded" if refused else None,
                error_message=(
                    f"Needs up to {reserve:,} tokens but only {max(0, budget - used):,} of the"
                    f" {budget:,} token budget remain."
                    if refused
                    else None
                ),
                prompt=_truncate(prompt_text),
                context=context or {},
            )
            db.add(call)
            db.commit()
            if refused:
                logger.warning(
                    "scan %s: LLM call refused, budget exhausted (%s)", scan_id, call.error_message
                )
                raise LLMBudgetExceededError(call.error_message)
            return call.id

    def _complete(
        self,
        scan_id: uuid.UUID,
        purpose: LLMPurpose,
        system: str,
        messages: list[dict[str, Any]],
        context: dict[str, Any] | None,
        max_tokens: int | None,
    ) -> tuple[str, int]:
        max_tokens = max_tokens or self.settings.llm_max_output_tokens
        params = self._request_params(system, messages, max_tokens)
        prompt_text = "\n\n".join(
            [f"[system]\n{system}"] + [f"[{m['role']}]\n{m['content']}" for m in messages]
        )

        started = time.monotonic()
        try:
            counted, _ = self._with_retries(
                lambda: self._client.messages.count_tokens(
                    model=params["model"],
                    system=params["system"],
                    messages=params["messages"],
                    thinking=params["thinking"],
                )
            )
        except _FailedRequest as failed:
            raise self._record_unsent_failure(
                scan_id, purpose, prompt_text, context, failed.error, started
            ) from failed.error
        call_id = self._reserve(
            scan_id, purpose, prompt_text, context, counted.input_tokens + max_tokens
        )

        try:
            response, attempts = self._with_retries(lambda: self._client.messages.create(**params))
        except _FailedRequest as failed:
            if isinstance(failed.error, anthropic.RateLimitError):
                failure = "rate_limited"
            elif isinstance(failed.error, anthropic.APIConnectionError):
                failure = "connection_error"
            else:
                failure = "api_error"
            self._finish(
                call_id,
                started,
                attempts=failed.attempts,
                success=False,
                error_type=failure,
                error_message=str(failed.error)[:2000],
            )
            raise LLMError(f"Anthropic API request failed: {failed.error}") from failed.error

        usage = response.usage
        text = "".join(block.text for block in response.content if block.type == "text")
        tokens = {
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "cache_creation_input_tokens": usage.cache_creation_input_tokens or 0,
            "cache_read_input_tokens": usage.cache_read_input_tokens or 0,
        }
        stop_reason = response.stop_reason
        error_type: str | None = None
        error_message: str | None = None
        if stop_reason == "refusal":
            error_type, error_message = "refusal", "The model declined this request."
        elif stop_reason == "max_tokens":
            error_type, error_message = "max_tokens", f"Output hit the {max_tokens:,} token limit."
        self._finish(
            call_id,
            started,
            attempts=attempts,
            success=error_type is None,
            error_type=error_type,
            error_message=error_message,
            stop_reason=stop_reason,
            request_id=getattr(response, "_request_id", None),
            response_text=text,
            **tokens,
        )
        if stop_reason == "refusal":
            raise LLMRefusalError("The model declined to answer this request.")
        if stop_reason == "max_tokens":
            raise LLMOutputError(error_message)
        return text, call_id

    def _record_unsent_failure(
        self,
        scan_id: uuid.UUID,
        purpose: LLMPurpose,
        prompt_text: str,
        context: dict[str, Any] | None,
        exc: Exception,
        started: float,
    ) -> LLMError:
        with self._session_factory() as db:
            db.add(
                LLMCall(
                    scan_id=scan_id,
                    purpose=purpose,
                    model=self.model,
                    success=False,
                    error_type="api_error",
                    error_message=f"Token counting failed: {exc}"[:2000],
                    duration_ms=int((time.monotonic() - started) * 1000),
                    prompt=_truncate(prompt_text),
                    context=context or {},
                )
            )
            db.commit()
        return LLMError(f"Anthropic API request failed: {exc}")

    def _finish(self, call_id: int, started: float, **values: Any) -> None:
        with self._session_factory() as db:
            call = db.get(LLMCall, call_id)
            if call is None:  # the scan was deleted mid-call
                return
            for key, value in values.items():
                setattr(call, key, _truncate(value) if key == "response_text" else value)
            call.pending = False
            call.duration_ms = int((time.monotonic() - started) * 1000)
            call.cost_usd = cost_usd(
                call.model,
                call.input_tokens or 0,
                call.output_tokens or 0,
                call.cache_creation_input_tokens or 0,
                call.cache_read_input_tokens or 0,
            )
            db.commit()

    def _mark_failed(self, call_id: int, error_type: str, message: str) -> None:
        with self._session_factory() as db:
            call = db.get(LLMCall, call_id)
            if call is not None:
                call.success = False
                call.error_type = error_type
                call.error_message = message[:2000]
                db.commit()

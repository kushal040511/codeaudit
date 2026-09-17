"""Structured logging, correlation IDs, secret scrubbing and Sentry.

Every log line is one JSON object carrying the current correlation context:
`request_id` (set per HTTP request or propagated into Celery tasks), `task_id`,
`scan_id` and `site_analysis_id`. A request that queues a scan produces API logs,
task logs and analyzer logs that share one `request_id`.

Secrets never reach logs or Sentry: a filter rewrites anything that looks like a
token, key, password or credential in messages and exception text.

Privacy: log statements must not include user code, page content or LLM prompts.
Those live only in the database (prompt/response text on LLMCall rows, with a
retention limit) and object storage.
"""

import contextvars
import json
import logging
import logging.config
import re
import sys
import traceback
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any

from app import __version__
from app.config import get_settings

request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id", default=None
)
task_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("task_id", default=None)
scan_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("scan_id", default=None)
site_analysis_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "site_analysis_id", default=None
)
CONTEXT_VARS = {
    "request_id": request_id_var,
    "task_id": task_id_var,
    "scan_id": scan_id_var,
    "site_analysis_id": site_analysis_id_var,
}
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]{8,128}$")

# Token shapes and credential assignments. Applied to messages, arguments and tracebacks.
SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
        "[github-token]",
    ),
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"), "[anthropic-key]"),
    (re.compile(r"\bcat_[A-Za-z0-9_-]{20,}\b"), "[api-token]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[aws-key]"),
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}"), r"\1 [redacted]"),
    (
        re.compile(
            r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|"
            r"authorization|cookie|dsn)(\"?\s*[:=]\s*\"?)([^\s\"',;&]{4,})"
        ),
        r"\1\2[redacted]",
    ),
    (
        re.compile(r"(?i)(postgres(?:ql)?(?:\+\w+)?|redis|amqp|https?)://([^:/@\s]+):([^@/\s]+)@"),
        r"\1://\2:[redacted]@",
    ),
)


def scrub(text: str) -> str:
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def current_context() -> dict[str, str]:
    return {name: value for name, var in CONTEXT_VARS.items() if (value := var.get())}


@contextmanager
def bind(**values: str | None) -> Iterator[None]:
    """Temporarily set correlation fields, e.g. `with bind(scan_id=str(scan.id)):`."""
    tokens = [
        (CONTEXT_VARS[name], CONTEXT_VARS[name].set(value))
        for name, value in values.items()
        if name in CONTEXT_VARS
    ]
    try:
        yield
    finally:
        for var, token in reversed(tokens):
            var.reset(token)


class JsonFormatter(logging.Formatter):
    RESERVED = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
        "message",
        "asctime",
    }

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": scrub(record.getMessage()),
            **current_context(),
        }
        for key, value in record.__dict__.items():
            if key not in self.RESERVED and not key.startswith("_") and key not in payload:
                payload[key] = scrub(str(value)) if isinstance(value, str) else value
        if record.exc_info:
            payload["exception"] = scrub(
                "".join(traceback.format_exception(*record.exc_info))[-8000:]
            )
        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    """Readable development output with the same scrubbing and context."""

    def format(self, record: logging.LogRecord) -> str:
        context = " ".join(f"{k}={v[:12]}" for k, v in current_context().items())
        line = f"{record.levelname[:5]:<5} [{record.name}] {scrub(record.getMessage())}"
        if context:
            line += f"  ({context})"
        if record.exc_info:
            line += "\n" + scrub("".join(traceback.format_exception(*record.exc_info)))
        return line


class ScrubFilter(logging.Filter):
    """For handlers we don't format ourselves (e.g. third-party): scrub the message in place."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = scrub(record.msg)
        if record.args:
            record.args = (
                tuple(scrub(a) if isinstance(a, str) else a for a in record.args)
                if isinstance(record.args, tuple)
                else record.args
            )
        return True


def configure_logging() -> None:
    settings = get_settings()
    formatter = "json" if settings.log_format == "json" else "text"
    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "filters": {"scrub": {"()": ScrubFilter}},
            "formatters": {"json": {"()": JsonFormatter}, "text": {"()": TextFormatter}},
            "handlers": {
                "stdout": {
                    "class": "logging.StreamHandler",
                    "stream": sys.stdout,
                    "formatter": formatter,
                    "filters": ["scrub"],
                }
            },
            "root": {"level": settings.log_level, "handlers": ["stdout"]},
            "loggers": {
                # Request lines are emitted by our own middleware (with status and timing).
                "uvicorn.access": {"level": "WARNING"},
                "httpx": {"level": "WARNING"},
                "httpx2": {"level": "WARNING"},
                "botocore": {"level": "WARNING"},
                "urllib3": {"level": "WARNING"},
                "docker": {"level": "WARNING"},
            },
        }
    )


# ------------------------------------------------------------------ Sentry


def _scrub_event(value: Any) -> Any:
    if isinstance(value, str):
        return scrub(value)
    if isinstance(value, dict):
        return {
            k: (
                "[redacted]"
                if re.search(r"(?i)token|secret|password|authorization|cookie|key|dsn|csrf", str(k))
                else _scrub_event(v)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_scrub_event(v) for v in value]
    return value


def before_send(event: dict[str, Any], hint: dict[str, Any]) -> dict[str, Any] | None:
    """Drop request bodies (uploaded code, URLs to analyze) and scrub everything else."""
    request = event.get("request")
    if isinstance(request, dict):
        request.pop("data", None)
        request.pop("cookies", None)
        headers = request.get("headers") or {}
        request["headers"] = {
            k: v
            for k, v in headers.items()
            if k.lower() not in {"authorization", "cookie", "x-csrf-token"}
        }
    for frame_container in (event.get("exception") or {}).get("values") or []:
        for frame in (frame_container.get("stacktrace") or {}).get("frames") or []:
            frame.pop("vars", None)  # local variables can hold code, tokens, page content
    return _scrub_event(event)  # type: ignore[no-any-return]


def init_sentry(component: str) -> bool:
    settings = get_settings()
    if settings.sentry_dsn is None or not settings.sentry_dsn.get_secret_value():
        return False
    import sentry_sdk
    from sentry_sdk.integrations.celery import CeleryIntegration
    from sentry_sdk.integrations.fastapi import FastApiIntegration
    from sentry_sdk.integrations.logging import LoggingIntegration

    sentry_sdk.init(
        dsn=settings.sentry_dsn.get_secret_value(),
        environment=settings.environment,
        release=f"codeaudit@{__version__}",
        send_default_pii=False,
        include_local_variables=False,
        max_request_body_size="never",
        traces_sample_rate=settings.sentry_traces_sample_rate,
        before_send=before_send,  # type: ignore[arg-type]
        integrations=[
            FastApiIntegration(),
            CeleryIntegration(),
            LoggingIntegration(level=logging.INFO, event_level=logging.ERROR),
        ],
    )
    sentry_sdk.set_tag("component", component)
    return True

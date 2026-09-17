from fastapi import HTTPException, status
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.errors import error_response
from app.config import get_settings


class BodySizeLimitMiddleware:
    """Reject request bodies over `max_bytes` without buffering them.

    Checks Content-Length up front, then counts bytes as they stream in, which
    also catches chunked uploads and lying headers. Multipart parsing spools
    uploads to disk past 1 MB, so this bounds both memory and disk use.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        message = f"Request body exceeds the {self.max_bytes // (1024 * 1024)} MB limit."
        content_length = Headers(scope=scope).get("content-length")
        if content_length is not None and content_length.isdigit():
            if int(content_length) > self.max_bytes:
                response = error_response(413, "payload_too_large", message)
                await response(scope, receive, send)
                return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            msg = await receive()
            if msg["type"] == "http.request":
                received += len(msg.get("body", b""))
                if received > self.max_bytes:
                    # FastAPI re-raises HTTPException from body parsing, so this
                    # reaches the normal exception handlers as a 413.
                    raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, detail=message)
            return msg

        await self.app(scope, limited_receive, send)


class RequestContextMiddleware:
    """Correlation ID, access log, HTTP metrics, security and rate-limit headers.

    - `X-Request-ID`: taken from the client if well-formed, otherwise generated, then
      bound to every log line (and propagated into Celery tasks) and echoed back.
    - Security headers on every API response. The API serves JSON and images only,
      so its CSP forbids everything; the frontend's CSP is set by the reverse proxy.
    - `X-RateLimit-*` headers from whatever limit the request consumed (quotas.py).
    """

    SECURITY_HEADERS: tuple[tuple[bytes, bytes], ...] = (
        (b"x-content-type-options", b"nosniff"),
        (b"x-frame-options", b"DENY"),
        (b"referrer-policy", b"no-referrer"),
        (b"cross-origin-opener-policy", b"same-origin"),
        (b"cross-origin-resource-policy", b"same-site"),
        (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
    )

    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        import logging
        import time
        import uuid

        from app.core import metrics
        from app.core.observability import REQUEST_ID_PATTERN, request_id_var
        from app.services.quotas import consumed_limits_var

        incoming = Headers(scope=scope).get("x-request-id", "")
        request_id = incoming if REQUEST_ID_PATTERN.match(incoming) else uuid.uuid4().hex
        token = request_id_var.set(request_id)
        limits_token = consumed_limits_var.set([])
        started = time.perf_counter()
        status_code = 500
        path = scope.get("path", "")

        async def send_with_headers(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = list(message.get("headers", []))
                existing = {name.lower() for name, _ in headers}
                headers.append((b"x-request-id", request_id.encode()))
                for name, value in self.SECURITY_HEADERS:
                    if name not in existing:
                        headers.append((name, value))
                if b"content-security-policy" not in existing:
                    headers.append(
                        (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'")
                    )
                if self.hsts:
                    headers.append(
                        (b"strict-transport-security", b"max-age=63072000; includeSubDomains")
                    )
                for name, value in rate_limit_headers(consumed_limits_var.get() or []):
                    headers.append((name, value))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        finally:
            elapsed = time.perf_counter() - started
            route = scope.get("route")
            template = getattr(route, "path", None) or (
                "/unmatched" if status_code == 404 else "/other"
            )
            # Routes in included routers report their path without the API prefix.
            prefix = get_settings().api_prefix
            if path.startswith(prefix + "/") and not template.startswith(("/unmatched", "/other")):
                template = template if template.startswith(prefix) else prefix + template
            method = scope.get("method", "GET")
            metrics.http_requests.labels(method, template, str(status_code)).inc()
            metrics.http_duration.labels(method, template).observe(elapsed)
            if not path.startswith(("/metrics", "/health", "/ready")):
                logging.getLogger("codeaudit.access").info(
                    "%s %s %s %.0fms",
                    method,
                    template,
                    status_code,
                    elapsed * 1000,
                    extra={
                        "http_status": status_code,
                        "route": template,
                        "duration_ms": round(elapsed * 1000, 1),
                    },
                )
            consumed_limits_var.reset(limits_token)
            request_id_var.reset(token)


def rate_limit_headers(consumed: list["LimitState"]) -> list[tuple[bytes, bytes]]:  # type: ignore[name-defined]  # noqa: F821
    """Headers for the most constrained limit this request consumed."""
    if not consumed:
        return []
    tightest = min(
        consumed, key=lambda state: (state.remaining / max(state.limit, 1), state.reset_seconds)
    )
    return [
        (b"x-ratelimit-limit", str(tightest.limit).encode()),
        (b"x-ratelimit-remaining", str(max(0, tightest.remaining)).encode()),
        (b"x-ratelimit-reset", str(tightest.reset_seconds).encode()),
        (b"x-ratelimit-policy", tightest.name.encode()),
    ]

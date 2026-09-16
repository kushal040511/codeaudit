from fastapi import HTTPException, status
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.api.errors import error_response


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

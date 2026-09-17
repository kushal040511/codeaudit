"""Error types shared by services, workers and the API (no web framework imports)."""

from http import HTTPStatus
from typing import Any


class TransientInfraError(Exception):
    """An infrastructure hiccup (database, object storage, Docker daemon, rule registry).

    The same scan may succeed if retried.
    """


class AnalysisError(Exception):
    """The scan itself failed (unsafe archive, analyzer crash or timeout).

    Retrying will not help; the message is shown to the user.
    """


class AnalyzerTimeoutError(AnalysisError):
    """An analyzer exceeded its time limit and was stopped."""


# ---------------------------------------------------------------- user-facing errors
# Rendered by app.api.errors as {"error": {code, message, details}}.


class AppError(Exception):
    """Expected, user-facing error. Rendered as {"error": {"code", "message", "details"}}."""

    status_code: int = HTTPStatus.BAD_REQUEST
    code: str = "bad_request"

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        details: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        if code is not None:
            self.code = code
        self.details = details
        self.headers = headers or {}


class NotFoundError(AppError):
    status_code = HTTPStatus.NOT_FOUND
    code = "not_found"


class ConflictError(AppError):
    status_code = HTTPStatus.CONFLICT
    code = "conflict"


class UnauthorizedError(AppError):
    status_code = HTTPStatus.UNAUTHORIZED
    code = "unauthorized"


class ForbiddenError(AppError):
    status_code = HTTPStatus.FORBIDDEN
    code = "forbidden"


class RateLimitedError(AppError):
    status_code = HTTPStatus.TOO_MANY_REQUESTS
    code = "rate_limited"


class PayloadTooLargeError(AppError):
    status_code = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    code = "payload_too_large"


class ServiceUnavailableError(AppError):
    status_code = HTTPStatus.SERVICE_UNAVAILABLE
    code = "service_unavailable"

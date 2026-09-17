"""Per-request rate limit applied to every API route (see app.main)."""

from fastapi import Request

from app.models import User
from app.services.quotas import client_ip, consume, subject_for


def request_rate_limit(request: Request) -> None:
    """Router dependency: per-user or per-IP request rate for every API call."""
    from app.api.deps import get_principal
    from app.core.db import SessionLocal

    if request.url.path.endswith(("/auth/config", "/auth/github/callback")):
        return
    session_cookie = request.cookies.get("codeaudit_session")
    user: User | None = None
    if session_cookie or request.headers.get("authorization"):
        with SessionLocal() as db:
            try:
                principal = get_principal(request, db)
            except Exception:  # noqa: BLE001 - authentication errors are raised by the route itself
                principal = None
            if principal is not None:
                user = principal.user
                db.expunge(user)
    consume(subject_for(user, client_ip(request)), "requests")

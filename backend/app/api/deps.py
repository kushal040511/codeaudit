"""Request authentication, CSRF protection and scan ownership."""

import uuid
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.api.errors import ForbiddenError, NotFoundError, UnauthorizedError
from app.core.db import get_db
from app.models import Scan, User
from app.services.auth.crypto import secrets_equal
from app.services.auth.sessions import (
    API_TOKEN_PREFIX,
    CSRF_HEADER,
    SESSION_COOKIE,
    Principal,
    session_for,
    user_for_api_token,
)

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def get_principal(request: Request, db: Annotated[Session, Depends(get_db)]) -> Principal | None:
    """The authenticated caller, or None.

    `Authorization: Bearer cat_...` authenticates with an API token (no CSRF: not
    ambient). The session cookie authenticates browsers; state-changing requests
    made with it must echo the session's CSRF token in X-CSRF-Token.
    """
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        secret = authorization[7:].strip()
        user = user_for_api_token(db, secret) if secret.startswith(API_TOKEN_PREFIX) else None
        if user is None:
            raise UnauthorizedError("Invalid or revoked API token.", code="invalid_token")
        return Principal(user=user, via="api_token")

    session = session_for(db, request.cookies.get(SESSION_COOKIE))
    if session is None:
        return None
    if request.method not in SAFE_METHODS:
        sent = request.headers.get(CSRF_HEADER, "")
        if not sent or not secrets_equal(sent, session.csrf_token):
            raise ForbiddenError("Missing or invalid CSRF token.", code="csrf_failed")
    user = db.get(User, session.user_id)
    if user is None:
        return None
    return Principal(user=user, via="session", session=session)


OptionalPrincipal = Annotated[Principal | None, Depends(get_principal)]


def require_principal(principal: OptionalPrincipal) -> Principal:
    if principal is None:
        raise UnauthorizedError("Sign in first.")
    return principal


CurrentPrincipal = Annotated[Principal, Depends(require_principal)]


def require_session(principal: CurrentPrincipal) -> Principal:
    """Signed in through the web app. API tokens (automation) can't manage the account or
    write to GitHub, so a leaked CI token can't open pull requests or mint more tokens."""
    if principal.via != "session":
        raise ForbiddenError(
            "This action is only available when signed in through the web app.",
            code="session_required",
        )
    return principal


SessionPrincipal = Annotated[Principal, Depends(require_session)]


def load_scan(db: Session, scan_id: uuid.UUID, principal: Principal | None) -> Scan:
    """The scan, if the caller may read it.

    Owned scans are visible only to their owner; anonymous scans to anyone who
    has the id. Others get 404 (not 403) so scan ids can't be probed.
    """
    scan = db.get(Scan, scan_id)
    if scan is None or (
        scan.user_id is not None and (principal is None or principal.user.id != scan.user_id)
    ):
        raise NotFoundError(f"Scan {scan_id} not found.")
    return scan


def load_owned_scan(db: Session, scan_id: uuid.UUID, principal: Principal) -> Scan:
    """The scan, if the caller owns it (required for anything that writes elsewhere)."""
    scan = load_scan(db, scan_id, principal)
    if scan.user_id != principal.user.id:
        raise NotFoundError(f"Scan {scan_id} not found.")
    return scan

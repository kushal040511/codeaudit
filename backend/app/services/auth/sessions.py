"""Sessions, API tokens and the request's authenticated user."""

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import ApiToken, User, UserSession
from app.services.auth.crypto import hash_secret, new_secret

SESSION_COOKIE = "codeaudit_session"
OAUTH_STATE_COOKIE = "codeaudit_oauth_state"
CSRF_HEADER = "X-CSRF-Token"
API_TOKEN_PREFIX = "cat_"  # noqa: S105 - a prefix, not a secret


@dataclass(frozen=True)
class Principal:
    user: User
    via: str  # "session" | "api_token"
    session: UserSession | None = None


def create_session(db: Session, user: User) -> tuple[str, UserSession]:
    secret = new_secret(nbytes=32)
    session = UserSession(
        user_id=user.id,
        token_hash=hash_secret(secret),
        csrf_token=new_secret(nbytes=24),
        expires_at=datetime.now(UTC) + timedelta(hours=get_settings().session_ttl_hours),
    )
    db.add(session)
    db.commit()
    return secret, session


def session_for(db: Session, secret: str | None) -> UserSession | None:
    if not secret:
        return None
    session = db.scalar(select(UserSession).where(UserSession.token_hash == hash_secret(secret)))
    if session is None or session.expires_at <= datetime.now(UTC):
        return None
    return session


def end_session(db: Session, session: UserSession) -> None:
    db.execute(delete(UserSession).where(UserSession.id == session.id))
    db.commit()


def create_api_token(db: Session, user_id: uuid.UUID, name: str) -> tuple[str, ApiToken]:
    secret = new_secret(API_TOKEN_PREFIX, nbytes=32)
    token = ApiToken(user_id=user_id, name=name, token_hash=hash_secret(secret), prefix=secret[:10])
    db.add(token)
    db.commit()
    return secret, token


def user_for_api_token(db: Session, secret: str) -> User | None:
    token = db.scalar(
        select(ApiToken).where(
            ApiToken.token_hash == hash_secret(secret), ApiToken.revoked_at.is_(None)
        )
    )
    if token is None:
        return None
    token.last_used_at = datetime.now(UTC)
    db.commit()
    return db.get(User, token.user_id)

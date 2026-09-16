"""GitHub OAuth (web application flow) and token lifecycle.

- State: a random single-use value stored in Redis (10 min) *and* in an HttpOnly
  cookie; the callback requires both to match (CSRF / login fixation).
- Scopes: `read:user public_repo` by default; `read:user repo` only when the user
  asks to connect private repositories.
- Tokens are Fernet-encrypted at rest. Expiring tokens are refreshed shortly
  before expiry; a failed refresh disconnects the identity.
- Disconnect revokes the grant at GitHub, then deletes the stored tokens.
"""

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import urlencode

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.redis_client import get_redis
from app.models import GitHubIdentity, User
from app.services.auth.crypto import decrypt_token, encrypt_token, new_secret, secrets_equal
from app.services.github.client import (
    GitHubAuthError,
    GitHubClient,
    GitHubUnavailableError,
    transport_override,
)

logger = logging.getLogger(__name__)

PUBLIC_SCOPES = ("read:user", "public_repo")
PRIVATE_SCOPES = ("read:user", "repo")
STATE_TTL_SECONDS = 600
STATE_KEY = "codeaudit:oauth_state:{}"
REFRESH_MARGIN = timedelta(minutes=5)


class OAuthError(Exception):
    """User-facing OAuth failure; `code` is stable."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class OAuthStart:
    authorize_url: str
    state: str


def oauth_configured() -> bool:
    settings = get_settings()
    return bool(
        settings.github_client_id
        and settings.github_client_secret
        and settings.github_client_secret.get_secret_value()
        and settings.token_encryption_keys
    )


def safe_next_path(next_path: str | None) -> str:
    """Only same-site relative paths (no open redirects)."""
    if (
        not next_path
        or not next_path.startswith("/")
        or next_path.startswith("//")
        or "\\" in next_path
    ):
        return "/settings"
    return next_path[:500]


def start_authorization(redirect_uri: str, *, private: bool, next_path: str | None) -> OAuthStart:
    settings = get_settings()
    state = new_secret(nbytes=24)
    record = {"private": private, "next": safe_next_path(next_path)}
    get_redis().set(STATE_KEY.format(state), json.dumps(record), ex=STATE_TTL_SECONDS)
    query = urlencode(
        {
            "client_id": settings.github_client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(PRIVATE_SCOPES if private else PUBLIC_SCOPES),
            "state": state,
            "allow_signup": "false",
        }
    )
    return OAuthStart(f"{settings.github_oauth_url}/login/oauth/authorize?{query}", state)


def consume_state(state: str | None, cookie_state: str | None) -> dict[str, Any]:
    """Validate and delete the state (single use). Raises OAuthError."""
    if not state or not cookie_state or not secrets_equal(state, cookie_state):
        raise OAuthError(
            "invalid_oauth_state",
            "Sign-in request expired or didn't start in this browser. Try again.",
        )
    raw = cast(bytes | None, get_redis().getdel(STATE_KEY.format(state)))
    if raw is None:
        raise OAuthError(
            "invalid_oauth_state", "Sign-in request expired or was already used. Try again."
        )
    return dict(json.loads(raw))


def _token_request(
    data: dict[str, str], transport: httpx.BaseTransport | None = None
) -> dict[str, Any]:
    settings = get_settings()
    if settings.github_client_secret is None:
        raise OAuthError(
            "github_not_configured", "GitHub sign-in is not configured on this server."
        )
    try:
        with httpx.Client(
            timeout=settings.github_timeout_seconds,
            follow_redirects=False,
            transport=transport or transport_override(),
        ) as http:
            response = http.post(
                f"{settings.github_oauth_url}/login/oauth/access_token",
                data={
                    "client_id": settings.github_client_id or "",
                    "client_secret": settings.github_client_secret.get_secret_value(),
                    **data,
                },
                headers={"Accept": "application/json"},
            )
    except httpx.HTTPError:
        raise OAuthError("github_unavailable", "Could not reach GitHub. Try again later.") from None
    payload = response.json() if response.content else {}
    if response.status_code != 200 or "access_token" not in payload:
        # GitHub returns 200 with {"error": ...} for bad codes; never echo the request.
        error = str(payload.get("error", f"http_{response.status_code}"))[:64]
        raise OAuthError(
            "oauth_exchange_failed", f"GitHub didn't accept the sign-in ({error}). Try again."
        )
    return dict(payload)


def _expiry(seconds: Any) -> datetime | None:
    return datetime.now(UTC) + timedelta(seconds=int(seconds)) if seconds else None


def _store_tokens(identity: GitHubIdentity, payload: dict[str, Any]) -> None:
    identity.access_token_encrypted = encrypt_token(payload["access_token"])
    identity.access_token_expires_at = _expiry(payload.get("expires_in"))
    if payload.get("refresh_token"):
        identity.refresh_token_encrypted = encrypt_token(payload["refresh_token"])
        identity.refresh_token_expires_at = _expiry(payload.get("refresh_token_expires_in"))
    scope = payload.get("scope")
    if isinstance(scope, str):
        identity.scopes = sorted({s for s in scope.replace(",", " ").split() if s})


def complete_authorization(
    db: Session,
    code: str,
    redirect_uri: str,
    current_user: User | None,
    *,
    transport: httpx.BaseTransport | None = None,
) -> User:
    """Exchange the code, fetch the GitHub user, create or update the user and identity."""
    payload = _token_request({"code": code, "redirect_uri": redirect_uri}, transport)
    with GitHubClient(payload["access_token"], transport=transport) as github:
        profile = github.get_authenticated_user()

    identity = db.scalar(
        select(GitHubIdentity).where(GitHubIdentity.github_user_id == int(profile["id"]))
    )
    user: User | None
    if identity is None:
        user = current_user or User(
            id=uuid.uuid4(), display_name=profile.get("name") or profile["login"]
        )
        if current_user is None:
            db.add(user)
        identity = GitHubIdentity(
            user_id=user.id, github_user_id=int(profile["id"]), login=profile["login"]
        )
        db.add(identity)
    elif current_user is not None and identity.user_id != current_user.id:
        raise OAuthError(
            "github_account_in_use",
            "That GitHub account is already connected to another CodeAudit user.",
        )
    else:
        user = db.get(User, identity.user_id)
    if user is None:
        raise OAuthError(
            "oauth_exchange_failed", "Could not find the user for this GitHub account."
        )
    identity.login = profile["login"]
    _store_tokens(identity, payload)
    identity.connected_at = datetime.now(UTC)
    user.display_name = profile.get("name") or profile["login"]
    user.avatar_url = profile.get("avatar_url")
    user.last_login_at = datetime.now(UTC)
    db.commit()
    logger.info("github identity %s connected with scopes %s", identity.login, identity.scopes)
    return user


def access_token(
    db: Session, identity: GitHubIdentity, *, transport: httpx.BaseTransport | None = None
) -> str:
    """A usable access token, refreshing an expiring one. Raises GitHubAuthError."""
    if identity.access_token_encrypted is None:
        raise GitHubAuthError("GitHub is not connected. Connect GitHub in Settings.")
    expires = identity.access_token_expires_at
    if expires is None or expires - REFRESH_MARGIN > datetime.now(UTC):
        return decrypt_token(identity.access_token_encrypted)

    refresh_expired = (
        identity.refresh_token_expires_at is not None
        and identity.refresh_token_expires_at <= datetime.now(UTC)
    )
    if identity.refresh_token_encrypted is None or refresh_expired:
        disconnect_locally(db, identity)
        raise GitHubAuthError("Your GitHub authorization expired. Reconnect GitHub in Settings.")
    try:
        payload = _token_request(
            {
                "grant_type": "refresh_token",
                "refresh_token": decrypt_token(identity.refresh_token_encrypted),
            },
            transport,
        )
    except OAuthError as exc:
        if exc.code == "github_unavailable":
            raise GitHubUnavailableError(exc.message) from None
        disconnect_locally(db, identity)
        raise GitHubAuthError(
            "Refreshing your GitHub authorization failed. Reconnect GitHub in Settings."
        ) from None
    _store_tokens(identity, payload)
    db.commit()
    return str(payload["access_token"])


def disconnect_locally(db: Session, identity: GitHubIdentity) -> None:
    identity.access_token_encrypted = None
    identity.refresh_token_encrypted = None
    identity.access_token_expires_at = None
    identity.refresh_token_expires_at = None
    identity.scopes = []
    identity.connected_at = None
    db.commit()


def revoke_and_disconnect(
    db: Session, identity: GitHubIdentity, *, transport: httpx.BaseTransport | None = None
) -> bool:
    """Revoke the OAuth grant at GitHub, then delete stored tokens.

    Returns whether GitHub confirmed the revocation; tokens are deleted either way.
    """
    settings = get_settings()
    revoked = False
    if identity.access_token_encrypted is not None and settings.github_client_secret is not None:
        token = decrypt_token(identity.access_token_encrypted)
        try:
            with httpx.Client(
                timeout=settings.github_timeout_seconds,
                follow_redirects=False,
                transport=transport or transport_override(),
            ) as http:
                response = http.request(
                    "DELETE",
                    f"{settings.github_api_url}/applications/{settings.github_client_id}/grant",
                    auth=(
                        settings.github_client_id or "",
                        settings.github_client_secret.get_secret_value(),
                    ),
                    json={"access_token": token},
                    headers={"Accept": "application/vnd.github+json"},
                )
            # 404: already revoked at GitHub.
            revoked = response.status_code in (204, 404)
            if not revoked:
                logger.warning(
                    "revoking github grant for %s returned %d", identity.login, response.status_code
                )
        except httpx.HTTPError:
            logger.warning("could not reach github to revoke grant for %s", identity.login)
    disconnect_locally(db, identity)
    return revoked

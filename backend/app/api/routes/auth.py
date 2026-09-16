import logging
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal, OptionalPrincipal, SessionPrincipal
from app.api.errors import AppError, NotFoundError, ServiceUnavailableError
from app.config import get_settings
from app.core.db import get_db
from app.models import ApiToken, GitHubIdentity, User
from app.schemas.auth import (
    ApiTokenCreate,
    ApiTokenCreated,
    ApiTokenRead,
    AuthConfigRead,
    GitHubConnectionRead,
    GitHubRepoRead,
    MeRead,
)
from app.services.auth.oauth import (
    OAuthError,
    access_token,
    complete_authorization,
    consume_state,
    oauth_configured,
    revoke_and_disconnect,
    safe_next_path,
    start_authorization,
)
from app.services.auth.sessions import (
    OAUTH_STATE_COOKIE,
    SESSION_COOKIE,
    create_api_token,
    create_session,
    end_session,
    session_for,
)
from app.services.github.client import GitHubClient, GitHubError
from app.services.scan_creation import GitHubApiError

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])
DbSession = Annotated[Session, Depends(get_db)]


def _callback_url(request: Request) -> str:
    return str(request.url_for("github_callback"))


def _frontend(path: str, **params: str) -> str:
    base = get_settings().frontend_url.rstrip("/")
    return f"{base}{path}" + (f"?{urlencode(params)}" if params else "")


@router.get("/config", response_model=AuthConfigRead)
def auth_config() -> AuthConfigRead:
    return AuthConfigRead(github_enabled=oauth_configured())


@router.get("/github/login")
def github_login(
    request: Request,
    private: Annotated[
        bool, Query(description="Request the `repo` scope for private repositories")
    ] = False,
    next: Annotated[str | None, Query(max_length=500)] = None,
) -> RedirectResponse:
    """Redirect to GitHub. Public access asks for `read:user public_repo`; private for `repo`."""
    if not oauth_configured():
        raise ServiceUnavailableError(
            "GitHub sign-in is not configured on this server.", code="github_not_configured"
        )
    start = start_authorization(_callback_url(request), private=private, next_path=next)
    response = RedirectResponse(start.authorize_url, status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        OAUTH_STATE_COOKIE,
        start.state,
        max_age=600,
        httponly=True,
        secure=get_settings().session_cookie_secure,
        samesite="lax",
        path="/api/auth/github",
    )
    return response


@router.get("/github/callback", name="github_callback")
def github_callback(
    request: Request,
    db: DbSession,
    code: Annotated[str | None, Query(max_length=200)] = None,
    state: Annotated[str | None, Query(max_length=200)] = None,
    error: Annotated[str | None, Query(max_length=100)] = None,
) -> RedirectResponse:
    """GitHub redirects here. Validates state, exchanges the code, starts a session."""
    settings = get_settings()
    cookie_state = request.cookies.get(OAUTH_STATE_COOKIE)

    def fail(code_: str) -> RedirectResponse:
        response = RedirectResponse(_frontend("/settings", github_error=code_), status_code=302)
        response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/auth/github")
        return response

    try:
        record = consume_state(state, cookie_state)
    except OAuthError as exc:
        logger.warning("github oauth callback rejected: %s", exc.code)
        return fail(exc.code)
    if error or not code:
        return fail("access_denied" if error == "access_denied" else "oauth_failed")

    current = session_for(db, request.cookies.get(SESSION_COOKIE))
    current_user = db.get(User, current.user_id) if current is not None else None
    try:
        user = complete_authorization(db, code, _callback_url(request), current_user)
    except OAuthError as exc:
        db.rollback()
        logger.warning("github oauth completion failed: %s", exc.code)
        return fail(exc.code)
    except GitHubError as exc:
        db.rollback()
        return fail(exc.code)

    response = RedirectResponse(_frontend(safe_next_path(record.get("next"))), status_code=302)
    response.delete_cookie(OAUTH_STATE_COOKIE, path="/api/auth/github")
    if current is None or current_user is None or current_user.id != user.id:
        secret, _ = create_session(db, user)
        response.set_cookie(
            SESSION_COOKIE,
            secret,
            max_age=settings.session_ttl_hours * 3600,
            httponly=True,
            secure=settings.session_cookie_secure,
            samesite="lax",
            path="/",
        )
    return response


@router.get("/me", response_model=MeRead, responses={401: {}})
def me(principal: CurrentPrincipal, db: DbSession) -> MeRead:
    identity = db.scalar(select(GitHubIdentity).where(GitHubIdentity.user_id == principal.user.id))
    return MeRead(
        id=str(principal.user.id),
        display_name=principal.user.display_name,
        avatar_url=principal.user.avatar_url,
        github=(
            GitHubConnectionRead(
                login=identity.login,
                connected=identity.access_token_encrypted is not None,
                scopes=identity.scopes,
                private_repo_access="repo" in identity.scopes,
                token_expires_at=identity.access_token_expires_at,
            )
            if identity
            else None
        ),
        csrf_token=principal.session.csrf_token if principal.session else None,
        auth_method=principal.via,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(principal: OptionalPrincipal, db: DbSession) -> Response:
    if principal is not None and principal.session is not None:
        end_session(db, principal.session)
    response = Response(status_code=status.HTTP_204_NO_CONTENT)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@router.delete("/github", status_code=status.HTTP_200_OK)
def disconnect_github(principal: SessionPrincipal, db: DbSession) -> dict[str, bool]:
    """Revoke the OAuth grant at GitHub and delete the stored tokens."""
    identity = db.scalar(select(GitHubIdentity).where(GitHubIdentity.user_id == principal.user.id))
    if identity is None:
        raise NotFoundError("GitHub is not connected.")
    revoked = revoke_and_disconnect(db, identity)
    return {"disconnected": True, "revoked_at_github": revoked}


@router.get("/github/repos", response_model=list[GitHubRepoRead])
def list_github_repos(
    principal: CurrentPrincipal,
    db: DbSession,
    page: Annotated[int, Query(ge=1, le=100)] = 1,
) -> list[GitHubRepoRead]:
    """Repositories the connected account can access, most recently pushed first."""
    identity = db.scalar(select(GitHubIdentity).where(GitHubIdentity.user_id == principal.user.id))
    if identity is None or identity.access_token_encrypted is None:
        raise AppError("Connect GitHub first.", code="github_auth_required")
    try:
        with GitHubClient(access_token(db, identity)) as github:
            repos = github.list_user_repos(page=page)
    except GitHubError as exc:
        raise GitHubApiError(exc) from None
    return [
        GitHubRepoRead(
            full_name=r["full_name"],
            private=bool(r.get("private")),
            default_branch=r.get("default_branch") or "main",
            description=r.get("description"),
            pushed_at=r.get("pushed_at"),
            html_url=r["html_url"],
        )
        for r in repos
    ]


@router.get("/tokens", response_model=list[ApiTokenRead])
def list_tokens(principal: SessionPrincipal, db: DbSession) -> list[ApiTokenRead]:
    tokens = db.scalars(
        select(ApiToken)
        .where(ApiToken.user_id == principal.user.id)
        .order_by(ApiToken.created_at.desc())
    ).all()
    return [ApiTokenRead.model_validate(t) for t in tokens]


@router.post("/tokens", response_model=ApiTokenCreated, status_code=status.HTTP_201_CREATED)
def create_token(
    body: ApiTokenCreate, principal: SessionPrincipal, db: DbSession
) -> ApiTokenCreated:
    """Create an API token (e.g. for the GitHub Action). The secret is returned once."""
    secret, token = create_api_token(db, principal.user.id, body.name)
    return ApiTokenCreated(**ApiTokenRead.model_validate(token).model_dump(), token=secret)


@router.delete("/tokens/{token_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_token(token_id: int, principal: SessionPrincipal, db: DbSession) -> Response:
    token = db.get(ApiToken, token_id)
    if token is None or token.user_id != principal.user.id:
        raise NotFoundError("API token not found.")
    token.revoked_at = token.revoked_at or datetime.now(UTC)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)

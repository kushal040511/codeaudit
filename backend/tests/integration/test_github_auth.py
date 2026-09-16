"""GitHub OAuth, sessions, CSRF and token handling (Postgres + Redis, GitHub faked)."""

from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.db import SessionLocal
from app.models import GitHubIdentity
from app.services.auth.crypto import decrypt_token, encrypt_token
from app.services.auth.oauth import access_token
from app.services.auth.sessions import OAUTH_STATE_COOKIE, SESSION_COOKIE
from app.services.github.client import GitHubAuthError
from tests.github_fakes import FakeGitHub
from tests.integration.conftest import SignedIn, SignIn

pytestmark = pytest.mark.integration


@pytest.fixture
def web(database: None, redis_clean: None, fake_github: FakeGitHub) -> TestClient:
    from app.main import app

    with TestClient(app, follow_redirects=False) as client:
        yield client  # type: ignore[misc]


def start_login(web: TestClient, **params: str) -> tuple[str, dict[str, list[str]]]:
    response = web.get("/api/auth/github/login", params=params)
    assert response.status_code == 302
    location = urlsplit(response.headers["location"])
    assert f"{location.scheme}://{location.netloc}{location.path}" == (
        "https://github.com/login/oauth/authorize"
    )
    query = parse_qs(location.query)
    return query["state"][0], query


def test_login_requests_minimal_scopes(web: TestClient) -> None:
    _, public = start_login(web)
    assert public["scope"] == ["read:user public_repo"]
    assert public["redirect_uri"] == ["http://testserver/api/auth/github/callback"]
    _, private = start_login(web, private="true")
    assert private["scope"] == ["read:user repo"]


def test_full_oauth_flow_encrypts_token_and_never_exposes_it(
    web: TestClient, fake_github: FakeGitHub
) -> None:
    token = "gho_flowTokenABCDEF1234567890"  # noqa: S105
    fake_github.add_user("octo", token, user_id=4242)
    fake_github.oauth_codes["good-code"] = {
        "access_token": token,
        "token_type": "bearer",
        "scope": "public_repo,read:user",
    }
    state, _ = start_login(web, next="/scans")

    callback = web.get("/api/auth/github/callback", params={"code": "good-code", "state": state})
    assert callback.status_code == 302
    assert callback.headers["location"] == "http://frontend.test/scans"
    assert SESSION_COOKIE in callback.cookies
    assert token not in callback.text and token not in str(callback.headers)

    with SessionLocal() as db:
        identity = db.scalar(select(GitHubIdentity).where(GitHubIdentity.github_user_id == 4242))
        assert identity is not None and identity.access_token_encrypted is not None
        assert token.encode() not in identity.access_token_encrypted
        assert decrypt_token(identity.access_token_encrypted) == token
        assert identity.scopes == ["public_repo", "read:user"]
        assert token not in repr(identity)

    me = web.get("/api/auth/me")
    assert me.status_code == 200
    body = me.json()
    assert body["github"]["login"] == "octo" and body["github"]["private_repo_access"] is False
    assert token not in me.text
    assert "access_token" not in me.text and "encrypted" not in me.text


@pytest.mark.parametrize("case", ["no_cookie", "wrong_state", "replayed", "unknown_state"])
def test_callback_rejects_invalid_state(
    web: TestClient, fake_github: FakeGitHub, case: str
) -> None:
    fake_github.add_user("octo", "gho_t", user_id=1)
    fake_github.oauth_codes["code"] = {"access_token": "gho_t", "scope": "public_repo"}
    state, _ = start_login(web)
    params = {"code": "code", "state": state}
    if case == "no_cookie":
        web.cookies.delete(OAUTH_STATE_COOKIE, path="/api/auth/github")
        web.cookies.clear()
    elif case == "wrong_state":
        params["state"] = state[:-2] + "xx"
    elif case == "replayed":
        fake_github.oauth_codes["code2"] = {"access_token": "gho_t", "scope": "public_repo"}
        assert (
            web.get(
                "/api/auth/github/callback", params={"code": "code2", "state": state}
            ).status_code
            == 302
        )
        web.cookies.set(OAUTH_STATE_COOKIE, state, path="/api/auth/github")
        web.cookies.delete(SESSION_COOKIE)
        fake_github.requests.clear()
    elif case == "unknown_state":
        web.cookies.set(OAUTH_STATE_COOKIE, "forged", path="/api/auth/github")
        params["state"] = "forged"

    response = web.get("/api/auth/github/callback", params=params)
    assert response.status_code == 302
    assert (
        response.headers["location"]
        == "http://frontend.test/settings?github_error=invalid_oauth_state"
    )
    assert SESSION_COOKIE not in response.cookies
    # The code was never exchanged.
    assert not any(r.url.path == "/login/oauth/access_token" for r in fake_github.requests)


def test_open_redirects_are_neutralised(web: TestClient, fake_github: FakeGitHub) -> None:
    fake_github.add_user("octo", "gho_r", user_id=7)
    for index, next_path in enumerate(["//evil.example/x", "https://evil.example", "\\\\evil"]):
        fake_github.oauth_codes[f"c{index}"] = {"access_token": "gho_r", "scope": "public_repo"}
        state, _ = start_login(web, next=next_path)
        response = web.get(
            "/api/auth/github/callback", params={"code": f"c{index}", "state": state}
        )
        assert response.headers["location"] == "http://frontend.test/settings"


def test_cookie_requests_that_change_state_need_csrf_token(sign_in: SignIn) -> None:
    user: SignedIn = sign_in("alice")
    denied = user.client.post("/api/auth/tokens", json={"name": "ci"})
    assert denied.status_code == 403 and denied.json()["error"]["code"] == "csrf_failed"
    wrong = user.client.post(
        "/api/auth/tokens", json={"name": "ci"}, headers={"X-CSRF-Token": "nope"}
    )
    assert wrong.status_code == 403

    created = user.client.post("/api/auth/tokens", json={"name": "ci"}, headers=user.headers)
    assert created.status_code == 201
    secret = created.json()["token"]
    assert secret.startswith("cat_")

    # The secret is shown once; listings never include it or the GitHub token.
    listing = user.client.get("/api/auth/tokens")
    assert secret not in listing.text and "token_hash" not in listing.text
    assert user.token not in listing.text

    # API tokens are not ambient credentials: no CSRF header needed.
    from app.main import app

    with TestClient(app) as bare:
        me = bare.get("/api/auth/me", headers={"Authorization": f"Bearer {secret}"})
        assert me.status_code == 200 and me.json()["auth_method"] == "api_token"
        assert me.json()["csrf_token"] is None
        bearer = {"Authorization": f"Bearer {secret}"}
        for method, url in [
            ("POST", "/api/auth/tokens"),
            ("GET", "/api/auth/tokens"),
            ("DELETE", "/api/auth/github"),
            ("POST", "/api/scans/00000000-0000-0000-0000-000000000000/pull-requests/preview"),
            ("POST", "/api/pull-requests/1/confirm"),
        ]:
            body = {"name": "x", "suggestion_ids": [1], "confirm": True}
            refused = bare.request(method, url, headers=bearer, json=body)
            assert refused.status_code == 403, url
            assert refused.json()["error"]["code"] == "session_required"
        assert (
            bare.get("/api/auth/me", headers={"Authorization": "Bearer cat_forged"}).status_code
            == 401
        )

    token_id = created.json()["id"]
    assert (
        user.client.delete(f"/api/auth/tokens/{token_id}", headers=user.headers).status_code == 204
    )
    with TestClient(app) as bare:
        assert (
            bare.get("/api/auth/me", headers={"Authorization": f"Bearer {secret}"}).status_code
            == 401
        )


def test_disconnect_revokes_grant_and_deletes_tokens(
    sign_in: SignIn, fake_github: FakeGitHub
) -> None:
    user: SignedIn = sign_in("bob")
    assert user.client.delete("/api/auth/github").status_code == 403  # CSRF
    response = user.client.delete("/api/auth/github", headers=user.headers)
    assert response.status_code == 200
    assert response.json() == {"disconnected": True, "revoked_at_github": True}
    assert fake_github.revoked == [user.token]
    revoke = next(r for r in fake_github.requests if r.url.path.startswith("/applications/"))
    assert revoke.url.path == "/applications/test-client-id/grant"
    with SessionLocal() as db:
        identity = db.scalar(select(GitHubIdentity).where(GitHubIdentity.user_id == user.user_id))
        assert identity is not None
        assert identity.access_token_encrypted is None and identity.refresh_token_encrypted is None
        assert identity.scopes == []
    assert user.client.get("/api/auth/me").json()["github"]["connected"] is False


def test_expiring_token_is_refreshed_and_failed_refresh_disconnects(
    sign_in: SignIn, fake_github: FakeGitHub
) -> None:
    user: SignedIn = sign_in("carol")
    fake_github.oauth_codes["refresh:r-1"] = {
        "access_token": "gho_refreshed",
        "refresh_token": "r-2",
        "expires_in": 28800,
        "refresh_token_expires_in": 15552000,
        "scope": "public_repo,read:user",
    }
    with SessionLocal() as db:
        identity = db.scalar(select(GitHubIdentity).where(GitHubIdentity.user_id == user.user_id))
        assert identity is not None
        identity.access_token_expires_at = datetime.now(UTC) + timedelta(minutes=1)
        identity.refresh_token_encrypted = encrypt_token("r-1")
        db.commit()

        assert access_token(db, identity) == "gho_refreshed"
        db.refresh(identity)
        assert identity.access_token_encrypted is not None
        assert decrypt_token(identity.access_token_encrypted) == "gho_refreshed"
        assert identity.refresh_token_encrypted is not None
        assert decrypt_token(identity.refresh_token_encrypted) == "r-2"
        assert identity.access_token_expires_at is not None
        assert identity.access_token_expires_at > datetime.now(UTC) + timedelta(hours=7)

        # r-2 is unknown to GitHub: the refresh fails and the connection is removed.
        identity.access_token_expires_at = datetime.now(UTC) - timedelta(minutes=1)
        db.commit()
        with pytest.raises(GitHubAuthError) as info:
            access_token(db, identity)
        assert "r-2" not in str(info.value)
        db.refresh(identity)
        assert identity.access_token_encrypted is None

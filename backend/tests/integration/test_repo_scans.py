"""Scanning a GitHub repository by URL, and scan ownership (GitHub faked, no clone)."""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.config import get_settings
from app.core.db import SessionLocal
from app.models import Scan, ScanSource, ScanStatus
from tests.github_fakes import FakeGitHub
from tests.integration.conftest import SignedIn, SignIn

pytestmark = pytest.mark.integration


@pytest.fixture
def queued(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record queued scans instead of cloning."""
    from app.api.routes import scans

    ids: list[str] = []
    monkeypatch.setattr(scans.run_scan, "delay", lambda scan_id: ids.append(scan_id))
    return ids


@pytest.fixture
def anon(database: None, redis_clean: None, fake_github: FakeGitHub) -> TestClient:
    from app.main import app

    with TestClient(app) as client:
        yield client  # type: ignore[misc]


def test_public_repo_without_signing_in(
    anon: TestClient, fake_github: FakeGitHub, queued: list[str]
) -> None:
    repo = fake_github.add_repo(
        "octo", "public-app", {"app.py": "print('hi')\n"}, default_branch="trunk"
    )
    response = anon.post("/api/scans", json={"repo_url": "https://github.com/octo/public-app"})
    assert response.status_code == 202, response.text
    scan_id = response.json()["scan_id"]
    assert queued == [scan_id]
    with SessionLocal() as db:
        scan = db.get(Scan, uuid.UUID(scan_id))
        assert scan is not None
        assert scan.source is ScanSource.GITHUB and scan.user_id is None
        assert (scan.repo_owner, scan.repo_name) == ("octo", "public-app")
        assert scan.repo_ref == "trunk" and scan.repo_default_branch == "trunk"
        assert scan.commit_sha == repo.branches["trunk"]
        assert scan.repo_private is False and scan.storage_key is None

    detail = anon.get(f"/api/scans/{scan_id}").json()
    assert detail["repository"]["full_name"] == "octo/public-app"
    assert detail["repository"]["commit_sha"] == repo.branches["trunk"]


def test_explicit_ref_and_tree_urls(
    anon: TestClient, fake_github: FakeGitHub, queued: list[str]
) -> None:
    repo = fake_github.add_repo("octo", "app", {"a.py": "x = 1\n"})
    feature = fake_github.push(repo, "main", {"a.py": "x = 2\n"}, "change")
    repo.branches["feature/x"] = feature
    by_url = anon.post(
        "/api/scans", json={"repo_url": "https://github.com/octo/app/tree/feature/x"}
    )
    by_field = anon.post("/api/scans", json={"repo_url": "github.com/octo/app", "ref": "feature/x"})
    missing = anon.post(
        "/api/scans", json={"repo_url": "https://github.com/octo/app", "ref": "nope"}
    )
    assert by_url.status_code == by_field.status_code == 202
    with SessionLocal() as db:
        for response in (by_url, by_field):
            scan = db.get(Scan, uuid.UUID(response.json()["scan_id"]))
            assert scan is not None and scan.commit_sha == feature
    assert missing.status_code == 400
    assert missing.json()["error"]["code"] == "ref_not_found"


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1/octo/app",
        "https://gitlab.com/octo/app",
        "https://github.com@10.0.0.1/octo/app",
        "file:///etc/passwd",
    ],
)
def test_non_github_urls_are_rejected_before_any_request(
    anon: TestClient, fake_github: FakeGitHub, queued: list[str], url: str
) -> None:
    response = anon.post("/api/scans", json={"repo_url": url})
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_repo_url"
    assert fake_github.requests == [] and queued == []


def test_private_repos_need_a_token_with_repo_scope(
    anon: TestClient, sign_in: SignIn, fake_github: FakeGitHub, queued: list[str]
) -> None:
    public_only: SignedIn = sign_in("dev")
    fake_github.add_repo("dev", "secret", {"a.py": "x = 1\n"}, private=True)
    body = {"repo_url": "https://github.com/dev/secret"}

    # Anonymous: GitHub hides private repos, so this looks like "not found" with a hint.
    hidden = anon.post("/api/scans", json=body)
    assert hidden.status_code == 400
    assert hidden.json()["error"]["code"] == "repository_not_found"
    assert "private repository access" in hidden.json()["error"]["message"]

    no_scope = public_only.client.post("/api/scans", json=body, headers=public_only.headers)
    assert no_scope.status_code == 400
    assert no_scope.json()["error"]["code"] == "private_repo_access_required"

    full: SignedIn = sign_in("dev2", scopes=("read:user", "repo"))
    fake_github.repos["dev/secret"].collaborators.add("dev2")
    allowed = full.client.post("/api/scans", json=body, headers=full.headers)
    assert allowed.status_code == 202, allowed.text
    scan_id = allowed.json()["scan_id"]
    with SessionLocal() as db:
        scan = db.get(Scan, uuid.UUID(scan_id))
        assert scan is not None and scan.repo_private is True and scan.user_id == full.user_id

    # Owned scans are invisible to everyone else (404, not 403).
    assert full.client.get(f"/api/scans/{scan_id}").status_code == 200
    assert anon.get(f"/api/scans/{scan_id}").status_code == 404
    assert public_only.client.get(f"/api/scans/{scan_id}").status_code == 404
    assert public_only.client.get(f"/api/scans/{scan_id}/findings").status_code == 404
    assert anon.get(f"/api/scans/{scan_id}/score").status_code == 404


def test_repository_size_cap(anon: TestClient, fake_github: FakeGitHub, queued: list[str]) -> None:
    limit_kb = get_settings().github_max_repo_size_mb * 1024
    fake_github.add_repo("octo", "huge", {"a.py": ""}, size_kb=limit_kb + 1)
    response = anon.post("/api/scans", json={"repo_url": "https://github.com/octo/huge"})
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "repository_too_large"
    assert queued == []


def test_scan_rate_limits(
    anon: TestClient,
    sign_in: SignIn,
    fake_github: FakeGitHub,
    queued: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_github.add_repo("octo", "app", {"a.py": "x = 1\n"})
    monkeypatch.setattr(get_settings(), "quota_anonymous_scans_per_day", 2)
    monkeypatch.setattr(get_settings(), "quota_free_scans_per_day", 3)
    body = {"repo_url": "https://github.com/octo/app"}
    assert [anon.post("/api/scans", json=body).status_code for _ in range(3)] == [202, 202, 429]
    response = anon.post("/api/scans", json=body)
    limited = response.json()["error"]
    assert limited["code"] == "quota_exceeded" and "Sign in for higher limits" in limited["message"]
    assert "2 scans per day" in limited["message"] and "It resets" in limited["message"]
    assert int(response.headers["Retry-After"]) > 0
    assert limited["details"]["limit"] == "scans" and limited["details"]["tier"] == "anonymous"

    user: SignedIn = sign_in("busy")
    codes = [
        user.client.post("/api/scans", json=body, headers=user.headers).status_code
        for _ in range(4)
    ]
    assert codes == [202, 202, 202, 429]
    # A per-user override beats the tier default.
    from app.core.db import SessionLocal
    from app.models import User

    with SessionLocal() as db:
        row = db.get(User, user.user_id)
        assert row is not None
        row.quota_scans = 5
        db.commit()
    ok = user.client.post("/api/scans", json=body, headers=user.headers)
    assert ok.status_code == 202
    assert ok.headers["X-RateLimit-Limit"].split(",")[0].strip() != ""


def test_github_rate_limit_is_reported_clearly(anon: TestClient, fake_github: FakeGitHub) -> None:
    import httpx

    original = fake_github.handle

    def limited(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            return httpx.Response(
                403,
                json={"message": "API rate limit exceeded"},
                headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1893456000"},
            )
        return original(request)

    fake_github.transport.handler = limited  # type: ignore[attr-defined]
    response = anon.post("/api/scans", json={"repo_url": "https://github.com/octo/app"})
    assert response.status_code == 429
    error = response.json()["error"]
    assert error["code"] == "github_rate_limited"
    assert "resets at" in error["message"] and "connect GitHub" in error["message"]


def test_scans_list_is_owner_only(
    sign_in: SignIn, fake_github: FakeGitHub, queued: list[str]
) -> None:
    owner: SignedIn = sign_in("lister")
    other: SignedIn = sign_in("stranger")
    repo = fake_github.add_repo("lister", "app", {"a.py": "x = 1\n"})
    created = owner.client.post(
        "/api/scans", json={"repo_url": "https://github.com/lister/app"}, headers=owner.headers
    ).json()
    sha = repo.branches["main"]
    mine = owner.client.get("/api/scans", params={"repo": "lister/app", "commit_sha": sha}).json()
    assert [item["id"] for item in mine["items"]] == [created["scan_id"]]
    assert mine["items"][0]["status"] == ScanStatus.QUEUED.value
    assert other.client.get("/api/scans", params={"repo": "lister/app"}).json()["total"] == 0
    assert owner.client.get("/api/scans", params={"repo": "not a repo"}).status_code == 400

"""Test environment.

This runs before any test module imports the app. Settings are cached and the DB
engine is created at import time, so the overrides must be in place first.
"""

import os
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy.engine import make_url

from app.config import Settings

_base_settings = Settings()
_base_url = make_url(_base_settings.database_url)
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL") or _base_url.set(
    database=f"{_base_url.database}_test"
).render_as_string(hide_password=False)
# Stable across runs so downloaded rule packs and vulnerability databases (~240 MB)
# stay cached; only per-scan directories are removed after the session.
# Separate Redis database: quota windows, kill switch and heartbeats never mix with dev.
TEST_REDIS_URL = os.environ.get("TEST_REDIS_URL") or (
    _base_settings.redis_url.rsplit("/", 1)[0] + "/13"
)
TEST_WORKSPACE = Path(tempfile.gettempdir()) / "codeaudit-test-workspace"
TEST_WORKSPACE.mkdir(exist_ok=True)

os.environ.update(
    {
        "DATABASE_URL": TEST_DATABASE_URL,
        "REDIS_URL": TEST_REDIS_URL,
        "S3_BUCKET_UPLOADS": "codeaudit-test-uploads",
        "CELERY_TASK_ALWAYS_EAGER": "true",
        "SCAN_WORKSPACE_DIR": str(TEST_WORKSPACE),
        # Worker runs on the host in tests: sandbox mounts are bind mounts.
        "SANDBOX_WORKSPACE_VOLUME": "",
        # Test-only GitHub app and encryption key; real credentials in .env are never used.
        "GITHUB_CLIENT_ID": "test-client-id",
        "GITHUB_CLIENT_SECRET": "test-client-secret",
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_OAUTH_URL": "https://github.com",
        "TOKEN_ENCRYPTION_KEYS": "J2mV0z7rQn3o4a9sJq1dYb3kq8m8yZq0yq3yWm0x3kE=",
        "FRONTEND_URL": "http://frontend.test",
    }
)

if "DOCKER_HOST" not in os.environ and not Path("/var/run/docker.sock").exists():
    # Docker Desktop without the default socket symlink: use the active CLI context.
    try:
        host = subprocess.run(
            ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout.strip()
        if host:
            os.environ["DOCKER_HOST"] = host
    except (OSError, subprocess.SubprocessError):
        pass


@pytest.fixture(scope="session", autouse=True)
def _cleanup_test_workspace() -> Iterator[None]:
    yield
    for scan_dir in TEST_WORKSPACE.glob("scan-*"):
        shutil.rmtree(scan_dir, ignore_errors=True)


@pytest.fixture(autouse=True)
def _fresh_redis() -> None:
    """Every test starts with empty quota windows, no kill switch and no heartbeats."""
    from redis.exceptions import RedisError

    from app.core.redis_client import get_redis

    try:
        get_redis().flushdb()
    except RedisError:
        pass  # tests that need Redis skip or fail on their own


@pytest.fixture(autouse=True)
def _no_live_github() -> Iterator[None]:
    """GitHub is always faked: any request that isn't routed to a fake fails the test."""
    import httpx

    from app.services.github import client as github_client

    def refuse(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"live GitHub call attempted: {request.method} {request.url}")

    github_client.set_transport_override(httpx.MockTransport(refuse))
    yield
    github_client.set_transport_override(None)

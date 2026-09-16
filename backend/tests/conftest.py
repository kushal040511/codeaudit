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
TEST_WORKSPACE = Path(tempfile.gettempdir()) / "codeaudit-test-workspace"
TEST_WORKSPACE.mkdir(exist_ok=True)

os.environ.update(
    {
        "DATABASE_URL": TEST_DATABASE_URL,
        "S3_BUCKET_UPLOADS": "codeaudit-test-uploads",
        "CELERY_TASK_ALWAYS_EAGER": "true",
        "SCAN_WORKSPACE_DIR": str(TEST_WORKSPACE),
        # Worker runs on the host in tests: sandbox mounts are bind mounts.
        "SANDBOX_WORKSPACE_VOLUME": "",
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

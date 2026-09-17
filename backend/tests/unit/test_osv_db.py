import io
import os
import time
import zipfile
from datetime import timedelta
from pathlib import Path

import httpx
import pytest

from app.services.analyzers.osv_db import (
    VulnerabilityDatabaseUnavailableError,
    database_path,
    detect_ecosystems,
    ecosystem_for,
    ensure_databases,
)

MAX_AGE = timedelta(hours=1)


def zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("GHSA-xxxx.json", "{}")
    return buf.getvalue()


def http(handler) -> httpx.Client:  # type: ignore[no-untyped-def]
    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.mark.parametrize(
    ("filename", "ecosystem"),
    [
        ("requirements.txt", "PyPI"),
        ("requirements-dev.txt", "PyPI"),
        ("poetry.lock", "PyPI"),
        ("package-lock.json", "npm"),
        ("yarn.lock", "npm"),
        ("go.mod", "Go"),
        ("Cargo.lock", "crates.io"),
        ("package.json", None),  # not a lockfile; osv-scanner ignores it
        ("README.md", None),
    ],
)
def test_ecosystem_for(filename: str, ecosystem: str | None) -> None:
    assert ecosystem_for(filename) == ecosystem


def test_detect_ecosystems_includes_nested_and_vendored_dirs(tmp_path: Path) -> None:
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "requirements.txt").write_text("flask==2.0.1\n")
    (tmp_path / "web" / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "web" / "node_modules" / "x" / "Cargo.lock").write_text("")

    assert detect_ecosystems(tmp_path) == {"PyPI", "crates.io"}


def test_downloads_into_osv_scanner_layout(tmp_path: Path) -> None:
    requested: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(200, content=zip_bytes())

    warnings = ensure_databases(["npm", "PyPI"], tmp_path, MAX_AGE, http=http(handler))

    assert warnings == []
    assert requested == [
        "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip",
        "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip",
    ]
    path = database_path(tmp_path, "npm")
    assert path == tmp_path / "osv-scalibr" / "npm" / "all.zip"
    assert zipfile.is_zipfile(path)
    assert oct(path.stat().st_mode & 0o777) == "0o640"


def test_fresh_database_skips_network(tmp_path: Path) -> None:
    path = database_path(tmp_path, "PyPI")
    path.parent.mkdir(parents=True)
    path.write_bytes(zip_bytes())

    def no_network(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"unexpected request to {request.url}")

    assert ensure_databases(["PyPI"], tmp_path, MAX_AGE, http=http(no_network)) == []


def test_stale_database_used_when_refresh_fails(tmp_path: Path) -> None:
    path = database_path(tmp_path, "PyPI")
    path.parent.mkdir(parents=True)
    path.write_bytes(zip_bytes())
    old = time.time() - 7200
    os.utime(path, (old, old))

    warnings = ensure_databases(
        ["PyPI"], tmp_path, MAX_AGE, http=http(lambda _: httpx.Response(503))
    )

    assert warnings == []
    assert zipfile.is_zipfile(path)


def test_partial_availability_warns(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if "/npm/" in str(request.url):
            return httpx.Response(200, content=b"<html>not a zip</html>")
        return httpx.Response(200, content=zip_bytes())

    warnings = ensure_databases(["npm", "PyPI"], tmp_path, MAX_AGE, http=http(handler))

    assert len(warnings) == 1 and "npm" in warnings[0]
    assert not database_path(tmp_path, "npm").exists()
    assert not list(database_path(tmp_path, "npm").parent.glob("*.tmp"))


def test_nothing_available_raises(tmp_path: Path) -> None:
    with pytest.raises(VulnerabilityDatabaseUnavailableError):
        ensure_databases(["Go"], tmp_path, MAX_AGE, http=http(lambda _: httpx.Response(500)))


def test_no_ecosystems_is_a_no_op(tmp_path: Path) -> None:
    assert ensure_databases([], tmp_path / "unused", MAX_AGE) == []
    assert not (tmp_path / "unused").exists()

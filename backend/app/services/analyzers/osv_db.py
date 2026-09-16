"""OSV vulnerability databases: fetched by the worker, cached, mounted read-only into the sandbox.

OSV-Scanner normally queries api.osv.dev, which the network-less sandbox cannot
reach. Instead the worker downloads the per-ecosystem offline databases for the
ecosystems present in the upload, in the layout OSV-Scanner expects
(`<cache>/osv-scalibr/<ecosystem>/all.zip`), and the scanner runs with --offline.

OSV-Scanner silently skips ecosystems whose database is missing, so detection
here must cover every lockfile/manifest it can parse; the analyzer also reports
any ecosystem it could not load as a warning.
"""

import fcntl
import logging
import os
import time
import uuid
import zipfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path

import httpx

from app.core.errors import TransientInfraError

logger = logging.getLogger(__name__)

DATABASE_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
LAYOUT_DIR = "osv-scalibr"
MAX_DATABASE_BYTES = 2 * 1024 * 1024 * 1024

# Lockfile / manifest name -> OSV ecosystem.
FILENAME_ECOSYSTEMS: dict[str, str] = {
    "Pipfile.lock": "PyPI",
    "poetry.lock": "PyPI",
    "pdm.lock": "PyPI",
    "uv.lock": "PyPI",
    "pylock.toml": "PyPI",
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "bun.lock": "npm",
    "go.mod": "Go",
    "Cargo.lock": "crates.io",
    "Gemfile.lock": "RubyGems",
    "gems.locked": "RubyGems",
    "composer.lock": "Packagist",
    "pom.xml": "Maven",
    "gradle.lockfile": "Maven",
    "buildscript-gradle.lockfile": "Maven",
    "packages.lock.json": "NuGet",
    "pubspec.lock": "Pub",
    "mix.lock": "Hex",
    "renv.lock": "CRAN",
    "conan.lock": "ConanCenter",
}


class VulnerabilityDatabaseUnavailableError(TransientInfraError):
    """A database could not be downloaded and no cached copy exists."""


def ecosystem_for(filename: str) -> str | None:
    if filename in FILENAME_ECOSYSTEMS:
        return FILENAME_ECOSYSTEMS[filename]
    if filename.startswith("requirements") and filename.endswith(".txt"):
        return "PyPI"
    return None


def detect_ecosystems(repo_path: Path) -> set[str]:
    """Ecosystems of every lockfile/manifest OSV-Scanner will find (including vendored dirs)."""
    ecosystems: set[str] = set()
    for _dirpath, _dirnames, filenames in os.walk(repo_path):  # does not follow symlinks
        for name in filenames:
            if (ecosystem := ecosystem_for(name)) is not None:
                ecosystems.add(ecosystem)
    return ecosystems


def database_path(cache_root: Path, ecosystem: str) -> Path:
    return cache_root / LAYOUT_DIR / ecosystem / "all.zip"


def ensure_databases(
    ecosystems: Iterable[str],
    cache_root: Path,
    max_age: timedelta,
    http: httpx.Client | None = None,
) -> list[str]:
    """Make sure a database exists for each ecosystem, refreshing stale ones.

    A stale database that fails to refresh is still used. Returns warnings for
    ecosystems that have no database at all; raises only if none are available.
    """
    wanted = sorted(set(ecosystems))
    if not wanted:
        return []
    client = http or httpx.Client(timeout=httpx.Timeout(120.0, connect=10.0), follow_redirects=True)
    warnings: list[str] = []
    try:
        for ecosystem in wanted:
            try:
                _ensure_database(client, ecosystem, cache_root, max_age)
            except VulnerabilityDatabaseUnavailableError as exc:
                warnings.append(str(exc))
    finally:
        if http is None:
            client.close()
    if len(warnings) == len(wanted):
        raise VulnerabilityDatabaseUnavailableError("; ".join(warnings))
    return warnings


@contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    """Serialise downloads of the same database across threads and worker processes."""
    with path.open("a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def _is_fresh(path: Path, max_age: timedelta) -> bool:
    return path.exists() and time.time() - path.stat().st_mtime < max_age.total_seconds()


def _ensure_database(
    client: httpx.Client, ecosystem: str, cache_root: Path, max_age: timedelta
) -> None:
    path = database_path(cache_root, ecosystem)
    if _is_fresh(path, max_age):
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    for directory in (cache_root, cache_root / LAYOUT_DIR, path.parent):
        os.chmod(directory, 0o755)  # noqa: S103 - read by the sandbox user

    with _file_lock(path.parent / ".lock"):
        if _is_fresh(path, max_age):  # another worker refreshed it while we waited
            return
        tmp = path.parent / f".all.zip.{uuid.uuid4().hex}.tmp"
        try:
            _download(client, DATABASE_URL.format(ecosystem=ecosystem), tmp)
            if not zipfile.is_zipfile(tmp):
                raise ValueError("response is not a zip archive")
        except (httpx.HTTPError, ValueError, OSError) as exc:
            tmp.unlink(missing_ok=True)
            if path.exists():
                logger.warning(
                    "refreshing OSV %s database failed (%s); using cache", ecosystem, exc
                )
                return
            raise VulnerabilityDatabaseUnavailableError(
                f"Could not download the OSV {ecosystem} vulnerability database: {exc}"
            ) from exc

        os.chmod(tmp, 0o644)
        os.replace(tmp, path)  # atomic: running scans keep their open file
        logger.info("cached OSV %s database (%d bytes)", ecosystem, path.stat().st_size)


def _download(client: httpx.Client, url: str, destination: Path) -> None:
    with client.stream("GET", url) as response:
        response.raise_for_status()
        written = 0
        with destination.open("wb") as fh:
            for chunk in response.iter_bytes(chunk_size=1024 * 1024):
                written += len(chunk)
                if written > MAX_DATABASE_BYTES:
                    raise ValueError("database exceeds the size limit")
                fh.write(chunk)

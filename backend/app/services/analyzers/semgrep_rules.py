"""Semgrep rule packs: fetched by the worker, cached, and mounted read-only into the sandbox.

`--config=auto` resolves rules from semgrep.dev at scan time (and requires
metrics to be on), which the network-less sandbox cannot do. Instead we choose
registry packs from the detected languages and cache them on the workspace
volume.

LICENSE: Semgrep Registry rules are distributed under the Semgrep Rules License,
which restricts using them to provide a competing hosted service. Review it
before offering CodeAudit commercially.
"""

import json
import logging
import os
import time
import uuid
from collections.abc import Iterable, Sequence
from datetime import timedelta
from pathlib import Path

import httpx

from app.core.errors import TransientInfraError

logger = logging.getLogger(__name__)

REGISTRY_URL = "https://semgrep.dev/c/{pack}"

# Always applied, whatever the language mix.
BASE_PACKS: tuple[str, ...] = ("p/security-audit", "p/secrets")

LANGUAGE_PACKS: dict[str, tuple[str, ...]] = {
    "python": ("p/python", "p/flask"),
    "javascript": ("p/javascript", "p/nodejs"),
    "typescript": ("p/typescript", "p/nodejs"),
    "go": ("p/golang",),
    "java": ("p/java",),
    "ruby": ("p/ruby",),
    "php": ("p/php",),
}


class RulesUnavailableError(TransientInfraError):
    """A rule pack could not be downloaded and no cached copy exists."""


def select_packs(languages: Iterable[str]) -> list[str]:
    packs = list(BASE_PACKS)
    for language in languages:
        for pack in LANGUAGE_PACKS.get(language, ()):
            if pack not in packs:
                packs.append(pack)
    return packs


def pack_filename(pack: str) -> str:
    return pack.replace("/", "-") + ".yml"


def ensure_rule_packs(
    packs: Sequence[str],
    cache_dir: Path,
    max_age: timedelta,
    http: httpx.Client | None = None,
) -> list[Path]:
    """Return local paths for `packs`, downloading any that are missing or stale.

    A stale pack that fails to refresh is still used; a missing one raises.
    """
    cache_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(cache_dir, 0o750)  # noqa: S103 - rules are read by the sandbox (worker group)
    client = http or httpx.Client(timeout=httpx.Timeout(60.0, connect=10.0), follow_redirects=True)
    try:
        return [_ensure_pack(client, pack, cache_dir, max_age) for pack in packs]
    finally:
        if http is None:
            client.close()


def _looks_like_rules(text: str) -> bool:
    """The registry serves YAML or JSON depending on the client; semgrep accepts both."""
    stripped = text.lstrip()
    if stripped.startswith("rules:"):
        return True
    try:
        data = json.loads(stripped)
    except ValueError:
        return False
    return isinstance(data, dict) and isinstance(data.get("rules"), list) and bool(data["rules"])


def _ensure_pack(client: httpx.Client, pack: str, cache_dir: Path, max_age: timedelta) -> Path:
    path = cache_dir / pack_filename(pack)
    if path.exists() and time.time() - path.stat().st_mtime < max_age.total_seconds():
        return path

    try:
        response = client.get(REGISTRY_URL.format(pack=pack))
        response.raise_for_status()
        if not _looks_like_rules(response.text):
            raise ValueError("response is not a Semgrep rules file")
    except (httpx.HTTPError, ValueError) as exc:
        if path.exists():
            logger.warning("refreshing rule pack %s failed (%s); using cached copy", pack, exc)
            return path
        raise RulesUnavailableError(f"Could not download Semgrep rule pack {pack}: {exc}") from exc

    # Atomic replace: concurrent scans never see a half-written file.
    tmp = cache_dir / f".{path.name}.{uuid.uuid4().hex}.tmp"
    tmp.write_text(response.text, encoding="utf-8")
    os.chmod(tmp, 0o640)
    os.replace(tmp, path)
    logger.info("cached Semgrep rule pack %s (%d bytes)", pack, len(response.content))
    return path

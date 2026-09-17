"""Reuse finished scan results for identical inputs.

An upload is identified by the SHA-256 of the archive bytes; a GitHub scan by
repository + commit SHA. A previous scan is reused only if it finished with results,
ran with the same analyzer set (images and rubric), is younger than
SCAN_CACHE_TTL_SECONDS, and is visible to the requester: their own scan, or an
anonymous scan (whose content an uploader of identical bytes already has). A private
scan by another user is never reused.
"""

import hashlib
from datetime import UTC, datetime, timedelta
from typing import BinaryIO

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import RESULT_STATUSES, Scan, ScanStatus
from app.services.auth.sessions import Principal
from app.services.scoring.rubric import RUBRIC_VERSION

CHUNK = 1024 * 1024
REUSABLE = frozenset(RESULT_STATUSES) - {ScanStatus.ENRICHING}


def analysis_version() -> str:
    """Changes whenever an analyzer image or the scoring rubric changes."""
    settings = get_settings()
    parts = [
        settings.semgrep_image,
        settings.bandit_image,
        settings.ruff_image,
        settings.osv_scanner_image,
        RUBRIC_VERSION,
        "architecture-1",
    ]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:32]


def sha256_of(fileobj: BinaryIO) -> str:
    fileobj.seek(0)
    digest = hashlib.sha256()
    while chunk := fileobj.read(CHUNK):
        digest.update(chunk)
    fileobj.seek(0)
    return digest.hexdigest()


def _visible(principal: Principal | None):  # type: ignore[no-untyped-def]
    if principal is None:
        return Scan.user_id.is_(None)
    return or_(Scan.user_id.is_(None), Scan.user_id == principal.user.id)


def find_reusable(db: Session, principal: Principal | None, **identity: str) -> Scan | None:
    ttl = get_settings().scan_cache_ttl_seconds
    if ttl <= 0:
        return None
    conditions = [getattr(Scan, key) == value for key, value in identity.items()]
    return db.scalar(
        select(Scan)
        .where(
            *conditions,
            Scan.analysis_version == analysis_version(),
            Scan.status.in_(REUSABLE),
            Scan.created_at >= datetime.now(UTC) - timedelta(seconds=ttl),
            _visible(principal),
        )
        .order_by(Scan.created_at.desc())
        .limit(1)
    )

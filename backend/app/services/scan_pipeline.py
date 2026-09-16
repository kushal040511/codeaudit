"""The scan pipeline: fetch archive -> extract -> detect languages -> analyze -> persist.

Status transitions, retries and cleanup live in app.workers.tasks.
"""

import logging
import os
import shutil
import tempfile
import time
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import delete, insert
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.storage import download_file
from app.models import Finding, Scan, ScanStatus
from app.services.analyzers.base import Analyzer, AnalyzerContext, AnalyzerFinding
from app.services.analyzers.semgrep import SemgrepAnalyzer
from app.services.archive import archive_limits_from_settings, safe_extract
from app.services.languages import detect_languages

logger = logging.getLogger(__name__)

WORKSPACE_PREFIX = "scan-"


def utcnow() -> datetime:
    return datetime.now(UTC)


def default_analyzers() -> list[Analyzer]:
    return [SemgrepAnalyzer()]


def create_workspace(scan_id: uuid.UUID) -> Path:
    root = Path(get_settings().scan_workspace_dir)
    root.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix=f"{WORKSPACE_PREFIX}{scan_id}-", dir=root))
    # mkdtemp creates 0700; the sandbox user must be able to traverse it.
    os.chmod(workdir, 0o755)  # noqa: S103
    return workdir


def remove_stale_workspaces(max_age_seconds: float) -> int:
    """Delete scan directories older than any scan could run (left by crashed workers)."""
    root = Path(get_settings().scan_workspace_dir)
    if not root.is_dir():
        return 0
    cutoff = time.time() - max_age_seconds
    removed = 0
    for path in root.glob(f"{WORKSPACE_PREFIX}*"):
        try:
            if path.is_dir() and path.stat().st_mtime < cutoff:
                shutil.rmtree(path, ignore_errors=True)
                removed += 1
        except OSError:
            continue
    return removed


def run_pipeline(
    db: Session,
    scan: Scan,
    workdir: Path,
    analyzers: Sequence[Analyzer] | None = None,
) -> int:
    """Run every analyzer against the scan's archive and persist the findings.

    Returns the number of findings. Raises AnalysisError / TransientInfraError.
    """
    settings = get_settings()
    archive_path = workdir / "source.zip"
    source_dir = workdir / "src"

    download_file(scan.storage_key, archive_path)
    summary = safe_extract(archive_path, source_dir, archive_limits_from_settings(settings))
    archive_path.unlink()
    logger.info("extracted scan %s: %d files", scan.id, summary.file_count)

    languages = detect_languages(source_dir)
    scan.detected_languages = [lang.to_dict() for lang in languages]
    db.commit()

    ctx = AnalyzerContext(
        scan_id=str(scan.id), source_dir=source_dir, work_dir=workdir, languages=languages
    )
    findings: list[AnalyzerFinding] = []
    for analyzer in analyzers if analyzers is not None else default_analyzers():
        findings.extend(analyzer.run(ctx))

    persist_results(db, scan, findings)
    return len(findings)


def persist_results(db: Session, scan: Scan, findings: Sequence[AnalyzerFinding]) -> None:
    """Replace the scan's findings and mark it completed in one transaction.

    Deleting first keeps a retried task from duplicating findings.
    """
    db.execute(delete(Finding).where(Finding.scan_id == scan.id))
    if findings:
        db.execute(
            insert(Finding),
            [
                {
                    "scan_id": scan.id,
                    "analyzer": f.analyzer,
                    "rule_id": f.rule_id,
                    "severity": f.severity,
                    "file_path": f.file_path,
                    "start_line": f.start_line,
                    "end_line": f.end_line,
                    "message": f.message,
                    "code_snippet": f.code_snippet,
                    "raw": f.raw,
                }
                for f in findings
            ],
        )
    scan.status = ScanStatus.COMPLETED
    scan.completed_at = utcnow()
    scan.error_message = None
    db.commit()

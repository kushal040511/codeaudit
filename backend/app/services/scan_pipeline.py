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
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import delete, insert
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.errors import AnalysisError, TransientInfraError
from app.core.storage import download_file
from app.models import AnalyzerRun, AnalyzerRunStatus, Finding, Scan, ScanStatus
from app.services.analyzers.base import AnalyzerResult, FindingData, ScanContext
from app.services.analyzers.dedup import deduplicate
from app.services.analyzers.orchestrator import run_analyzers
from app.services.analyzers.registry import AnalyzerRegistry, default_registry
from app.services.analyzers.snippets import fill_snippets
from app.services.archive import archive_limits_from_settings, safe_extract
from app.services.languages import DetectedLanguage, detect_languages

logger = logging.getLogger(__name__)

WORKSPACE_PREFIX = "scan-"


@dataclass(frozen=True)
class PipelineOutcome:
    status: ScanStatus
    findings_before_dedup: int
    findings_after_dedup: int
    results: list[AnalyzerResult]


def utcnow() -> datetime:
    return datetime.now(UTC)


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
    registry: AnalyzerRegistry | None = None,
) -> PipelineOutcome:
    """Download and extract the scan's archive, then analyze it and persist the results.

    Raises AnalysisError / TransientInfraError when the scan as a whole fails.
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

    return analyze_and_persist(
        db, scan, source_dir, workdir, languages, registry or default_registry()
    )


def analyze_and_persist(
    db: Session,
    scan: Scan,
    source_dir: Path,
    workdir: Path,
    languages: Sequence[DetectedLanguage],
    registry: AnalyzerRegistry,
) -> PipelineOutcome:
    """Run the applicable analyzers concurrently, recording each one's status as it finishes.

    A failing analyzer never fails the scan on its own: the scan is `partial`. Only
    when every analyzer failed is the scan failed, and retried if the cause was
    infrastructure.
    """
    context = ScanContext(scan_id=str(scan.id), work_dir=workdir, languages=list(languages))
    applicable, skipped = registry.select(context.language_names)

    # A retried task starts from scratch.
    db.execute(delete(AnalyzerRun).where(AnalyzerRun.scan_id == scan.id))
    started_at = utcnow()
    runs = {
        analyzer.name: AnalyzerRun(
            scan_id=scan.id,
            analyzer_name=analyzer.name,
            status=AnalyzerRunStatus.RUNNING,
            started_at=started_at,
        )
        for analyzer in applicable
    }
    for analyzer in skipped:
        languages_text = ", ".join(sorted(analyzer.supported_languages))
        db.add(
            AnalyzerRun(
                scan_id=scan.id,
                analyzer_name=analyzer.name,
                status=AnalyzerRunStatus.SKIPPED,
                error_message=f"Not applicable: no {languages_text} code detected.",
            )
        )
    db.add_all(runs.values())
    db.commit()

    def record(result: AnalyzerResult) -> None:
        run = runs[result.analyzer]
        if result.success:
            run.status = AnalyzerRunStatus.COMPLETED
            run.finding_count = len(result.findings)
        else:
            run.status = (
                AnalyzerRunStatus.TIMED_OUT if result.timed_out else AnalyzerRunStatus.FAILED
            )
        run.duration_ms = result.duration_ms
        run.error_message = result.error_message
        run.warnings = list(result.warnings)
        run.completed_at = utcnow()
        db.commit()

    results = run_analyzers(
        applicable,
        source_dir,
        context,
        max_workers=get_settings().analyzer_max_workers,
        on_result=record,
    )

    succeeded = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    if applicable and not succeeded:
        reasons = "; ".join(f"{r.error_message}" for r in failed)
        if any(r.transient for r in failed):
            raise TransientInfraError(f"No analyzer could run: {reasons}")
        raise AnalysisError(f"Every analyzer failed: {reasons}")

    findings = fill_snippets([f for r in succeeded for f in r.findings], source_dir)
    unique = deduplicate(findings)
    status = ScanStatus.PARTIAL if failed else ScanStatus.COMPLETED
    persist_results(db, scan, unique, status)
    logger.info(
        "scan %s %s: %d/%d analyzers succeeded, %d findings (%d before dedup)",
        scan.id,
        status.value,
        len(succeeded),
        len(results),
        len(unique),
        len(findings),
    )
    return PipelineOutcome(
        status=status,
        findings_before_dedup=len(findings),
        findings_after_dedup=len(unique),
        results=results,
    )


def persist_results(
    db: Session, scan: Scan, findings: Sequence[FindingData], status: ScanStatus
) -> None:
    """Replace the scan's findings and mark it finished in one transaction.

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
                    "category": f.category[:512] if f.category else None,
                    "corroborated_by": list(f.corroborated_by),
                    "merged_from": list(f.merged_from),
                    "dependency": f.dependency,
                    "raw": f.raw,
                }
                for f in findings
            ],
        )
    scan.status = status
    scan.completed_at = utcnow()
    scan.error_message = None
    db.commit()

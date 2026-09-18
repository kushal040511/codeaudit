"""The scan pipeline: fetch archive -> extract -> detect languages -> analyze -> persist.

Status transitions, retries and cleanup live in app.workers.tasks.
"""

import dataclasses
import logging
import os
import shutil
import tempfile
import time
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core import metrics
from app.core.errors import AnalysisError, TransientInfraError
from app.core.storage import download_file
from app.models import (
    AnalyzerRun,
    AnalyzerRunStatus,
    EnrichmentStatus,
    Finding,
    GitHubIdentity,
    Scan,
    ScanSource,
    ScanStatus,
)
from app.models.finding import finding_fingerprint
from app.services.analyzers.base import AnalyzerResult, FindingData, ScanContext
from app.services.analyzers.dedup import deduplicate
from app.services.analyzers.orchestrator import run_analyzers
from app.services.analyzers.registry import AnalyzerRegistry, default_registry
from app.services.analyzers.signals import ADVISORY, SignalReport, not_applicable
from app.services.analyzers.snippets import fill_snippets
from app.services.archive import archive_limits_from_settings, safe_extract
from app.services.auth.oauth import access_token
from app.services.github.client import GitHubAuthError
from app.services.github.clone import clone_repository
from app.services.graph.analysis import ArchitectureReport
from app.services.graph.persistence import delete_architecture, persist_architecture
from app.services.languages import DetectedLanguage, count_source_lines, detect_languages
from app.services.llm.client import llm_configured
from app.services.scoring.rubric import ScoreContext, finding_impacts, score
from app.services.scoring.service import ScorableRow, rubric_config, store_score

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
    # mkdtemp creates 0700; the sandbox (worker group) must be able to traverse it.
    os.chmod(workdir, 0o750)  # noqa: S103
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


def extract_source(db: Session, scan: Scan, workdir: Path) -> Path:
    """Materialise the scan's code in `workdir/src`: extract the uploaded archive, or
    shallow-clone the scanned commit in the clone sandbox. Returns the source dir."""
    settings = get_settings()
    limits = archive_limits_from_settings(settings)
    if scan.source is ScanSource.GITHUB:
        if not (scan.repo_owner and scan.repo_name and scan.commit_sha):
            raise AnalysisError("This scan has no repository to clone.")
        token = github_token_for_clone(db, scan)
        return clone_repository(
            scan_id=str(scan.id),
            owner=scan.repo_owner,
            name=scan.repo_name,
            sha=scan.commit_sha,
            token=token,
            workdir=workdir,
            limits=limits,
        )
    if scan.storage_key is None:
        raise AnalysisError("This scan has no uploaded archive.")
    archive_path = workdir / "source.zip"
    source_dir = workdir / "src"
    download_file(scan.storage_key, archive_path)
    summary = safe_extract(archive_path, source_dir, limits)
    archive_path.unlink()
    logger.info("extracted scan %s: %d files", scan.id, summary.file_count)
    return source_dir


def github_token_for_clone(db: Session, scan: Scan) -> str | None:
    """The owner's token for private repositories; public ones are cloned anonymously."""
    if not scan.repo_private:
        return None
    identity = (
        db.scalar(select(GitHubIdentity).where(GitHubIdentity.user_id == scan.user_id))
        if scan.user_id
        else None
    )
    if identity is None:
        raise AnalysisError("This private repository needs the scan owner's GitHub connection.")
    try:
        return access_token(db, identity)
    except GitHubAuthError as exc:
        raise AnalysisError(exc.message) from None


def run_pipeline(
    db: Session,
    scan: Scan,
    workdir: Path,
    registry: AnalyzerRegistry | None = None,
) -> PipelineOutcome:
    """Download and extract the scan's archive, then analyze it and persist the results.

    Raises AnalysisError / TransientInfraError when the scan as a whole fails.
    """
    with stage_timer("extract"):
        source_dir = extract_source(db, scan, workdir)
    languages = detect_languages(source_dir)
    scan.detected_languages = [lang.to_dict() for lang in languages]
    scan.source_loc = count_source_lines(source_dir)
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
    history = workdir / "history"
    context = ScanContext(
        scan_id=str(scan.id),
        work_dir=workdir,
        languages=list(languages),
        git_log_path=history if (history / "git-log.txt").is_file() else None,
    )
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
        metrics.analyzer_runs.labels(result.analyzer, run.status.value).inc()
        if result.duration_ms is not None:
            metrics.analyzer_duration.labels(result.analyzer).observe(result.duration_ms / 1000)
        run.warnings = list(result.warnings)
        run.completed_at = utcnow()
        db.commit()

    first = [a for a in applicable if a.phase == 1]
    second = [a for a in applicable if a.phase != 1]
    with stage_timer("analyzers"):
        results = run_analyzers(
            first,
            source_dir,
            context,
            max_workers=get_settings().analyzer_max_workers,
            on_result=record,
        )
        if second:
            # Phase 2 builds on phase-1 output (the import graph, for example).
            phase_two = dataclasses.replace(
                context, prior_results={r.analyzer: r for r in results if r.success}
            )
            results += run_analyzers(
                second,
                source_dir,
                phase_two,
                max_workers=get_settings().analyzer_max_workers,
                on_result=record,
            )

    experimental = {a.name for a in applicable if a.experimental}
    signal_results = [r for r in results if r.analyzer in experimental]
    results = [r for r in results if r.analyzer not in experimental]
    store_signals(scan, signal_results)
    succeeded = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    if applicable and not succeeded:
        reasons = "; ".join(f"{r.error_message}" for r in failed)
        if any(r.transient for r in failed):
            raise TransientInfraError(f"No analyzer could run: {reasons}")
        raise AnalysisError(f"Every analyzer failed: {reasons}")

    signal_findings = [f for r in signal_results if r.success for f in r.findings]
    findings = fill_snippets(
        [f for r in succeeded for f in r.findings] + signal_findings, source_dir
    )
    unique = deduplicate(findings)
    status = ScanStatus.PARTIAL if failed else ScanStatus.COMPLETED
    architecture = next(
        (r.artifact for r in succeeded if isinstance(r.artifact, ArchitectureReport)), None
    )
    # With LLM enrichment to come, findings are readable now but the scan isn't final.
    skip_reason = llm_configured()
    scan.analysis_partial = bool(failed)
    scan.enrichment_status = EnrichmentStatus.SKIPPED if skip_reason else EnrichmentStatus.PENDING
    scan.enrichment_error = skip_reason
    stored_status = status if skip_reason else ScanStatus.ANALYSIS_COMPLETE
    score_context = ScoreContext(
        source_loc=scan.source_loc
        or (architecture.summary.get("total_loc", 0) if architecture else 0),
        module_count=architecture.summary.get("node_count", 0) if architecture else 0,
        analyzers_run=frozenset(r.analyzer for r in succeeded),
        analyzers_failed=frozenset(r.analyzer for r in failed),
        signals=scan.signal_metrics or {},
    )
    with stage_timer("persist"):
        persist_results(db, scan, unique, stored_status, architecture, score_context)
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


def store_signals(scan: Scan, results: Sequence[AnalyzerResult]) -> None:
    """Keep each experimental signal's report on the scan (advisory metrics separately).

    A failed signal analyzer is stored as not applicable with its error, so the rubric
    skips it instead of penalising.
    """
    signals: dict[str, object] = {}
    advisory: dict[str, object] | None = None
    for result in results:
        report = result.artifact if isinstance(result.artifact, SignalReport) else None
        if report is None:
            report = not_applicable(
                result.analyzer, result.error_message or "the analyzer produced no report"
            )
        if report.name == ADVISORY:
            advisory = report.as_dict()
        else:
            signals[report.name] = report.as_dict()
    scan.signal_metrics = signals or None
    scan.advisory_metrics = advisory


def persist_results(
    db: Session,
    scan: Scan,
    findings: Sequence[FindingData],
    status: ScanStatus,
    architecture: ArchitectureReport | None = None,
    score_context: ScoreContext | None = None,
) -> None:
    """Replace the scan's findings, architecture data and score and mark it finished,
    in one transaction. Deleting first keeps a retried task from duplicating rows.
    """
    impacts: dict[int, float] = {}
    if score_context is not None:
        # Findings have no ids yet: score them by position.
        rows = [
            ScorableRow(i, f.analyzer, f.rule_id, f.severity, f.file_path, list(f.corroborated_by))
            for i, f in enumerate(findings)
        ]
        config = rubric_config()
        impacts = finding_impacts(rows, score_context, config)
        store_score(db, scan.id, score(rows, score_context, config=config), score_context)
    db.execute(delete(Finding).where(Finding.scan_id == scan.id))
    if architecture is not None:
        persist_architecture(db, scan.id, architecture)
    else:
        delete_architecture(db, scan.id)
    if findings:
        db.execute(
            postgresql_insert(Finding).on_conflict_do_nothing(
                constraint="uq_findings_scan_id_fingerprint"
            ),
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
                    "score_impact": impacts.get(index),
                    "raw": f.raw,
                    "fingerprint": finding_fingerprint(
                        {
                            "analyzer": f.analyzer,
                            "rule_id": f.rule_id,
                            "file_path": f.file_path,
                            "start_line": f.start_line,
                            "end_line": f.end_line,
                            "message": f.message,
                            "dependency": f.dependency,
                        }
                    ),
                }
                for index, f in enumerate(findings)
            ],
        )
    scan.status = status
    scan.completed_at = utcnow()
    scan.error_message = None
    db.commit()


@contextmanager
def stage_timer(stage: str) -> Iterator[None]:
    """Observe a pipeline stage's duration, labelled with whether it raised."""
    started = time.monotonic()
    outcome = "error"
    try:
        yield
        outcome = "ok"
    finally:
        metrics.scan_stage_duration.labels(stage, outcome).observe(time.monotonic() - started)

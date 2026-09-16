"""Compute, store and project scan scores from persisted findings."""

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import (
    FAILED_RUN_STATUSES,
    AnalyzerRun,
    AnalyzerRunStatus,
    ArchitectureSummary,
    Finding,
    Scan,
    ScanScore,
)
from app.models.finding import Severity
from app.services.scoring.rubric import (
    ScoreContext,
    ScoreReport,
    finding_impacts,
    score,
)


@dataclass(frozen=True)
class ScorableRow:
    """Finding fields the rubric needs, for findings not yet in the database."""

    id: int
    analyzer: str
    rule_id: str
    severity: Severity
    file_path: str
    corroborated_by: list[str]


def context_for_scan(db: Session, scan: Scan) -> ScoreContext:
    runs = db.scalars(select(AnalyzerRun).where(AnalyzerRun.scan_id == scan.id)).all()
    summary = db.get(ArchitectureSummary, scan.id)
    return ScoreContext(
        source_loc=scan.source_loc
        or int((summary.summary if summary else {}).get("total_loc") or 0),
        module_count=int((summary.summary if summary else {}).get("node_count") or 0),
        analyzers_run=frozenset(
            r.analyzer_name for r in runs if r.status is AnalyzerRunStatus.COMPLETED
        ),
        analyzers_failed=frozenset(
            r.analyzer_name for r in runs if r.status in FAILED_RUN_STATUSES
        ),
    )


def store_score(
    db: Session, scan_id: uuid.UUID, report: ScoreReport, context: ScoreContext
) -> ScanScore:
    row = db.get(ScanScore, scan_id) or ScanScore(scan_id=scan_id)
    row.rubric_version = report.rubric_version
    row.overall = report.overall
    row.grade = report.grade
    row.incomplete = report.incomplete
    row.incomplete_reasons = report.incomplete_reasons
    row.categories = [c.as_dict() for c in report.categories]
    row.source_loc = context.source_loc
    row.module_count = context.module_count
    db.add(row)
    return row


def rescore_scan(db: Session, scan: Scan) -> ScanScore:
    """Recompute the score and every finding's impact from what's stored. Does not commit."""
    findings = db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    context = context_for_scan(db, scan)
    impacts = finding_impacts(findings, context)
    for finding in findings:
        finding.score_impact = impacts.get(finding.id)
    return store_score(db, scan.id, score(findings, context), context)


@dataclass(frozen=True)
class Projection:
    current: ScoreReport
    projected: ScoreReport
    included_finding_ids: list[int]
    ignored_finding_ids: list[int]

    @property
    def delta(self) -> float | None:
        if self.current.overall is None or self.projected.overall is None:
            return None
        return round(self.projected.overall - self.current.overall, 2)


def project(db: Session, scan: Scan, finding_ids: Iterable[int]) -> Projection:
    """The score if exactly these findings were fixed (ids from other scans are ignored)."""
    findings: Sequence[Finding] = db.scalars(
        select(Finding).where(Finding.scan_id == scan.id)
    ).all()
    own = {f.id for f in findings}
    requested = list(dict.fromkeys(finding_ids))
    context = context_for_scan(db, scan)
    return Projection(
        current=score(findings, context),
        projected=score(findings, context, exclude_ids=requested),
        included_finding_ids=[i for i in requested if i in own],
        ignored_finding_ids=[i for i in requested if i not in own],
    )


def clear_impacts(db: Session, scan_id: uuid.UUID) -> None:
    db.execute(update(Finding).where(Finding.scan_id == scan_id).values(score_impact=None))

"""Scan lookup and comparison (used by the GitHub Action to report deltas on pull requests)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal, OptionalPrincipal, load_scan
from app.api.errors import AppError, ConflictError
from app.core.db import get_db
from app.models import RESULT_STATUSES, Scan, ScanScore, ScanStatus
from app.schemas.compare import (
    MAX_LISTED_FINDINGS,
    CategoryDelta,
    CompareRead,
    CompareRequest,
    ScanList,
    ScanListItem,
    ScanSide,
)
from app.schemas.errors import ErrorResponse
from app.schemas.finding import FindingRead
from app.services.compare import diff_findings, load_findings, load_score, severity_counts
from app.services.github.urls import OWNER, REPO, SHA

router = APIRouter(prefix="/scans", tags=["scans"])

DbSession = Annotated[Session, Depends(get_db)]


def _errors(*codes: int) -> dict[int | str, dict[str, object]]:
    return {code: {"model": ErrorResponse} for code in codes}


def _repository(scan: Scan) -> str | None:
    return f"{scan.repo_owner}/{scan.repo_name}" if scan.repo_owner else None


@router.get("", response_model=ScanList, responses=_errors(401, 422))
def list_my_scans(
    db: DbSession,
    principal: CurrentPrincipal,
    repo: Annotated[str | None, Query(max_length=201, description="owner/name")] = None,
    commit_sha: Annotated[str | None, Query(max_length=40)] = None,
    status: Annotated[ScanStatus | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
    page: Annotated[int, Query(ge=1, le=10_000)] = 1,
) -> ScanList:
    """Your scans, newest first. Only scans you own are listed."""
    conditions = [Scan.user_id == principal.user.id]
    if repo:
        owner, _, name = repo.partition("/")
        if not (OWNER.match(owner) and REPO.match(name)):
            raise AppError("repo must be owner/name.", code="validation_error")
        conditions += [
            func.lower(Scan.repo_owner) == owner.lower(),
            func.lower(Scan.repo_name) == name.lower(),
        ]
    if commit_sha:
        if not SHA.match(commit_sha):
            raise AppError("commit_sha must be a full 40-character SHA.", code="validation_error")
        conditions.append(Scan.commit_sha == commit_sha.lower())
    if status:
        conditions.append(Scan.status == status)
    total = db.scalar(select(func.count()).select_from(Scan).where(*conditions)) or 0
    rows = db.execute(
        select(Scan, ScanScore)
        .outerjoin(ScanScore, ScanScore.scan_id == Scan.id)
        .where(*conditions)
        .order_by(Scan.created_at.desc())
        .offset((page - 1) * limit)
        .limit(limit)
    ).all()
    return ScanList(
        items=[
            ScanListItem(
                id=scan.id,
                status=scan.status,
                source=scan.source,
                repository=_repository(scan),
                commit_sha=scan.commit_sha,
                repo_ref=scan.repo_ref,
                score=score.overall if score else None,
                grade=score.grade if score else None,
                created_at=scan.created_at,
            )
            for scan, score in rows
        ],
        total=total,
    )


@router.post("/compare", response_model=CompareRead, responses=_errors(404, 409, 422))
def compare_scans(
    request: CompareRequest, db: DbSession, principal: OptionalPrincipal
) -> CompareRead:
    """New and resolved findings, and the score delta, from `base` to `head`."""
    base = load_scan(db, request.base_scan_id, principal)
    head = load_scan(db, request.head_scan_id, principal)
    for label, scan in (("base", base), ("head", head)):
        if scan.status not in RESULT_STATUSES:
            raise ConflictError(
                f"The {label} scan {scan.id} has no results yet (status {scan.status.value}).",
                code="scan_not_ready",
            )
    base_findings, head_findings = load_findings(db, base), load_findings(db, head)
    base_score, head_score = load_score(db, base), load_score(db, head)
    comparison = diff_findings(base_findings, head_findings)

    warnings: list[str] = []
    if _repository(base) != _repository(head):
        warnings.append("The scans are of different repositories.")
    comparable = True
    if base_score is None or head_score is None:
        comparable = False
        warnings.append("A scan has no score.")
    else:
        if base_score.rubric_version != head_score.rubric_version:
            comparable = False
            warnings.append(
                f"Scores use different rubric versions ({base_score.rubric_version} vs"
                f" {head_score.rubric_version})."
            )
        if base_score.incomplete or head_score.incomplete:
            comparable = False
            warnings.append(
                "An analyzer failed in one of the scans, so the score delta is unreliable."
            )
    for label, scan in (("base", base), ("head", head)):
        if scan.status is ScanStatus.PARTIAL:
            warnings.append(f"The {label} scan is partial: some analyzers didn't complete.")

    delta = (
        round(head_score.overall - base_score.overall, 2)
        if base_score
        and head_score
        and base_score.overall is not None
        and head_score.overall is not None
        else None
    )
    base_categories = {c["category"]: c for c in (base_score.categories if base_score else [])}
    categories = []
    for category in head_score.categories if head_score else []:
        before = base_categories.get(category["category"], {}).get("score")
        after = category.get("score")
        categories.append(
            CategoryDelta(
                category=category["category"],
                label=category["label"],
                base=before,
                head=after,
                delta=(
                    round(after - before, 2) if before is not None and after is not None else None
                ),
            )
        )

    def side(scan: Scan, score: ScanScore | None, count: int) -> ScanSide:
        return ScanSide(
            scan_id=scan.id,
            status=scan.status,
            repository=_repository(scan),
            commit_sha=scan.commit_sha,
            score=score.overall if score else None,
            grade=score.grade if score else None,
            rubric_version=score.rubric_version if score else None,
            incomplete=score.incomplete if score else True,
            finding_count=count,
        )

    return CompareRead(
        base=side(base, base_score, len(base_findings)),
        head=side(head, head_score, len(head_findings)),
        score_delta=delta,
        comparable=comparable,
        warnings=warnings,
        categories=categories,
        new_count=len(comparison.new),
        resolved_count=len(comparison.resolved),
        unchanged_count=comparison.unchanged_count,
        new_by_severity=severity_counts(comparison.new),
        resolved_by_severity=severity_counts(comparison.resolved),
        new_findings=[FindingRead.model_validate(f) for f in comparison.new[:MAX_LISTED_FINDINGS]],
        resolved_findings=[
            FindingRead.model_validate(f) for f in comparison.resolved[:MAX_LISTED_FINDINGS]
        ],
    )

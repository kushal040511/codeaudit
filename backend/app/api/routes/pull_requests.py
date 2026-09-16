"""Fix pull requests: preview (read-only), then explicit confirmation (writes to GitHub).

Creating a pull request takes two requests from the scan's owner:

1. POST /scans/{id}/pull-requests/preview computes the exact change against the
   repository's current state and stores a `previewed` row. Nothing is written
   to GitHub.
2. POST /pull-requests/{id}/confirm with `{"confirm": true}` queues the job that
   writes the branch, commits and pull request, after re-checking that the plan
   still matches the preview.

No other code path creates pull requests. Both steps require a browser session:
API tokens (used by CI) can read pull requests but not create them.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, status
from kombu.exceptions import OperationalError as BrokerError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import (
    CurrentPrincipal,
    OptionalPrincipal,
    SessionPrincipal,
    load_owned_scan,
    load_scan,
)
from app.api.errors import (
    AppError,
    ConflictError,
    NotFoundError,
    RateLimitedError,
    ServiceUnavailableError,
)
from app.core.db import get_db
from app.models import (
    RESULT_STATUSES,
    Finding,
    FixStatus,
    FixSuggestion,
    PullRequest,
    PullRequestStatus,
    ValidationStatus,
)
from app.schemas.errors import ErrorResponse
from app.schemas.pull_request import (
    FixCandidateRead,
    PullRequestConfirmRequest,
    PullRequestPreviewRead,
    PullRequestPreviewRequest,
    PullRequestRead,
)
from app.services.github.pr_builder import (
    PullRequestError,
    build_plan,
    preview_details,
    save_preview,
)
from app.services.rate_limit import hit

router = APIRouter(tags=["pull requests"])

DbSession = Annotated[Session, Depends(get_db)]
PREVIEWS_PER_HOUR = 60
# A confirmation must follow the preview reasonably soon; the plan is re-checked anyway.
PREVIEW_TTL = timedelta(minutes=30)


def _errors(*codes: int) -> dict[int | str, dict[str, object]]:
    return {code: {"model": ErrorResponse} for code in codes}


def _app_error(exc: PullRequestError) -> AppError:
    error = AppError(exc.message, code=exc.code, details=exc.details or None)
    error.status_code = exc.http_status
    return error


def _owned_pull_request(db: Session, pr_id: int, principal: CurrentPrincipal) -> PullRequest:
    row = db.get(PullRequest, pr_id)
    if row is None or row.user_id != principal.user.id:
        raise NotFoundError(f"Pull request {pr_id} not found.")
    return row


@router.get(
    "/scans/{scan_id}/fixes", response_model=list[FixCandidateRead], responses=_errors(404, 422)
)
def list_fix_candidates(
    scan_id: uuid.UUID, db: DbSession, principal: OptionalPrincipal
) -> list[FixCandidateRead]:
    """Suggestions with a verified patch: the only ones a pull request can include."""
    load_scan(db, scan_id, principal)
    rows = db.execute(
        select(FixSuggestion, Finding)
        .join(Finding, Finding.id == FixSuggestion.finding_id)
        .where(
            FixSuggestion.scan_id == scan_id,
            FixSuggestion.status == FixStatus.READY,
            FixSuggestion.validation_status == ValidationStatus.VALID,
        )
        .order_by(Finding.score_impact.desc().nulls_last(), Finding.id)
    ).all()
    return [
        FixCandidateRead(
            suggestion_id=suggestion.id,
            finding_id=finding.id,
            severity=finding.severity,
            analyzer=finding.analyzer,
            rule_id=finding.rule_id,
            file_path=finding.file_path,
            start_line=finding.start_line,
            message=finding.message,
            explanation=suggestion.explanation,
            confidence=suggestion.confidence.value if suggestion.confidence else None,
            breaking_risk=suggestion.breaking_risk.value if suggestion.breaking_risk else None,
            score_impact=finding.score_impact,
            shared_with_finding_ids=suggestion.shared_with_finding_ids,
            patch=suggestion.patch or "",
        )
        for suggestion, finding in rows
    ]


@router.post(
    "/scans/{scan_id}/pull-requests/preview",
    response_model=PullRequestPreviewRead,
    status_code=status.HTTP_201_CREATED,
    responses=_errors(401, 403, 404, 409, 422, 429, 502, 503),
)
def preview_pull_request(
    scan_id: uuid.UUID,
    request: PullRequestPreviewRequest,
    db: DbSession,
    principal: SessionPrincipal,
) -> PullRequestPreviewRead:
    """Show exactly what a fix pull request would contain. Writes nothing to GitHub."""
    scan = load_owned_scan(db, scan_id, principal)
    if scan.status not in RESULT_STATUSES:
        raise ConflictError(f"Scan {scan_id} has no results yet (status {scan.status.value}).")
    limit = hit(f"pr_preview:{principal.user.id}", PREVIEWS_PER_HOUR, 3600)
    if not limit.allowed:
        raise RateLimitedError(
            f"Preview limit reached ({PREVIEWS_PER_HOUR} per hour).",
            details={"retry_after_seconds": limit.retry_after_seconds},
        )
    try:
        plan = build_plan(
            db,
            scan,
            principal.user,
            request.suggestion_ids,
            branch=request.branch,
            use_fork=request.use_fork,
        )
    except PullRequestError as exc:
        raise _app_error(exc) from None
    row = save_preview(db, scan, principal.user, plan)
    return PullRequestPreviewRead(
        **PullRequestRead.model_validate(row).model_dump(),
        combined_diff=plan.combined_diff,
        **preview_details(plan, scan),
    )


@router.post(
    "/pull-requests/{pr_id}/confirm",
    response_model=PullRequestRead,
    status_code=status.HTTP_202_ACCEPTED,
    responses=_errors(401, 403, 404, 409, 422, 503),
)
def confirm_pull_request(
    pr_id: int,
    request: PullRequestConfirmRequest,
    db: DbSession,
    principal: SessionPrincipal,
) -> PullRequestRead:
    """Create the previewed pull request. Requires `{"confirm": true}`. Poll GET to follow it."""
    from app.workers.tasks import create_pull_request_task

    row = db.scalar(
        select(PullRequest)
        .where(PullRequest.id == pr_id, PullRequest.user_id == principal.user.id)
        .with_for_update()
    )
    if row is None:
        raise NotFoundError(f"Pull request {pr_id} not found.")
    load_owned_scan(db, row.scan_id, principal)
    if row.status is not PullRequestStatus.PREVIEWED:
        raise ConflictError(
            f"Pull request {pr_id} was already confirmed (status {row.status.value}).",
            code="already_confirmed",
        )
    if datetime.now(UTC) - row.created_at > PREVIEW_TTL:
        raise ConflictError(
            "This preview has expired. Open a new preview and confirm again.",
            code="preview_expired",
        )
    if request.title is not None:
        row.title = request.title
    if request.body is not None:
        row.body = request.body
    row.status = PullRequestStatus.CREATING
    row.confirmed_at = datetime.now(UTC)
    db.commit()

    try:
        create_pull_request_task.delay(row.id)
    except BrokerError as exc:
        row.status = PullRequestStatus.FAILED
        row.error_code = "queue_unavailable"
        row.error_message = "Could not queue the job. Nothing was written to GitHub."
        db.commit()
        raise ServiceUnavailableError("Job queue is unavailable. Try again later.") from exc
    db.refresh(row)
    return PullRequestRead.model_validate(row)


@router.get(
    "/scans/{scan_id}/pull-requests",
    response_model=list[PullRequestRead],
    responses=_errors(401, 404, 422),
)
def list_pull_requests(
    scan_id: uuid.UUID, db: DbSession, principal: CurrentPrincipal
) -> list[PullRequestRead]:
    """Pull requests you confirmed for this scan (previews that were never confirmed are hidden)."""
    load_owned_scan(db, scan_id, principal)
    rows = db.scalars(
        select(PullRequest)
        .where(
            PullRequest.scan_id == scan_id,
            PullRequest.user_id == principal.user.id,
            PullRequest.status != PullRequestStatus.PREVIEWED,
        )
        .order_by(PullRequest.id.desc())
    ).all()
    return [PullRequestRead.model_validate(row) for row in rows]


@router.get(
    "/pull-requests/{pr_id}", response_model=PullRequestRead, responses=_errors(401, 404, 422)
)
def get_pull_request(pr_id: int, db: DbSession, principal: CurrentPrincipal) -> PullRequestRead:
    return PullRequestRead.model_validate(_owned_pull_request(db, pr_id, principal))

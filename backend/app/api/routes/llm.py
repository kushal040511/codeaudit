import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status
from kombu.exceptions import OperationalError as BrokerError
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import OptionalPrincipal, load_scan
from app.api.errors import ConflictError, NotFoundError, ServiceUnavailableError
from app.config import get_settings
from app.core.db import get_db
from app.models import (
    RESULT_STATUSES,
    ArchitectureReview,
    Finding,
    FixStatus,
    FixSuggestion,
    LLMCall,
    ValidationStatus,
)
from app.schemas.errors import ErrorResponse
from app.schemas.llm import (
    ArchitectureReviewRead,
    FixSuggestionRead,
    LLMCallRead,
    LLMUsageRead,
    RegenerateFixRequest,
)
from app.services.llm.client import llm_configured, tokens_used
from app.services.llm.pricing import is_priced
from app.services.llm.usage import usage_by_purpose

router = APIRouter(prefix="/scans/{scan_id}", tags=["llm"])

DbSession = Annotated[Session, Depends(get_db)]
RECENT_CALLS = 100


def _errors(*codes: int) -> dict[int | str, dict[str, object]]:
    return {code: {"model": ErrorResponse} for code in codes}


def _finding_or_404(db: Session, scan_id: uuid.UUID, finding_id: int) -> Finding:
    finding = db.get(Finding, finding_id)
    if finding is None or finding.scan_id != scan_id:
        raise NotFoundError(f"Finding {finding_id} not found in scan {scan_id}.")
    return finding


def to_read(suggestion: FixSuggestion) -> FixSuggestionRead:
    verified = suggestion.validation_status is ValidationStatus.VALID
    return FixSuggestionRead(
        finding_id=suggestion.finding_id,
        status=suggestion.status,
        validation_status=suggestion.validation_status,
        patch_verified=verified,
        validation_detail=suggestion.validation_detail,
        explanation=suggestion.explanation,
        confidence=suggestion.confidence,
        patch=suggestion.patch if verified else None,
        rejected_patch=None if verified else suggestion.patch,
        breaking_risk=suggestion.breaking_risk,
        test_suggestion=suggestion.test_suggestion,
        file_changes=suggestion.file_changes if verified else [],
        shared_with_finding_ids=suggestion.shared_with_finding_ids,
        user_hint=suggestion.user_hint,
        version=suggestion.version,
        model=suggestion.model,
        error_message=suggestion.error_message,
        updated_at=suggestion.updated_at,
    )


@router.get(
    "/findings/{finding_id}/fix", response_model=FixSuggestionRead, responses=_errors(404, 422)
)
def get_fix(
    scan_id: uuid.UUID, finding_id: int, db: DbSession, principal: OptionalPrincipal
) -> FixSuggestionRead:
    """The fix suggestion for a finding. The patch is only included if it was verified."""
    load_scan(db, scan_id, principal)
    _finding_or_404(db, scan_id, finding_id)
    suggestion = db.scalar(select(FixSuggestion).where(FixSuggestion.finding_id == finding_id))
    if suggestion is None:
        raise NotFoundError(
            f"No fix suggestion for finding {finding_id}: only the highest-priority findings"
            " get one automatically. Request one with POST .../fix/regenerate."
        )
    return to_read(suggestion)


@router.post(
    "/findings/{finding_id}/fix/regenerate",
    response_model=FixSuggestionRead,
    status_code=status.HTTP_202_ACCEPTED,
    responses=_errors(404, 409, 422, 503),
)
def regenerate_fix(
    scan_id: uuid.UUID,
    finding_id: int,
    db: DbSession,
    principal: OptionalPrincipal,
    body: RegenerateFixRequest | None = None,
) -> FixSuggestionRead:
    """Queue a new suggestion for this finding, optionally guided by a hint. Poll GET .../fix."""
    from app.workers.tasks import regenerate_fix_task

    # Anonymous scans stay regenerable by id holders; owned scans only by the owner.
    scan = load_scan(db, scan_id, principal)
    finding = _finding_or_404(db, scan_id, finding_id)
    if reason := llm_configured():
        raise ServiceUnavailableError(reason)
    if scan.status not in RESULT_STATUSES:
        raise ConflictError(f"Scan {scan_id} has no results yet (status {scan.status.value}).")
    if finding.analyzer == "architecture":
        raise ConflictError(
            "Structural issues are covered by the architecture review, not patches."
        )
    settings = get_settings()
    remaining = settings.llm_token_budget_per_scan - tokens_used(db, scan_id)
    if remaining < settings.llm_max_output_tokens:
        raise ConflictError(
            f"The scan's LLM token budget is exhausted ({remaining:,} of"
            f" {settings.llm_token_budget_per_scan:,} tokens left)."
        )

    suggestion = db.scalar(
        select(FixSuggestion).where(FixSuggestion.finding_id == finding_id).with_for_update()
    )
    if suggestion is not None and suggestion.status is FixStatus.GENERATING:
        raise ConflictError("A suggestion for this finding is already being generated.")
    if suggestion is None:
        suggestion = FixSuggestion(scan_id=scan_id, finding_id=finding_id, version=0)
        db.add(suggestion)
    suggestion.status = FixStatus.GENERATING
    # The previous patch and its validation result stay until the new one replaces
    # them: the regeneration prompt uses them.
    if suggestion.validation_status is None:
        suggestion.validation_status = ValidationStatus.NOT_VALIDATED
    suggestion.error_message = None
    suggestion.user_hint = body.hint if body else None
    db.commit()

    try:
        regenerate_fix_task.delay(str(scan_id), finding_id, body.hint if body else None)
    except BrokerError as exc:
        suggestion.status = FixStatus.FAILED
        suggestion.error_message = "Could not queue the regeneration job."
        db.commit()
        raise ServiceUnavailableError("Job queue is unavailable. Try again later.") from exc
    db.refresh(suggestion)
    return to_read(suggestion)


@router.get(
    "/architecture-review", response_model=ArchitectureReviewRead, responses=_errors(404, 422)
)
def get_architecture_review(
    scan_id: uuid.UUID, db: DbSession, principal: OptionalPrincipal
) -> ArchitectureReviewRead:
    """The model's structural critique; every cited module was checked against the graph."""
    scan = load_scan(db, scan_id, principal)
    review = db.get(ArchitectureReview, scan_id)
    if review is None:
        detail = f" ({scan.enrichment_error})" if scan.enrichment_error else ""
        raise NotFoundError(f"Scan {scan_id} has no architecture review{detail}.")
    return ArchitectureReviewRead.model_validate(review)


@router.get("/llm-usage", response_model=LLMUsageRead, responses=_errors(404, 422))
def get_llm_usage(scan_id: uuid.UUID, db: DbSession, principal: OptionalPrincipal) -> LLMUsageRead:
    """Tokens, cost and latency of every model call for this scan."""
    scan = load_scan(db, scan_id, principal)
    settings = get_settings()
    totals = db.execute(
        select(
            func.coalesce(
                func.sum(
                    LLMCall.input_tokens
                    + LLMCall.cache_creation_input_tokens
                    + LLMCall.cache_read_input_tokens
                ),
                0,
            ),
            func.coalesce(func.sum(LLMCall.output_tokens), 0),
            func.coalesce(func.sum(LLMCall.cost_usd), 0),
            func.count(LLMCall.id),
            func.count(LLMCall.id).filter(LLMCall.success.is_(False)),
            func.coalesce(func.sum(LLMCall.duration_ms), 0),
            func.max(LLMCall.model),
        ).where(LLMCall.scan_id == scan_id)
    ).one()
    input_tokens, output_tokens, cost, calls, failed, duration, model = totals
    calls_list = db.scalars(
        select(LLMCall)
        .where(LLMCall.scan_id == scan_id)
        .order_by(LLMCall.id.desc())
        .limit(RECENT_CALLS)
    ).all()
    model_name = model or settings.anthropic_model
    return LLMUsageRead(
        enrichment_status=scan.enrichment_status,
        enrichment_error=scan.enrichment_error,
        model=model,
        token_budget=settings.llm_token_budget_per_scan,
        tokens_used=tokens_used(db, scan_id),
        input_tokens=int(input_tokens),
        output_tokens=int(output_tokens),
        cost_usd=round(float(cost), 6),
        calls=int(calls),
        failed_calls=int(failed),
        total_duration_ms=int(duration),
        pricing_note=(
            "Anthropic first-party API list prices (2026-06-24), including cache pricing."
            if is_priced(model_name)
            else f"No price known for {model_name}; cost shown as $0."
        ),
        by_purpose=usage_by_purpose(db, scan_id),
        recent_calls=[LLMCallRead.model_validate(c) for c in calls_list],
    )

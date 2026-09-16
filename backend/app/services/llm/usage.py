"""Token and cost accounting per scan, from the LLMCall log."""

import uuid

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.models import FixStatus, FixSuggestion, LLMCall, LLMPurpose, ValidationStatus
from app.schemas.llm import LLMUsageByPurpose, LLMUsageSummary

TOKENS = (
    LLMCall.input_tokens
    + LLMCall.output_tokens
    + LLMCall.cache_creation_input_tokens
    + LLMCall.cache_read_input_tokens
)


def usage_by_purpose(db: Session, scan_id: uuid.UUID) -> list[LLMUsageByPurpose]:
    rows = db.execute(
        select(
            LLMCall.purpose,
            func.count(),
            func.sum(case((LLMCall.success.is_(False), 1), else_=0)),
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
        )
        .where(LLMCall.scan_id == scan_id)
        .group_by(LLMCall.purpose)
        .order_by(LLMCall.purpose)
    ).all()
    return [
        LLMUsageByPurpose(
            purpose=LLMPurpose(purpose),
            calls=calls,
            failed_calls=int(failed or 0),
            input_tokens=int(input_tokens),
            output_tokens=int(output_tokens),
            cost_usd=round(float(cost), 6),
        )
        for purpose, calls, failed, input_tokens, output_tokens, cost in rows
    ]


def llm_usage_summary(db: Session, scan_id: uuid.UUID) -> LLMUsageSummary:
    tokens, cost, calls = db.execute(
        select(
            func.coalesce(func.sum(TOKENS), 0),
            func.coalesce(func.sum(LLMCall.cost_usd), 0),
            func.count(LLMCall.id),
        ).where(LLMCall.scan_id == scan_id)
    ).one()
    suggestions, valid = db.execute(
        select(
            func.count(FixSuggestion.id),
            func.sum(case((FixSuggestion.validation_status == ValidationStatus.VALID, 1), else_=0)),
        ).where(FixSuggestion.scan_id == scan_id, FixSuggestion.status == FixStatus.READY)
    ).one()
    return LLMUsageSummary(
        tokens=int(tokens),
        cost_usd=round(float(cost), 6),
        calls=int(calls),
        fix_suggestions=int(suggestions or 0),
        valid_fix_suggestions=int(valid or 0),
    )

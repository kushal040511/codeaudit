"""Quota status for everyone; operator endpoints for costs, the kill switch and quotas."""

import json
import uuid
from typing import Annotated, Any, Literal, cast

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.deps import CurrentPrincipal, OptionalPrincipal
from app.api.errors import ForbiddenError, NotFoundError
from app.core.celery_app import DEAD_LETTER_KEY
from app.core.db import get_db
from app.core.redis_client import get_redis
from app.models import User
from app.schemas.errors import ErrorResponse
from app.services import costs, quotas
from app.services.auth.sessions import Principal

router = APIRouter(tags=["quotas", "admin"])
DbSession = Annotated[Session, Depends(get_db)]


def _errors(*codes: int) -> dict[int | str, dict[str, object]]:
    return {code: {"model": ErrorResponse} for code in codes}


class LimitRead(BaseModel):
    name: str
    description: str
    limit: int
    used: int
    remaining: int
    window_seconds: int
    reset_seconds: int


class QuotaRead(BaseModel):
    tier: str
    limits: list[LimitRead]
    llm_tokens: dict[str, Any]
    llm_available: bool
    llm_blocked_reason: str | None


@router.get("/quotas", response_model=QuotaRead)
def get_quotas(request: Request, db: DbSession, principal: OptionalPrincipal) -> QuotaRead:
    """Your current limits and what's left (per client IP when signed out)."""
    user = principal.user if principal else None
    subject = quotas.subject_for(user, quotas.client_ip(request))
    limits = []
    names: tuple[quotas.LimitName, ...] = (
        "scans",
        "site_analyses",
        "pull_requests",
        "pr_previews",
        "requests",
    )
    for name_ in names:
        name = str(name_)
        state = quotas.peek(subject, name_)
        limits.append(
            LimitRead(
                name=name,
                description=quotas.DESCRIPTIONS[name_],
                limit=state.limit,
                used=state.used,
                remaining=state.remaining,
                window_seconds=quotas.WINDOWS[name_],
                reset_seconds=state.reset_seconds,
            )
        )
    token_quota = quotas.llm_token_quota(db, user)
    blocked = costs.blocked_reason(db)
    return QuotaRead(
        tier=subject.tier,
        limits=limits,
        llm_tokens={
            "limit": token_quota.limit,
            "used": token_quota.used,
            "remaining": token_quota.remaining,
            "resets_at": token_quota.resets_at,
            "shared_by_anonymous_users": user is None,
        },
        llm_available=blocked is None,
        # Operators see the reason; everyone else just that suggestions are paused.
        llm_blocked_reason=(
            blocked
            if blocked and user is not None and user.is_admin
            else ("Fix suggestions are temporarily paused." if blocked else None)
        ),
    )


def require_admin(principal: CurrentPrincipal) -> Principal:
    if not principal.user.is_admin:
        raise ForbiddenError("Operator access required.", code="admin_required")
    return principal


AdminPrincipal = Annotated[Principal, Depends(require_admin)]


@router.get("/admin/costs", responses=_errors(401, 403))
def cost_dashboard(
    db: DbSession, _: AdminPrincipal, days: Annotated[int, Query(ge=1, le=90)] = 30
) -> dict[str, Any]:
    """LLM spend by day, by user and by purpose, plus today's cap status."""
    return costs.spend_report(db, days)


class KillSwitchRequest(BaseModel):
    enabled: bool
    reason: str = Field(default="manual", max_length=300)


@router.post("/admin/llm-kill-switch", responses=_errors(401, 403))
def llm_kill_switch(body: KillSwitchRequest, principal: AdminPrincipal) -> dict[str, Any]:
    """Turn every LLM call off (or back on) immediately. Scans still complete."""
    if body.enabled:
        costs.set_kill_switch(f"{body.reason} (by {principal.user.display_name})")
    else:
        costs.clear_kill_switch()
    return {"kill_switch": costs.kill_switch_reason()}


@router.get("/admin/dead-letters", responses=_errors(401, 403))
def dead_letters(
    _: AdminPrincipal, limit: Annotated[int, Query(ge=1, le=500)] = 100
) -> list[dict[str, Any]]:
    """Tasks that failed permanently, newest first."""
    raw = cast(list[bytes], get_redis().lrange(DEAD_LETTER_KEY, 0, limit - 1))
    return [json.loads(item) for item in raw]


class QuotaUpdate(BaseModel):
    tier: Literal["free", "pro"] | None = None
    # null clears an override (back to the tier default).
    overrides: dict[
        Literal["scans", "site_analyses", "pull_requests", "pr_previews", "requests", "llm_tokens"],
        int | None,
    ] = Field(default_factory=dict)


@router.patch("/admin/users/{user_id}/quota", responses=_errors(401, 403, 404))
def update_user_quota(
    user_id: uuid.UUID, body: QuotaUpdate, db: DbSession, _: AdminPrincipal
) -> dict[str, Any]:
    user = db.get(User, user_id)
    if user is None:
        raise NotFoundError("User not found.")
    if body.tier is not None:
        user.quota_tier = body.tier
    for name, value in body.overrides.items():
        if value is not None and value < 0:
            raise ForbiddenError("Quota overrides can't be negative.", code="validation_error")
        setattr(user, f"quota_{name}", value)
    db.commit()
    return {
        "user_id": str(user.id),
        "tier": user.quota_tier,
        "overrides": {
            name: getattr(user, f"quota_{name}")
            for name in (
                "scans",
                "site_analyses",
                "pull_requests",
                "pr_previews",
                "requests",
                "llm_tokens",
            )
        },
    }

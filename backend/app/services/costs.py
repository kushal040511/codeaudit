"""LLM cost controls: daily spend cap, kill switch, alerts, spend reporting.

- Every LLM call is reserved before it's sent with a worst-case cost estimate stored
  on its LLMCall row, so today's spend (finished calls + in-flight estimates) can't be
  overshot by concurrent calls. The reservation takes a transaction-scoped advisory
  lock so the check-and-reserve is serialised across workers.
- When today's spend would exceed LLM_DAILY_SPEND_CAP_USD, or an operator has set the
  kill switch, calls are refused and the LLM stage is skipped; scans still complete.
- Crossing LLM_SPEND_ALERT_RATIO of the cap (and reaching the cap) logs a warning and,
  if ALERT_WEBHOOK_URL is set, posts a JSON alert. Each alert fires once per UTC day.
"""

import logging
import threading
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Any, cast

import httpx
from sqlalchemy import Date, func, select, text
from sqlalchemy import cast as sql_cast
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core import metrics
from app.core.redis_client import get_redis
from app.models import LLMCall, Scan, SiteAnalysis, User

logger = logging.getLogger(__name__)

KILL_SWITCH_KEY = "codeaudit:llm:kill_switch"
ALERT_KEY = "codeaudit:llm:alert:{day}:{level}"
SPEND_LOCK_ID = 7_302_001  # pg_advisory_xact_lock key for the daily spend check


def day_start(now: datetime | None = None) -> datetime:
    now = now or datetime.now(UTC)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def spend_today(db: Session) -> float:
    """Finished calls' cost plus in-flight reservations' worst-case estimates."""
    total = db.scalar(
        select(func.coalesce(func.sum(LLMCall.cost_usd), 0)).where(
            LLMCall.created_at >= day_start()
        )
    )
    return float(total or 0)


def kill_switch_reason() -> str | None:
    value = cast(bytes | None, get_redis().get(KILL_SWITCH_KEY))
    return value.decode() if value else None


def set_kill_switch(reason: str) -> None:
    get_redis().set(KILL_SWITCH_KEY, reason[:300])
    logger.warning("LLM kill switch engaged: %s", reason)


def clear_kill_switch() -> None:
    get_redis().delete(KILL_SWITCH_KEY)
    logger.warning("LLM kill switch cleared")


def lock_daily_spend(db: Session) -> None:
    db.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": SPEND_LOCK_ID})


def blocked_reason(db: Session, additional_usd: float = 0.0) -> str | None:
    """Why no (further) LLM spend is allowed right now, or None."""
    if reason := kill_switch_reason():
        return f"LLM features are switched off by an operator ({reason})."
    cap = get_settings().llm_daily_spend_cap_usd
    spent = spend_today(db)
    if cap <= 0 or spent + additional_usd > cap:
        return (
            f"The daily LLM spend cap (${cap:,.2f}) has been reached; fix suggestions resume"
            " tomorrow (UTC)."
        )
    return None


@dataclass(frozen=True)
class Alert:
    level: str
    spent: float
    cap: float


def check_spend_alerts(db: Session) -> Alert | None:
    """Fire the threshold alerts once per day. Returns the alert raised, if any."""
    settings = get_settings()
    cap = settings.llm_daily_spend_cap_usd
    if cap <= 0:
        return None
    spent = spend_today(db)
    metrics.llm_spend_today.set(spent)
    level = (
        "cap_reached"
        if spent >= cap
        else "threshold" if spent >= cap * settings.llm_spend_alert_ratio else None
    )
    if level is None:
        return None
    key = ALERT_KEY.format(day=date.today().isoformat(), level=level)
    if not get_redis().set(key, "1", nx=True, ex=2 * 86_400):
        return None
    alert = Alert(level, round(spent, 4), cap)
    logger.warning(
        "LLM spend alert: %s ($%.2f of $%.2f daily cap)",
        level,
        spent,
        cap,
        extra={"alert": "llm_spend", "level": level, "spent_usd": spent, "cap_usd": cap},
    )
    if settings.alert_webhook_url:
        threading.Thread(
            target=_post_webhook, args=(settings.alert_webhook_url, alert), daemon=True
        ).start()
    return alert


def _post_webhook(url: str, alert: Alert) -> None:
    percent = round(alert.spent / alert.cap * 100)
    payload = {
        "text": (
            f"CodeAudit LLM spend {'reached the daily cap' if alert.level == 'cap_reached' else 'alert'}:"  # noqa: E501
            f" ${alert.spent:,.2f} of ${alert.cap:,.2f} ({percent}%)."
        ),
        "event": "llm_spend_alert",
        "level": alert.level,
        "spent_usd": alert.spent,
        "cap_usd": alert.cap,
        "environment": get_settings().environment,
    }
    try:
        httpx.post(url, json=payload, timeout=5.0, follow_redirects=False)
    except httpx.HTTPError as exc:
        logger.warning("spend alert webhook failed: %s", type(exc).__name__)


# ------------------------------------------------------------------ reporting


def spend_report(db: Session, days: int) -> dict[str, Any]:
    since = day_start() - timedelta(days=days - 1)
    finished = LLMCall.pending.is_(False)
    tokens = (
        LLMCall.input_tokens
        + LLMCall.output_tokens
        + LLMCall.cache_creation_input_tokens
        + LLMCall.cache_read_input_tokens
    )
    by_day = db.execute(
        select(
            sql_cast(LLMCall.created_at, Date).label("day"),
            func.sum(LLMCall.cost_usd),
            func.sum(tokens),
            func.count(LLMCall.id),
            func.count(LLMCall.id).filter(LLMCall.success.is_(False)),
        )
        .where(LLMCall.created_at >= since, finished)
        .group_by("day")
        .order_by("day")
    ).all()
    by_purpose = db.execute(
        select(
            LLMCall.purpose, func.sum(LLMCall.cost_usd), func.sum(tokens), func.count(LLMCall.id)
        )
        .where(LLMCall.created_at >= since, finished)
        .group_by(LLMCall.purpose)
        .order_by(func.sum(LLMCall.cost_usd).desc())
    ).all()
    owner = func.coalesce(Scan.user_id, SiteAnalysis.user_id)
    by_user = db.execute(
        select(
            owner.label("user_id"),
            func.sum(LLMCall.cost_usd),
            func.sum(tokens),
            func.count(LLMCall.id),
        )
        .select_from(LLMCall)
        .outerjoin(Scan, Scan.id == LLMCall.scan_id)
        .outerjoin(SiteAnalysis, SiteAnalysis.id == LLMCall.site_analysis_id)
        .where(LLMCall.created_at >= since, finished)
        .group_by(owner)
        .order_by(func.sum(LLMCall.cost_usd).desc())
        .limit(50)
    ).all()
    names = {
        u.id: u.display_name
        for u in db.scalars(select(User).where(User.id.in_([r[0] for r in by_user if r[0]]))).all()
    }
    settings = get_settings()
    today = spend_today(db)
    return {
        "days": days,
        "currency": "USD",
        "today": {
            "spent_usd": round(today, 4),
            "cap_usd": settings.llm_daily_spend_cap_usd,
            "used_ratio": (
                round(today / settings.llm_daily_spend_cap_usd, 4)
                if settings.llm_daily_spend_cap_usd > 0
                else None
            ),
            "kill_switch": kill_switch_reason(),
            "blocked_reason": blocked_reason(db),
        },
        "total_usd": round(sum(float(r[1] or 0) for r in by_day), 4),
        "by_day": [
            {
                "day": r[0].isoformat(),
                "cost_usd": round(float(r[1] or 0), 4),
                "tokens": int(r[2] or 0),
                "calls": r[3],
                "failed_calls": r[4],
            }
            for r in by_day
        ],
        "by_purpose": [
            {
                "purpose": r[0].value,
                "cost_usd": round(float(r[1] or 0), 4),
                "tokens": int(r[2] or 0),
                "calls": r[3],
            }
            for r in by_purpose
        ],
        "by_user": [
            {
                "user_id": str(r[0]) if r[0] else None,
                "display_name": names.get(r[0]) if r[0] else "(anonymous)",
                "cost_usd": round(float(r[1] or 0), 4),
                "tokens": int(r[2] or 0),
                "calls": r[3],
            }
            for r in by_user
        ],
        "pricing_note": "Costs are estimates from the per-model price table at call time.",
    }


def owner_of_subject(
    db: Session, scan_id: uuid.UUID | None, site_analysis_id: uuid.UUID | None
) -> tuple[bool, User | None]:
    """(found, owner) for an LLM call subject; owner None means anonymous."""
    if scan_id is not None:
        scan = db.get(Scan, scan_id)
        return scan is not None, (db.get(User, scan.user_id) if scan and scan.user_id else None)
    site = db.get(SiteAnalysis, site_analysis_id)
    return site is not None, (db.get(User, site.user_id) if site and site.user_id else None)

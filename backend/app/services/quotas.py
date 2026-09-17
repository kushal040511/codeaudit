"""Rate limits and quotas: Redis sliding windows, tiered defaults, per-user overrides.

Limits (all sliding windows, so a burst at a window boundary can't double a quota):

    requests        per IP (anonymous) or per user, per minute: all API requests
    scans           per day
    site_analyses   per day
    pull_requests   per day (confirmed PRs)
    pr_previews     per hour
    llm_tokens      per month (enforced when an LLM call is reserved, not here)

Tiers: `anonymous` (keyed by client IP), `free` (every signed-in user by default),
`pro` (granted per user). Defaults come from settings; a user row can override any
quota. Refusals raise RateLimitedError carrying `Retry-After`, which limit was hit
and when it resets. Every limit a request consumes is recorded so the response gets
`X-RateLimit-*` headers for the tightest one.
"""

import contextvars
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal, cast

from fastapi import Request
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.core import metrics
from app.core.errors import RateLimitedError
from app.core.redis_client import get_redis
from app.models import LLMCall, Scan, SiteAnalysis, User

LimitName = Literal["requests", "scans", "site_analyses", "pull_requests", "pr_previews"]
Tier = Literal["anonymous", "free", "pro"]

WINDOWS: dict[LimitName, int] = {
    "requests": 60,
    "scans": 86_400,
    "site_analyses": 86_400,
    "pull_requests": 86_400,
    "pr_previews": 3_600,
}
DESCRIPTIONS: dict[LimitName, str] = {
    "requests": "API requests per minute",
    "scans": "scans per day",
    "site_analyses": "site analyses per day",
    "pull_requests": "pull requests per day",
    "pr_previews": "pull request previews per hour",
}

# Atomic sliding window: drop entries older than the window, count, add if allowed.
# Returns {allowed, count, oldest_timestamp_ms}.
SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
local cost = tonumber(ARGV[5])
redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)
local allowed = 0
if cost == 0 then
  allowed = count < limit and 1 or 0
elseif count + cost <= limit then
  for i = 1, cost do redis.call('ZADD', key, now, member .. ':' .. i) end
  count = count + cost
  allowed = 1
end
redis.call('PEXPIRE', key, window)
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local oldest_ts = now
if oldest[2] then oldest_ts = tonumber(oldest[2]) end
return {allowed, count, oldest_ts}
"""

# Set to a fresh list per HTTP request by RequestContextMiddleware; None elsewhere.
consumed_limits_var: contextvars.ContextVar[list["LimitState"] | None] = contextvars.ContextVar(
    "consumed_limits", default=None
)


@dataclass(frozen=True)
class LimitState:
    name: str
    limit: int
    used: int
    reset_seconds: int  # until the oldest counted event leaves the window
    allowed: bool

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)


@dataclass(frozen=True)
class Subject:
    """Who a limit applies to: a user, or an anonymous client IP."""

    tier: Tier
    key: str
    user: User | None = None


def tier_defaults(tier: Tier) -> dict[str, int]:
    settings = get_settings()
    table: dict[Tier, dict[str, int]] = {
        "anonymous": {
            "requests": settings.quota_anonymous_requests_per_minute,
            "scans": settings.quota_anonymous_scans_per_day,
            "site_analyses": settings.quota_anonymous_site_analyses_per_day,
            "pull_requests": 0,
            "pr_previews": 0,
            "llm_tokens": settings.quota_anonymous_llm_tokens_per_month,
        },
        "free": {
            "requests": settings.quota_free_requests_per_minute,
            "scans": settings.quota_free_scans_per_day,
            "site_analyses": settings.quota_free_site_analyses_per_day,
            "pull_requests": settings.quota_free_pull_requests_per_day,
            "pr_previews": settings.quota_free_pr_previews_per_hour,
            "llm_tokens": settings.quota_free_llm_tokens_per_month,
        },
        "pro": {
            "requests": settings.quota_pro_requests_per_minute,
            "scans": settings.quota_pro_scans_per_day,
            "site_analyses": settings.quota_pro_site_analyses_per_day,
            "pull_requests": settings.quota_pro_pull_requests_per_day,
            "pr_previews": settings.quota_pro_pr_previews_per_hour,
            "llm_tokens": settings.quota_pro_llm_tokens_per_month,
        },
    }
    return table[tier]


def limit_for(subject: Subject, name: str) -> int:
    if subject.user is not None:
        override = getattr(subject.user, f"quota_{name}", None)
        if override is not None:
            return int(override)
    return tier_defaults(subject.tier)[name]


def client_ip(request: Request) -> str:
    """The client address, honouring X-Forwarded-For only from trusted proxy hops."""
    hops = get_settings().trusted_proxy_hops
    forwarded = request.headers.get("x-forwarded-for")
    if hops > 0 and forwarded:
        addresses = [a.strip() for a in forwarded.split(",") if a.strip()]
        if len(addresses) >= hops:
            return addresses[-hops]
    return request.client.host if request.client else "unknown"


def subject_for(user: User | None, ip: str) -> Subject:
    if user is None:
        return Subject("anonymous", f"ip:{ip}")
    tier = cast(Tier, user.quota_tier or "free")
    return Subject(tier if tier in ("free", "pro") else "free", f"user:{user.id}", user)


def _window(subject: Subject, name: str, window: int, limit: int, cost: int) -> LimitState:
    now_ms = int(time.time() * 1000)
    key = f"codeaudit:limit:{name}:{subject.key}"
    redis = get_redis()
    allowed, count, oldest = cast(
        list[int],
        redis.eval(
            SLIDING_WINDOW_LUA,
            1,
            key,
            str(now_ms),
            str(window * 1000),
            str(limit),
            uuid.uuid4().hex,
            str(cost),
        ),
    )
    reset = max(1, int((int(oldest) + window * 1000 - now_ms) / 1000) + 1) if count else 0
    return LimitState(name, limit, int(count), reset, bool(allowed))


def _format_reset(seconds: int) -> str:
    at = datetime.now(UTC) + timedelta(seconds=seconds)
    if seconds < 90:
        return f"in {seconds} seconds"
    if seconds < 5400:
        return f"in {round(seconds / 60)} minutes ({at:%H:%M} UTC)"
    return f"at {at:%Y-%m-%d %H:%M} UTC"


def consume(subject: Subject, name: LimitName, *, cost: int = 1, stage: str = "api") -> LimitState:
    """Count `cost` events against a limit, or raise RateLimitedError if it would be exceeded."""
    limit = limit_for(subject, name)
    state = _window(subject, name, WINDOWS[name], limit, cost)
    consumed = consumed_limits_var.get()
    if consumed is not None:
        consumed.append(state)
    if not state.allowed:
        metrics.quota_rejections.labels(name, stage).inc()
        who = (
            " Sign in for higher limits."
            if subject.tier == "anonymous" and name != "pull_requests"
            else ""
        )
        if limit == 0:
            message = f"Your plan doesn't include {DESCRIPTIONS[name]}.{who}"
        else:
            message = (
                f"Limit reached: {limit} {DESCRIPTIONS[name]} ({subject.tier} tier). It resets"
                f" {_format_reset(state.reset_seconds)}.{who}"
            )
        raise RateLimitedError(
            message,
            code="quota_exceeded" if name != "requests" else "rate_limited",
            details={
                "limit": name,
                "tier": subject.tier,
                "max": limit,
                "retry_after_seconds": state.reset_seconds,
            },
            headers={"Retry-After": str(state.reset_seconds)},
        )
    return state


def peek(subject: Subject, name: LimitName) -> LimitState:
    return _window(subject, name, WINDOWS[name], limit_for(subject, name), 0)


# ------------------------------------------------------------------ monthly LLM tokens


def month_start(now: datetime | None = None) -> datetime:
    now = now or datetime.now(UTC)
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _call_tokens() -> Any:
    """Tokens a call counts against a quota: what it used once finished, and its
    worst-case reservation only while it is still in flight."""
    return (
        LLMCall.input_tokens
        + LLMCall.output_tokens
        + LLMCall.cache_creation_input_tokens
        + LLMCall.cache_read_input_tokens
        + case((LLMCall.pending.is_(True), LLMCall.reserved_tokens), else_=0)
    )


def llm_tokens_used_this_month(db: Session, user_id: uuid.UUID) -> int:
    tokens = _call_tokens()
    since = month_start()
    scans = db.scalar(
        select(func.coalesce(func.sum(tokens), 0))
        .join(Scan, Scan.id == LLMCall.scan_id)
        .where(Scan.user_id == user_id, LLMCall.created_at >= since)
    )
    sites = db.scalar(
        select(func.coalesce(func.sum(tokens), 0))
        .join(SiteAnalysis, SiteAnalysis.id == LLMCall.site_analysis_id)
        .where(SiteAnalysis.user_id == user_id, LLMCall.created_at >= since)
    )
    return int(scans or 0) + int(sites or 0)


def llm_tokens_used_anonymous_this_month(db: Session) -> int:
    """Anonymous scans share one pool (they can't be attributed to an IP after the fact)."""
    tokens = _call_tokens()
    since = month_start()
    scans = db.scalar(
        select(func.coalesce(func.sum(tokens), 0))
        .join(Scan, Scan.id == LLMCall.scan_id)
        .where(Scan.user_id.is_(None), LLMCall.created_at >= since)
    )
    sites = db.scalar(
        select(func.coalesce(func.sum(tokens), 0))
        .join(SiteAnalysis, SiteAnalysis.id == LLMCall.site_analysis_id)
        .where(SiteAnalysis.user_id.is_(None), LLMCall.created_at >= since)
    )
    return int(scans or 0) + int(sites or 0)


@dataclass(frozen=True)
class TokenQuota:
    limit: int
    used: int
    resets_at: datetime

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.used)


def llm_token_quota(db: Session, user: User | None) -> TokenQuota:
    start = month_start()
    next_month = (start + timedelta(days=32)).replace(day=1)
    if user is None:
        limit = tier_defaults("anonymous")["llm_tokens"]
        return TokenQuota(limit, llm_tokens_used_anonymous_this_month(db), next_month)
    subject = subject_for(user, "")
    return TokenQuota(
        limit_for(subject, "llm_tokens"), llm_tokens_used_this_month(db, user.id), next_month
    )

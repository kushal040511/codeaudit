"""Fixed-window rate limits in Redis."""

import time
from dataclasses import dataclass

from app.core.redis_client import get_redis


@dataclass(frozen=True)
class RateLimitResult:
    allowed: bool
    remaining: int
    retry_after_seconds: int


def hit(key: str, limit: int, window_seconds: int) -> RateLimitResult:
    now = int(time.time())
    window = now // window_seconds
    redis_key = f"codeaudit:ratelimit:{key}:{window}"
    pipeline = get_redis().pipeline()
    pipeline.incr(redis_key)
    pipeline.expire(redis_key, window_seconds + 5)
    count = int(pipeline.execute()[0])
    retry_after = (window + 1) * window_seconds - now
    return RateLimitResult(count <= limit, max(0, limit - count), retry_after)

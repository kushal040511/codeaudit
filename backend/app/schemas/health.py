from typing import Literal

from pydantic import BaseModel


class ComponentCheck(BaseModel):
    status: Literal["ok", "error"]
    latency_ms: float | None = None
    detail: str | None = None


class HealthResponse(BaseModel):
    status: Literal["ok", "unavailable"]
    version: str
    checks: dict[str, ComponentCheck]

"""Shared contract for the experimental rubric-1.1 signals.

Every experimental analyzer returns a `SignalReport` as its `AnalyzerResult.artifact`.
The pipeline stores `as_dict()` in `scans.signal_metrics[name]` (or, for advisory
metrics, `scans.advisory_metrics`). The rubric reads only `score` and `components`,
so a signal can be re-scored offline from what's stored.

Conventions:
- `score` and every component are in [0, 1], 1 = best, or None when unavailable.
- `applicable` False means the signal couldn't be computed for this codebase
  (no .git, no CI config, no tests, offline registry...). An inapplicable signal is
  never a penalty: the rubric skips it and says why.
- `metrics` holds the raw measurements (counts, ratios, lists) behind the score.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

EXPERIMENTAL_SIGNALS = ("error_handling", "dep_health", "git_history", "ci_quality", "test_quality")
ADVISORY = "advisory"


@dataclass
class SignalReport:
    name: str
    applicable: bool
    score: float | None = None
    components: dict[str, float | None] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None  # why not applicable, or what limited it

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "applicable": self.applicable,
            "score": None if self.score is None else round(self.score, 4),
            "components": {
                k: None if v is None else round(v, 4) for k, v in self.components.items()
            },
            "metrics": self.metrics,
            "reason": self.reason,
        }


def mean_score(components: Mapping[str, float | None]) -> float | None:
    """Unweighted mean of the available components; None if none are available."""
    values = [v for v in components.values() if v is not None]
    return sum(values) / len(values) if values else None


def clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


def not_applicable(name: str, reason: str) -> SignalReport:
    return SignalReport(name=name, applicable=False, reason=reason)

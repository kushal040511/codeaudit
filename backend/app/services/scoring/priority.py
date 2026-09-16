"""Which findings get an LLM fix suggestion first: the ones that improve the score most.

Ordering uses each finding's `score_impact` from the scoring rubric; ties go to
the more severe finding, then file and line, so the selection is deterministic.
Findings without an impact (scans scored before the rubric existed) fall back to
severity alone. It never depends on LLM output.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from app.models import Finding, Severity

# Structural issues span several modules; the architecture review covers them.
NOT_FIXABLE_ANALYZERS = frozenset({"architecture"})
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(Severity)}


@dataclass(frozen=True)
class PrioritizedFinding:
    finding: Finding
    priority: float  # score points gained if fixed (0 when unknown)


def top_fixable(findings: Sequence[Finding], limit: int) -> list[PrioritizedFinding]:
    """The `limit` fixable findings that improve the score most."""
    ranked = sorted(
        (f for f in findings if f.analyzer not in NOT_FIXABLE_ANALYZERS),
        key=lambda f: (
            -(f.score_impact or 0.0),
            -_SEVERITY_RANK[f.severity],
            -len(f.corroborated_by or []),
            f.file_path,
            f.start_line,
            f.id,
        ),
    )
    return [PrioritizedFinding(f, f.score_impact or 0.0) for f in ranked[: max(0, limit)]]

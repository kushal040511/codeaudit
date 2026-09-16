"""Deterministic finding priority: which findings are worth an LLM fix suggestion first.

INTERIM: the scoring rubric (rubric.py) is not implemented yet. Once it exists,
replace `priority()` with the rubric's per-finding score impact. The ordering here
must stay deterministic and must never depend on LLM output.
"""

from collections.abc import Sequence
from dataclasses import dataclass

from app.models import Finding, Severity

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 100.0,
    Severity.ERROR: 50.0,
    Severity.WARNING: 15.0,
    Severity.INFO: 3.0,
}
# Security and dependency issues matter more than lint for the same severity.
ANALYZER_WEIGHT = {"semgrep": 1.2, "bandit": 1.1, "dependency": 1.2, "ruff": 0.6}
CORROBORATION_BONUS = 10.0  # per other analyzer that reported the same issue

# Structural issues span several modules; the architecture review covers them.
NOT_FIXABLE_ANALYZERS = frozenset({"architecture"})


@dataclass(frozen=True)
class PrioritizedFinding:
    finding: Finding
    priority: float


def priority(finding: Finding) -> float:
    base = SEVERITY_WEIGHT[finding.severity] * ANALYZER_WEIGHT.get(finding.analyzer, 1.0)
    return round(base + CORROBORATION_BONUS * len(finding.corroborated_by or []), 3)


def top_fixable(findings: Sequence[Finding], limit: int) -> list[PrioritizedFinding]:
    """The `limit` highest-priority findings a single-file patch could address."""
    ranked = [
        PrioritizedFinding(f, priority(f))
        for f in findings
        if f.analyzer not in NOT_FIXABLE_ANALYZERS
    ]
    # Ties: file then line, so the selection is stable across runs.
    ranked.sort(
        key=lambda p: (-p.priority, p.finding.file_path, p.finding.start_line, p.finding.id)
    )
    return ranked[: max(0, limit)]

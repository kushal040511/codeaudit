from dataclasses import dataclass

from app.services.analyzers.base import AnalyzerFinding


@dataclass(frozen=True)
class CategoryScore:
    category: str  # e.g. "security", "architecture", "code_health"
    score: float
    max_score: float
    rationale: list[str]


@dataclass(frozen=True)
class ScoreReport:
    overall: float
    categories: list[CategoryScore]
    rubric_version: str


def score(findings: list[AnalyzerFinding], graph_metrics: dict[str, float]) -> ScoreReport:
    """Deterministic rubric scoring. The score must never depend on LLM output.

    TODO: versioned rubric (weights per category/severity), normalisation by
    codebase size, and validation against a labelled benchmark set.
    """
    raise NotImplementedError

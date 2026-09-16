"""Deterministic, versioned scoring. The score never depends on LLM output.

Rubric v1
---------
Overall score (0-100) = weighted mean of category scores. Categories:

    security       40%  Semgrep and Bandit findings
    dependencies   20%  OSV-Scanner findings
    architecture   20%  structural issues (cycles, layering, god modules, orphans)
    code_health    20%  Ruff findings

A category whose analyzer didn't run is excluded and the remaining weights are
renormalised; the score is then marked `incomplete` and can't be compared with
complete scores.

Category score = 100 * exp(-penalty * ln2 / half_life): each `half_life` points
of penalty halve the score. Penalty:

1. Each finding weighs severity weight x corroboration (1.25 when another
   analyzer reported the same issue) x path factor (0.2 in test files).
2. Within one rule, the i-th heaviest finding counts 1/i^0.75: a pattern repeated
   500 times is worse than once, but not 500 times worse (15,000 test asserts add
   about as much as four real findings). Because the multipliers decrease, removing
   any finding never raises the penalty: every fix has a non-negative impact.
3. Size normalisation: code health divides by sqrt(KLOC) (lint debt grows with
   size); security by cbrt(KLOC), capped at 6, because a vulnerability is an
   absolute risk that a bigger codebase barely dilutes; architecture by
   sqrt(modules / 20); dependencies not at all.

The impact of fixing a set of findings is computed exactly by rescoring without
them, so projections for any selection are consistent with the real score.
"""

import math
import re
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from app.models import Severity

RUBRIC_VERSION = "1.0"


class ScorableFinding(Protocol):
    """What the rubric reads from a finding (ORM rows and plain dataclasses both fit)."""

    @property
    def id(self) -> int: ...
    @property
    def analyzer(self) -> str: ...
    @property
    def rule_id(self) -> str: ...
    @property
    def severity(self) -> Severity: ...
    @property
    def file_path(self) -> str: ...
    @property
    def corroborated_by(self) -> list[str]: ...


@dataclass(frozen=True)
class CategorySpec:
    name: str
    label: str
    weight: float
    analyzers: frozenset[str]
    severity_weights: dict[Severity, float]
    half_life: float
    # "kloc_sqrt" (lint debt grows with size), "kloc_cbrt" (vulnerabilities are absolute
    # risks: size dilutes them only a little, capped), "modules", or "none".
    size_normalized: str


DEFAULT_SEVERITY = {
    Severity.CRITICAL: 10.0,
    Severity.ERROR: 5.0,
    Severity.WARNING: 2.0,
    Severity.INFO: 0.5,
}
# Lint findings are about maintainability, not exploitability.
LINT_SEVERITY = {
    Severity.CRITICAL: 3.0,
    Severity.ERROR: 1.5,
    Severity.WARNING: 0.5,
    Severity.INFO: 0.1,
}

CATEGORIES: tuple[CategorySpec, ...] = (
    CategorySpec(
        "security",
        "Security",
        0.40,
        frozenset({"semgrep", "bandit"}),
        DEFAULT_SEVERITY,
        12.0,
        "kloc_cbrt",
    ),
    CategorySpec(
        "dependencies",
        "Dependencies",
        0.20,
        frozenset({"dependency"}),
        DEFAULT_SEVERITY,
        25.0,
        "none",
    ),
    CategorySpec(
        "architecture",
        "Architecture",
        0.20,
        frozenset({"architecture"}),
        DEFAULT_SEVERITY,
        20.0,
        "modules",
    ),
    CategorySpec(
        "code_health", "Code health", 0.20, frozenset({"ruff"}), LINT_SEVERITY, 25.0, "kloc_sqrt"
    ),
)
CATEGORY_BY_ANALYZER = {analyzer: spec for spec in CATEGORIES for analyzer in spec.analyzers}

CORROBORATION_FACTOR = 1.25
TEST_PATH_FACTOR = 0.2
MODULES_PER_UNIT = 20
RULE_DAMPING_EXPONENT = 0.75
MAX_SECURITY_SIZE_FACTOR = 6.0  # reached at 216 KLOC
GRADES = ((90, "A"), (80, "B"), (70, "C"), (55, "D"), (0, "F"))

_TEST_PATH = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|testing|e2e)(/|$)|(^|/)(test_[^/]*|[^/]*_test\.py|[^/]*\.(test|spec)\.[cm]?[jt]sx?|conftest\.py)$"
)


@dataclass(frozen=True)
class ScoreContext:
    """Inputs besides findings. `analyzers_run` = analyzers that completed successfully."""

    source_loc: int
    module_count: int
    analyzers_run: frozenset[str]
    analyzers_failed: frozenset[str] = frozenset()


@dataclass
class CategoryScore:
    category: str
    label: str
    score: float | None  # None when excluded
    weight: float  # effective weight after renormalisation (0 when excluded)
    penalty: float
    finding_count: int
    excluded_reason: str | None = None
    rationale: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "label": self.label,
            "score": None if self.score is None else round(self.score, 2),
            "weight": round(self.weight, 4),
            "penalty": round(self.penalty, 4),
            "finding_count": self.finding_count,
            "excluded_reason": self.excluded_reason,
            "rationale": self.rationale,
        }


@dataclass
class ScoreReport:
    # Rounded to 2 decimals; category values keep full precision. None when no
    # category could be scored (e.g. every relevant analyzer failed).
    overall: float | None
    grade: str | None
    categories: list[CategoryScore]
    rubric_version: str
    incomplete: bool
    incomplete_reasons: list[str]

    def category(self, name: str) -> CategoryScore:
        return next(c for c in self.categories if c.category == name)


def grade_for(score: float) -> str:
    return next(letter for threshold, letter in GRADES if score >= threshold)


def is_test_path(path: str) -> bool:
    return bool(_TEST_PATH.search(path.lower()))


def finding_weight(finding: ScorableFinding, spec: CategorySpec) -> float:
    weight = spec.severity_weights[finding.severity]
    if finding.corroborated_by:
        weight *= CORROBORATION_FACTOR
    if is_test_path(finding.file_path):
        weight *= TEST_PATH_FACTOR
    return weight


def _size_factor(spec: CategorySpec, context: ScoreContext) -> float:
    kloc = max(1.0, context.source_loc / 1000)
    if spec.size_normalized == "kloc_sqrt":
        return math.sqrt(kloc)
    if spec.size_normalized == "kloc_cbrt":
        return min(MAX_SECURITY_SIZE_FACTOR, float(kloc ** (1 / 3)))
    if spec.size_normalized == "modules":
        return math.sqrt(max(1.0, context.module_count / MODULES_PER_UNIT))
    return 1.0


def _rank_multiplier(rank: int) -> float:
    return float(rank**-RULE_DAMPING_EXPONENT)


def _rule_penalty(weights: list[float]) -> float:
    ranked = sorted(weights, reverse=True)
    return sum(w * _rank_multiplier(rank) for rank, w in enumerate(ranked, start=1))


def score(
    findings: Iterable[ScorableFinding],
    context: ScoreContext,
    exclude_ids: Iterable[int] = (),
) -> ScoreReport:
    excluded = set(exclude_ids)
    by_category: defaultdict[str, defaultdict[str, list[float]]] = defaultdict(
        lambda: defaultdict(list)
    )
    counts: defaultdict[str, int] = defaultdict(int)
    for finding in findings:
        spec = CATEGORY_BY_ANALYZER.get(finding.analyzer)
        if spec is None or finding.id in excluded:
            continue
        by_category[spec.name][f"{finding.analyzer}:{finding.rule_id}"].append(
            finding_weight(finding, spec)
        )
        counts[spec.name] += 1

    categories: list[CategoryScore] = []
    incomplete_reasons: list[str] = []
    for spec in CATEGORIES:
        failed = spec.analyzers & context.analyzers_failed
        ran = spec.analyzers & context.analyzers_run
        if failed or not ran:
            reason = (
                f"{', '.join(sorted(failed))} failed"
                if failed
                else "not applicable to this codebase"
            )
            if failed:
                incomplete_reasons.append(f"{spec.label}: {reason}")
            categories.append(CategoryScore(spec.name, spec.label, None, 0.0, 0.0, 0, reason))
            continue
        rules = by_category[spec.name]
        raw_penalty = sum(_rule_penalty(weights) for weights in rules.values())
        penalty = raw_penalty / _size_factor(spec, context)
        value = 100.0 * math.exp(-penalty * math.log(2) / spec.half_life)
        worst = sorted(rules.items(), key=lambda item: -_rule_penalty(item[1]))[:3]
        categories.append(
            CategoryScore(
                spec.name,
                spec.label,
                value,
                spec.weight,
                penalty,
                counts[spec.name],
                rationale=[
                    f"{rule} ({len(weights)} finding{'s' if len(weights) != 1 else ''})"
                    for rule, weights in worst
                ],
            )
        )

    total_weight = sum(c.weight for c in categories if c.score is not None)
    if total_weight == 0:
        reasons = incomplete_reasons or ["No analyzer results could be scored."]
        return ScoreReport(None, None, categories, RUBRIC_VERSION, True, reasons)
    for category in categories:
        if category.score is not None:
            category.weight = category.weight / total_weight
    overall = round(sum(c.score * c.weight for c in categories if c.score is not None), 2)
    return ScoreReport(
        overall=overall,
        grade=grade_for(overall),
        categories=categories,
        rubric_version=RUBRIC_VERSION,
        incomplete=bool(incomplete_reasons),
        incomplete_reasons=incomplete_reasons,
    )


def _removal_penalties(weights: Sequence[float]) -> list[float]:
    """Rule penalty after removing each element, in O(n log n); input order preserved.

    With weights sorted descending, P = sum(w_i * m(i)). Removing rank r moves every
    later element up one rank: P'_r = P - w_r * m(r) + sum_{i>r} w_i * (m(i-1) - m(i)).
    """
    order = sorted(range(len(weights)), key=lambda i: -weights[i])
    ranked = [weights[i] for i in order]
    total = sum(w * _rank_multiplier(rank) for rank, w in enumerate(ranked, start=1))
    # gain[p]: what the elements after position p gain by moving up one rank
    gain = [0.0] * (len(ranked) + 1)
    for position in range(len(ranked) - 1, 0, -1):
        rank = position + 1
        gain[position] = gain[position + 1] + ranked[position] * (
            _rank_multiplier(rank - 1) - _rank_multiplier(rank)
        )
    result = [0.0] * len(ranked)
    for position, original_index in enumerate(order):
        result[original_index] = (
            total - ranked[position] * _rank_multiplier(position + 1) + gain[position + 1]
        )
    return result


def finding_impacts(findings: Sequence[ScorableFinding], context: ScoreContext) -> dict[int, float]:
    """Overall points gained if each finding alone were fixed (exact)."""
    base = score(findings, context)
    groups: defaultdict[tuple[str, str], list[ScorableFinding]] = defaultdict(list)
    for finding in findings:
        spec = CATEGORY_BY_ANALYZER.get(finding.analyzer)
        if spec is not None:
            groups[(spec.name, f"{finding.analyzer}:{finding.rule_id}")].append(finding)

    specs = {spec.name: spec for spec in CATEGORIES}
    impacts: dict[int, float] = {f.id: 0.0 for f in findings}  # unscored analyzers: 0
    for (category_name, _), members in groups.items():
        category = base.category(category_name)
        if category.score is None:
            impacts.update({f.id: 0.0 for f in members})
            continue
        spec = specs[category_name]
        size = _size_factor(spec, context)
        weights = [finding_weight(f, spec) for f in members]
        other_penalty = category.penalty * size - _rule_penalty(weights)
        for finding, remaining in zip(members, _removal_penalties(weights), strict=True):
            penalty = max(0.0, other_penalty + remaining) / size
            new_value = 100.0 * math.exp(-penalty * math.log(2) / spec.half_life)
            gain = (new_value - category.score) * category.weight
            impacts[finding.id] = round(max(0.0, gain), 4)
    return impacts

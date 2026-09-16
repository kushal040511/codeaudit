import random
from dataclasses import dataclass, field

import pytest

from app.models import Severity
from app.services.scoring.rubric import (
    RUBRIC_VERSION,
    ScoreContext,
    finding_impacts,
    grade_for,
    is_test_path,
    score,
)

ALL = frozenset({"semgrep", "bandit", "ruff", "dependency", "architecture"})


@dataclass(frozen=True)
class F:
    id: int
    analyzer: str = "semgrep"
    rule_id: str = "rule"
    severity: Severity = Severity.ERROR
    file_path: str = "app/views.py"
    corroborated_by: list[str] = field(default_factory=list)


def ctx(
    loc: int = 5000,
    modules: int = 40,
    run: frozenset[str] = ALL,
    failed: frozenset[str] = frozenset(),
) -> ScoreContext:
    return ScoreContext(
        source_loc=loc, module_count=modules, analyzers_run=run, analyzers_failed=failed
    )


def test_no_findings_is_perfect() -> None:
    report = score([], ctx())

    assert (report.overall, report.grade, report.incomplete) == (100.0, "A", False)
    assert report.rubric_version == RUBRIC_VERSION
    assert [c.category for c in report.categories] == [
        "security",
        "dependencies",
        "architecture",
        "code_health",
    ]
    assert sum(c.weight for c in report.categories) == pytest.approx(1.0)


def test_random_property_fixing_never_lowers_and_impacts_are_exact() -> None:
    rng = random.Random(7)
    analyzers = ["semgrep", "bandit", "ruff", "dependency", "architecture", "unknown-tool"]
    for trial in range(30):
        findings = [
            F(
                id=i,
                analyzer=rng.choice(analyzers),
                rule_id=rng.choice(["a", "b", "c"]),
                severity=rng.choice(list(Severity)),
                file_path=rng.choice(["app/x.py", "tests/test_x.py", "web/app.ts"]),
                corroborated_by=rng.choice([[], ["bandit"]]),
            )
            for i in range(rng.randint(0, 40))
        ]
        context = ctx(loc=rng.randint(0, 50_000), modules=rng.randint(0, 300))
        base = score(findings, context)
        impacts = finding_impacts(findings, context)
        for finding in findings:
            fixed = score(findings, context, exclude_ids=[finding.id])
            assert base.overall is not None and fixed.overall is not None
            assert fixed.overall >= base.overall - 1e-9, (trial, finding)
            assert impacts[finding.id] >= 0
            # the stored impact matches a full rescore (up to rounding of the overall)
            assert abs((fixed.overall - base.overall) - impacts[finding.id]) < 0.011, (
                trial,
                finding,
            )


def test_severity_corroboration_and_test_paths_order_impacts() -> None:
    findings = [
        F(1, rule_id="r1", severity=Severity.CRITICAL),
        F(2, rule_id="r2", severity=Severity.ERROR),
        F(3, rule_id="r3", severity=Severity.WARNING),
        F(4, rule_id="r4", severity=Severity.INFO),
        F(5, rule_id="r5", severity=Severity.ERROR, corroborated_by=["bandit"]),
        F(6, rule_id="r6", severity=Severity.ERROR, file_path="tests/test_views.py"),
    ]
    impacts = finding_impacts(findings, ctx())

    assert impacts[1] > impacts[5] > impacts[2] > impacts[3] > impacts[6] > impacts[4] > 0


def test_repeated_rule_is_dampened() -> None:
    once = score([F(0, severity=Severity.WARNING)], ctx())
    many_same_rule = score([F(i, severity=Severity.WARNING) for i in range(100)], ctx())
    many_distinct = score(
        [F(i, rule_id=f"r{i}", severity=Severity.WARNING) for i in range(100)], ctx()
    )

    assert once.overall > many_same_rule.overall > many_distinct.overall  # type: ignore[operator]
    # 100 repeats cost far less than 100 times one occurrence
    assert many_same_rule.category("security").penalty < 100 * once.category("security").penalty / 7


def test_larger_codebases_tolerate_more_findings() -> None:
    findings = [F(i, rule_id=f"r{i}") for i in range(5)]

    small, large = score(findings, ctx(loc=2_000)), score(findings, ctx(loc=300_000))

    assert small.overall < large.overall  # type: ignore[operator]
    # 100x the code barely dilutes 5 security errors (cube root, capped)
    assert large.category("security").score < 80  # type: ignore[operator]
    assert large.overall < 92  # type: ignore[operator]
    huge = score(findings, ctx(loc=5_000_000))
    assert huge.category("security").score == large.category("security").score  # capped
    # dependencies aren't size-normalised
    dep = [F(1, analyzer="dependency", severity=Severity.CRITICAL)]
    assert (
        score(dep, ctx(loc=1_000)).category("dependencies").score
        == score(dep, ctx(loc=500_000)).category("dependencies").score
    )


def test_failed_analyzer_makes_score_incomplete_and_renormalises() -> None:
    findings = [
        F(1, analyzer="dependency", severity=Severity.CRITICAL),
        F(2, severity=Severity.ERROR),
    ]

    report = score(findings, ctx(run=ALL - {"dependency"}, failed=frozenset({"dependency"})))

    deps = report.category("dependencies")
    assert (deps.score, deps.weight, deps.excluded_reason) == (None, 0.0, "dependency failed")
    assert report.incomplete and report.incomplete_reasons == ["Dependencies: dependency failed"]
    assert sum(c.weight for c in report.categories) == pytest.approx(1.0)
    assert report.category("security").weight == pytest.approx(0.5)


def test_not_applicable_category_is_excluded_but_complete() -> None:
    js_only = ctx(run=frozenset({"semgrep", "dependency", "architecture"}))

    report = score([F(1)], js_only)

    assert report.category("code_health").excluded_reason == "not applicable to this codebase"
    assert not report.incomplete
    # bandit didn't run but semgrep did: security is scored
    assert report.category("security").score is not None


def test_nothing_scoreable() -> None:
    report = score([F(1)], ctx(run=frozenset(), failed=ALL))

    assert (report.overall, report.grade, report.incomplete) == (None, None, True)
    assert finding_impacts([F(1)], ctx(run=frozenset(), failed=ALL)) == {1: 0.0}


@pytest.mark.parametrize(
    ("value", "grade"),
    [(100, "A"), (90, "A"), (89.99, "B"), (70, "C"), (55, "D"), (54.9, "F"), (0, "F")],
)
def test_grades(value: float, grade: str) -> None:
    assert grade_for(value) == grade


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("tests/test_api.py", True),
        ("pkg/tests/helpers.py", True),
        ("src/__tests__/App.tsx", True),
        ("web/app.spec.ts", True),
        ("api/views_test.py", True),
        ("conftest.py", True),
        ("app/testimonials.py", False),
        ("app/latest.py", False),
    ],
)
def test_test_path_detection(path: str, expected: bool) -> None:
    assert is_test_path(path) is expected


def test_closed_form_removal_matches_brute_force() -> None:
    from app.services.scoring.rubric import _removal_penalties, _rule_penalty

    rng = random.Random(3)
    for n in (1, 2, 3, 10, 60):
        weights = [rng.choice([0.1, 0.5, 2.0, 5.0, 10.0]) for _ in range(n)]
        brute = [_rule_penalty(weights[:i] + weights[i + 1 :]) for i in range(n)]
        assert _removal_penalties(weights) == pytest.approx(brute, abs=1e-9)

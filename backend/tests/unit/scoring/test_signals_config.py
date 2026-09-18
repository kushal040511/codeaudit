"""Rubric 1.1.0: experimental signals are opt-in and add one deduction line each."""

import math

import pytest

from app.models import Severity
from app.services.scoring.rubric import (
    CATEGORIES,
    RubricConfig,
    ScoreContext,
    score,
)
from app.services.scoring.service import ScorableRow

ALL = frozenset({"semgrep", "bandit", "ruff", "dependency", "architecture"})


def findings() -> list[ScorableRow]:
    return [
        ScorableRow(1, "semgrep", "sqli", Severity.ERROR, "app/db.py", []),
        ScorableRow(2, "ruff", "F401", Severity.INFO, "app/x.py", []),
        ScorableRow(3, "dependency", "CVE-1", Severity.ERROR, "requirements.txt", []),
        ScorableRow(4, "architecture", "architecture/orphan_module", Severity.INFO, "a.py", []),
    ]


def signal(value: float | None, applicable: bool = True, **components: float | None) -> dict:
    return {"applicable": applicable, "score": value, "components": components, "reason": None}


SIGNALS = {
    "error_handling": signal(0.5),
    "test_quality": signal(0.0),
    "git_history": signal(0.8),
    "ci_quality": signal(None, applicable=False),
    "dep_health": signal(
        0.6, direct_count=1.0, freshness=0.5, transitive=None, trivial=0.9, unused=0.5, phantom=1.0
    ),
}


def context(signals: dict | None = None) -> ScoreContext:
    return ScoreContext(5000, 40, ALL, signals=signals if signals is not None else SIGNALS)


def test_default_config_ignores_collected_signals() -> None:
    with_signals = score(findings(), context())
    without = score(findings(), context({}))
    assert with_signals.overall == without.overall
    assert with_signals.config == "base"
    assert all(c.deductions == [] for c in with_signals.categories)


def test_enabled_signal_adds_half_life_scaled_penalty() -> None:
    base = score(findings(), context())
    report = score(
        findings(), context(), config=RubricConfig(signals=frozenset({"error_handling"}))
    )
    health, base_health = report.category("code_health"), base.category("code_health")
    spec = next(s for s in CATEGORIES if s.name == "code_health")
    assert health.penalty == pytest.approx(base_health.penalty + spec.half_life * 0.5)
    # Halfway signal on top of the findings: exactly half a half-life more penalty.
    assert health.score == pytest.approx(base_health.score * 2**-0.5)
    [line] = health.deductions
    assert line["signal"] == "error_handling"
    assert line["signal_score"] == 0.5
    assert line["points"] == pytest.approx(round(base_health.score - health.score, 2))
    assert report.config == "error_handling"


def test_signal_at_zero_halves_the_category() -> None:
    base = score(findings(), context()).category("code_health").score
    halved = score(
        findings(), context(), config=RubricConfig(signals=frozenset({"test_quality"}))
    ).category("code_health")
    assert halved.score == pytest.approx(base / 2)


def test_inapplicable_signal_is_not_a_penalty_and_says_why() -> None:
    base = score(findings(), context())
    report = score(findings(), context(), config=RubricConfig(signals=frozenset({"ci_quality"})))
    assert report.overall == base.overall
    [line] = report.category("architecture").deductions
    assert line["signal"] is None and line["points"] == 0.0
    assert "not applicable" in line["label"]


def test_dep_health_splits_supply_chain_and_hygiene() -> None:
    config = RubricConfig(signals=frozenset({"dep_health"}))
    report = score(findings(), context(), config=config)
    [supply] = report.category("dependencies").deductions
    [hygiene] = report.category("architecture").deductions
    assert supply["signal_score"] == pytest.approx((1.0 + 0.5 + 0.9) / 3)  # transitive None
    assert hygiene["signal_score"] == pytest.approx(0.75)
    to_security = score(
        findings(),
        context(),
        config=RubricConfig(signals=frozenset({"dep_health"}), dep_health_target="security"),
    )
    assert to_security.category("security").deductions[0]["signal"] == "dep_health"
    assert to_security.category("dependencies").deductions == []


def test_process_dimension_collects_git_and_ci() -> None:
    config = RubricConfig(signals=frozenset({"git_history", "ci_quality"}), process_dimension=True)
    report = score(findings(), context(), config=config)
    process = report.category("process")
    assert process.score == pytest.approx(100 * 2**-0.2)  # git 0.8, CI not applicable
    assert report.category("architecture").deductions == []
    assert sum(c.weight for c in report.categories if c.score is not None) == pytest.approx(1.0)
    assert report.config == "ci_quality,git_history,process-dimension"


def test_process_dimension_excluded_when_no_signal_applies() -> None:
    signals = {"git_history": signal(None, applicable=False)}
    config = RubricConfig(signals=frozenset({"git_history"}), process_dimension=True)
    report = score(findings(), context(signals), config=config)
    assert report.category("process").score is None
    assert report.overall == score(findings(), context(signals)).overall


def test_code_health_scored_from_signals_when_ruff_did_not_run() -> None:
    js_only = ScoreContext(
        5000, 40, frozenset({"semgrep", "dependency", "architecture"}), signals=SIGNALS
    )
    assert score([], js_only).category("code_health").score is None
    report = score([], js_only, config=RubricConfig(signals=frozenset({"error_handling"})))
    assert report.category("code_health").score == pytest.approx(
        100 * math.exp(-12.5 * math.log(2) / 25)
    )

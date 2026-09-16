"""Calibration benchmark: fixture repositories must score in the expected order.

These are the labelled cases the rubric is validated against. Changing weights
that break this ordering means the rubric no longer matches expert judgement.
"""

from pathlib import Path

import pytest

from app.services.analyzers.architecture import ArchitectureAnalyzer
from app.services.analyzers.bandit import BanditAnalyzer
from app.services.analyzers.dedup import deduplicate
from app.services.analyzers.dependency import DependencyAnalyzer
from app.services.analyzers.ruff import RuffAnalyzer
from app.services.analyzers.semgrep import SemgrepAnalyzer
from app.services.graph.analysis import analyze_architecture
from app.services.languages import count_source_lines
from app.services.scoring.rubric import ScoreContext, ScoreReport, score
from app.services.scoring.service import ScorableRow

FIXTURES = Path(__file__).parents[2] / "fixtures"
ALL = frozenset({"semgrep", "bandit", "ruff", "dependency", "architecture"})


def score_repo(root: Path, extra_findings: list = ()) -> ScoreReport:  # type: ignore[assignment,type-arg]
    report = analyze_architecture(root)
    architecture = ArchitectureAnalyzer().parse(
        __import__("json").dumps(
            {
                "issues": __import__(
                    "app.services.analyzers.architecture", fromlist=["issue_payload"]
                ).issue_payload(report)
            }
        )
    )
    findings = deduplicate([*architecture, *extra_findings])
    rows = [
        ScorableRow(i, f.analyzer, f.rule_id, f.severity, f.file_path, list(f.corroborated_by))
        for i, f in enumerate(findings)
    ]
    context = ScoreContext(count_source_lines(root), report.summary["node_count"], ALL)
    return score(rows, context)


@pytest.fixture(scope="module")
def polyglot_findings() -> list:  # type: ignore[type-arg]
    return [
        *SemgrepAnalyzer().parse((FIXTURES / "semgrep_polyglot_output.json").read_text()),
        *BanditAnalyzer().parse((FIXTURES / "bandit_output.json").read_text()),
        *RuffAnalyzer().parse((FIXTURES / "ruff_output.json").read_text()),
        *DependencyAnalyzer().parse((FIXTURES / "osv_scanner_output.json").read_text()),
    ]


def test_benchmark_ordering(polyglot_findings: list) -> None:  # type: ignore[type-arg]
    clean = score_repo(FIXTURES / "architecture" / "clean_layered")
    layer_skip = score_repo(FIXTURES / "architecture" / "layer_violation")
    cycle = score_repo(FIXTURES / "architecture" / "cycle_repo")
    vulnerable = score_repo(FIXTURES / "polyglot_app", polyglot_findings)

    scores = {
        name: r.overall
        for name, r in [
            ("clean", clean),
            ("layer_skip", layer_skip),
            ("cycle", cycle),
            ("vulnerable", vulnerable),
        ]
    }
    assert clean.overall == 100.0 and clean.grade == "A"
    # A single warning-level layering skip is a small deduction; a runtime import
    # cycle (error) costs more; an app full of injection flaws and CVEs fails.
    assert scores["clean"] > scores["layer_skip"] > scores["cycle"] > scores["vulnerable"], scores  # type: ignore[operator]
    assert layer_skip.grade == "A" and cycle.grade in {"A", "B"}
    assert vulnerable.grade == "F"
    assert vulnerable.category("security").score < 30  # type: ignore[operator]
    assert vulnerable.category("dependencies").score < 30  # type: ignore[operator]
    assert vulnerable.category("code_health").score > 80  # type: ignore[operator]

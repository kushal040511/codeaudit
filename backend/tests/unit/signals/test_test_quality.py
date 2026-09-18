"""Test quality signal: exact detections on small fixture repositories."""

import json
import time
from pathlib import Path
from typing import Any

import pytest

from app.models import Severity
from app.services.analyzers.base import ScanContext
from app.services.analyzers.signals import SignalReport
from app.services.analyzers.test_quality import (
    COVERAGE_UNAVAILABLE,
    TestQualityAnalyzer,
    build_report,
    collect,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "signals"


def run_collect(name: str) -> dict[str, Any]:
    return collect(FIXTURES / name, time.monotonic() + 60)


def test_counts_tests_and_assertions_per_function() -> None:
    data = run_collect("tests_assertion_free")

    counts = {(t["file"], t["name"]): t["assertions"] for t in data["tests"]}
    assert counts == {
        ("tests/calc.test.js", "adds"): 1,
        ("tests/calc.test.js", "runs without checking"): 0,
        ("tests/calc.test.js", "snapshot"): 2,
        ("tests/calc.test.js", "each %i"): 1,
        ("tests/calc.test.js", "helper"): 1,  # expectSum(...) helper heuristic
        ("tests/test_calc.py", "test_add"): 2,
        ("tests/test_calc.py", "test_add_runs"): 0,
        ("tests/test_calc.py", "test_uses_helper"): 1,  # assert_positive(...) helper
        ("tests/test_calc.py", "test_divide_by_zero"): 1,  # pytest.raises
        ("tests/test_calc.py", "test_param_smoke"): 0,
        ("tests/test_calc.py", "test_mock_called"): 1,  # m.assert_called_once_with
        ("tests/test_calc.py", "TestCalc.test_method_no_assert"): 0,
        ("tests/test_calc.py", "CalcCase.test_equal"): 2,
        ("tests/integration/test_api.py", "test_health"): 1,
    }
    assert data["test_functions"] == 14
    assert data["assertions"] == 13
    assert data["type_counts"] == {"unit": 2, "integration": 1, "e2e": 0}
    assert (data["source_files"], data["test_files"]) == (2, 3)


def test_flags_assertion_free_tests_with_location() -> None:
    data = run_collect("tests_assertion_free")

    flagged = [(t["file"], t["line"], t["name"]) for t in data["zero_assertion_tests"]]
    assert flagged == [
        ("tests/calc.test.js", 8, "runs without checking"),
        ("tests/test_calc.py", 18, "test_add_runs"),
        ("tests/test_calc.py", 32, "test_param_smoke"),
        ("tests/test_calc.py", 43, "TestCalc.test_method_no_assert"),
    ]

    findings = TestQualityAnalyzer().parse(
        json.dumps({"zero_assertion_tests": data["zero_assertion_tests"]})
    )
    assert [(f.file_path, f.start_line, f.end_line) for f in findings] == [
        ("tests/calc.test.js", 8, 10),
        ("tests/test_calc.py", 18, 19),
        ("tests/test_calc.py", 32, 33),
        ("tests/test_calc.py", 43, 45),
    ]
    assert {f.rule_id for f in findings} == {"assertion-free-test"}
    assert {f.severity for f in findings} == {Severity.INFO}
    assert len({f.category for f in findings}) == 4  # never merged with each other


def test_components_without_coverage_report() -> None:
    report = build_report(run_collect("tests_assertion_free"))

    assert report.applicable
    assert report.components == {
        "test_presence": 1.0,
        "assertion_density": pytest.approx(13 / 14 / 2),
        "assertion_free": pytest.approx(1 - 4 / 14),
        "type_mix": 1.0,
        "coverage": None,
    }
    assert report.metrics["coverage_pct"] is None
    assert report.metrics["coverage_status"] == COVERAGE_UNAVAILABLE
    assert report.metrics["coverage_status"].startswith("unavailable")
    assert report.metrics["coverage_configured"] is False


def test_reads_committed_coverage_reports() -> None:
    data = run_collect("tests_with_coverage")
    report = build_report(data)

    assert data["coverage"]["reports"] == [
        {"path": "coverage.xml", "kind": "cobertura", "covered": 30, "total": 40, "pct": 75.0},
        {
            "path": "frontend/coverage/lcov.info",
            "kind": "lcov",
            "covered": 14,
            "total": 20,
            "pct": 70.0,
        },
    ]
    assert data["coverage"]["pct"] == 73.33  # (30 + 14) / (40 + 20)
    assert data["coverage"]["notes"] == [".coverage: coverage.py SQLite data file, not read"]
    assert report.components["coverage"] == pytest.approx(0.7333)
    assert report.metrics["coverage_configured"] is True
    assert report.metrics["coverage_config"] == [".coveragerc"]
    assert data["type_counts"] == {"unit": 1, "integration": 0, "e2e": 1}
    assert data["zero_assertion_tests"] == []


def test_istanbul_summary_wins_in_its_directory(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text("export const a = 1;\n")
    coverage = tmp_path / "coverage"
    coverage.mkdir()
    (coverage / "coverage-summary.json").write_text(
        '{"total": {"lines": {"total": 50, "covered": 45, "skipped": 0, "pct": 90}}}'
    )
    (coverage / "lcov.info").write_text("LF:10\nLH:1\n")

    data = collect(tmp_path, time.monotonic() + 60)

    assert [r["kind"] for r in data["coverage"]["reports"]] == ["istanbul-summary"]
    assert data["coverage"]["pct"] == 90.0


def test_no_tests_scores_zero() -> None:
    report = build_report(run_collect("tests_none"))

    assert report.applicable
    assert report.score == 0.0
    assert report.components == {
        "test_presence": 0.0,
        "assertion_density": None,
        "assertion_free": None,
        "type_mix": None,
        "coverage": None,
    }
    assert report.metrics["coverage_status"] == COVERAGE_UNAVAILABLE


def test_no_source_code_is_not_applicable(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("docs only\n")

    report = build_report(collect(tmp_path, time.monotonic() + 60))

    assert not report.applicable
    assert report.score is None


def test_test_presence_formula() -> None:
    data = {**run_collect("tests_assertion_free"), "source_loc": 200, "test_loc": 30}

    report = build_report(data)

    assert report.components["test_presence"] == pytest.approx(30 / (0.3 * 200))


def test_analyzer_runs_the_collector_in_a_child_process(tmp_path: Path) -> None:
    analyzer = TestQualityAnalyzer()
    context = ScanContext(scan_id="s", work_dir=tmp_path, languages=[])

    result = analyzer.run(FIXTURES / "tests_assertion_free", context)

    assert analyzer.experimental and analyzer.phase == 1
    assert result.success
    assert isinstance(result.artifact, SignalReport)
    assert result.artifact.name == "test_quality"
    assert result.artifact.metrics["test_functions"] == 14
    assert sorted((f.file_path, f.start_line) for f in result.findings) == [
        ("tests/calc.test.js", 8),
        ("tests/test_calc.py", 18),
        ("tests/test_calc.py", 32),
        ("tests/test_calc.py", 43),
    ]
    assert list(tmp_path.iterdir()) == []  # hand-off files removed

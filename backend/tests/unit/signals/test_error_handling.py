import json
import time
from pathlib import Path
from typing import Any

import pytest

from app.models import Severity
from app.services.analyzers.base import ScanContext
from app.services.analyzers.error_handling import (
    ErrorHandlingAnalyzer,
    build_report,
    collect,
)
from app.services.analyzers.signals import SignalReport

FIXTURES = Path(__file__).parents[2] / "fixtures" / "signals"
BAD = FIXTURES / "bad_error_handling"
GOOD = FIXTURES / "good_error_handling"

EXPECTED_BAD = [
    ("bare-except", "app/service.py", 14),
    ("swallowed-broad-except", "app/service.py", 21),
    ("swallowed-broad-except", "app/service.py", 28),
    ("exception-ignored", "app/service.py", 35),
    ("exception-ignored", "app/service.py", 42),
    ("broad-except-large-block", "app/service.py", 74),
    ("await-io-outside-try", "web/api.ts", 4),
    ("unhandled-promise", "web/api.ts", 13),
    ("empty-catch", "web/client.js", 7),
    ("empty-catch", "web/client.js", 13),
    ("catch-only-logs-to-console", "web/client.js", 21),
    ("unhandled-promise", "web/client.js", 27),
    ("await-io-outside-try", "web/client.js", 31),
]


def run_collect(repo: Path) -> dict[str, Any]:
    return collect(repo, time.monotonic() + 60)


def test_detects_exactly_the_expected_issues() -> None:
    collected = run_collect(BAD)

    assert [(f["rule"], f["path"], f["line"]) for f in collected["findings"]] == EXPECTED_BAD
    # The test file's bare except and open() are excluded entirely.
    assert collected["files_parsed"] == 3
    assert collected["languages"] == {"javascript": 1, "python": 1, "typescript": 1}


def test_counts_handlers_io_and_promise_sites() -> None:
    collected = run_collect(BAD)

    # 11 Python except clauses + 4 JS catch clauses.
    assert collected["handlers"] == 15
    # py: requests.get, open, subprocess.run (wrapped)
    # js: fetch x3 (one wrapped by .catch), fs.promises.readFile (wrapped by try), fs.readFileSync
    # ts: axios.get, new XMLHttpRequest, db.query
    assert collected["io_sites"] == 11
    assert collected["io_wrapped"] == 3
    # .then chains: 27, 38, 44 (client.js), 13 (api.ts); awaited I/O: 31, 49, api.ts:4
    assert collected["promise_sites"] == 7


def test_bad_repo_components() -> None:
    report = build_report(run_collect(BAD)).as_dict()

    assert report["applicable"] is True
    assert report["components"] == {
        "swallow_rate": round(1 - 8 / 15, 4),
        "io_wrapped_ratio": round(3 / 11, 4),
        "promise_handling": round(1 - 4 / 7, 4),
    }
    assert report["score"] == round(((1 - 8 / 15) + 3 / 11 + (1 - 4 / 7)) / 3, 4)
    assert report["metrics"]["rule_counts"] == {
        "bare-except": 1,
        "swallowed-broad-except": 2,
        "exception-ignored": 2,
        "broad-except-large-block": 1,
        "empty-catch": 2,
        "catch-only-logs-to-console": 1,
        "unhandled-promise": 2,
        "await-io-outside-try": 2,
    }


def test_good_repo_has_no_findings_and_full_score() -> None:
    collected = run_collect(GOOD)

    assert collected["findings"] == []
    assert (collected["handlers"], collected["io_sites"], collected["io_wrapped"]) == (4, 4, 4)
    assert collected["promise_sites"] == 2
    report = build_report(collected)
    assert report.components == {
        "swallow_rate": 1.0,
        "io_wrapped_ratio": 1.0,
        "promise_handling": 1.0,
    }
    assert report.score == 1.0


def test_python_only_repo_has_no_promise_component(tmp_path: Path) -> None:
    (tmp_path / "mod.py").write_text("def f():\n    return 1\n")

    report = build_report(run_collect(tmp_path))

    assert report.applicable is True
    assert report.components == {
        "swallow_rate": None,
        "io_wrapped_ratio": None,
        "promise_handling": None,
    }
    assert report.score is None
    assert report.reason == "no exception handlers, I/O calls or promise chains found"


def test_not_applicable_without_source_files(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# nothing to see\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("try:\n    pass\nexcept:\n    pass\n")

    report = build_report(run_collect(tmp_path))

    assert report.applicable is False
    assert report.reason == "no non-test Python, JavaScript or TypeScript source files"
    assert report.score is None


def test_parse_maps_findings_with_unique_categories() -> None:
    raw = json.dumps(run_collect(BAD))

    findings = ErrorHandlingAnalyzer().parse(raw)

    assert len(findings) == len(EXPECTED_BAD)
    first = findings[0]
    assert first.analyzer == "error_handling"
    assert first.rule_id == "error_handling/bare-except"
    assert first.severity is Severity.WARNING
    assert first.category == "error_handling:bare-except:app/service.py:14"
    assert first.code_snippet == "except:  # bare-except"
    severities = {f.rule_id.split("/")[1]: f.severity for f in findings}
    assert severities["exception-ignored"] is Severity.INFO
    assert severities["empty-catch"] is Severity.WARNING
    assert severities["await-io-outside-try"] is Severity.INFO
    assert len({f.category for f in findings}) == len(findings)


def test_analyzer_run_uses_a_child_process(tmp_path: Path) -> None:
    analyzer = ErrorHandlingAnalyzer()
    context = ScanContext(scan_id="s", work_dir=tmp_path, languages=[])

    result = analyzer.run(BAD, context)

    assert result.success is True
    assert analyzer.experimental is True and analyzer.phase == 1
    assert [(f.rule_id.split("/")[1], f.file_path, f.start_line) for f in result.findings] == [
        (rule, path, line) for rule, path, line in EXPECTED_BAD
    ]
    assert isinstance(result.artifact, SignalReport)
    assert result.artifact.components["io_wrapped_ratio"] == pytest.approx(3 / 11)
    assert list(tmp_path.iterdir()) == []  # hand-off files removed

import json
from pathlib import Path

import pytest

from app.models import Severity
from app.services.analyzers.ruff import RuffAnalyzer, normalize_severity
from app.services.analyzers.sandbox import AnalyzerOutputError

# Real `ruff check --output-format json` output from scanning fixtures/polyglot_app.
RUFF_OUTPUT = Path(__file__).parents[1] / "fixtures" / "ruff_output.json"


def test_maps_real_ruff_output() -> None:
    findings = RuffAnalyzer().parse(RUFF_OUTPUT.read_text())

    assert [
        (f.rule_id, f.file_path, f.start_line, f.end_line, f.severity, f.category) for f in findings
    ] == [
        ("B006", "api/app.py", 53, 53, Severity.WARNING, "code-quality:B006"),
        ("E722", "api/app.py", 62, 62, Severity.WARNING, "code-quality:E722"),
    ]
    assert findings[0].message == "Do not use mutable data structures for argument defaults"
    assert findings[0].raw["url"] == "https://docs.astral.sh/ruff/rules/mutable-argument-default"


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (None, Severity.ERROR),  # syntax error
        ("E999", Severity.ERROR),
        ("F821", Severity.ERROR),  # undefined name
        ("F501", Severity.ERROR),  # invalid % format
        ("F706", Severity.ERROR),  # return outside function
        ("F632", Severity.ERROR),  # `is` with a literal
        ("PLE0101", Severity.ERROR),
        ("E722", Severity.WARNING),
        ("F811", Severity.WARNING),
        ("F601", Severity.WARNING),
        ("B006", Severity.WARNING),
        ("F401", Severity.INFO),  # unused import
        ("F841", Severity.INFO),  # unused variable
        ("E711", Severity.INFO),
        ("C901", Severity.INFO),
        ("E402", Severity.INFO),
    ],
)
def test_severity_normalization(code: str | None, expected: Severity) -> None:
    assert normalize_severity(code) is expected


def test_syntax_error_without_code() -> None:
    raw = json.dumps(
        [
            {
                "code": None,
                "filename": "/src/broken.py",
                "location": {"row": 4, "column": 1},
                "end_location": {"row": 4, "column": 5},
                "message": "SyntaxError: Expected an expression",
            },
            {"code": "F401"},  # malformed: skipped
        ]
    )

    [finding] = RuffAnalyzer().parse(raw)

    assert (finding.rule_id, finding.file_path, finding.severity) == (
        "syntax-error",
        "broken.py",
        Severity.ERROR,
    )


@pytest.mark.parametrize("raw", ["", "{}", "nope"])
def test_invalid_output_raises(raw: str) -> None:
    with pytest.raises(AnalyzerOutputError):
        RuffAnalyzer().parse(raw)

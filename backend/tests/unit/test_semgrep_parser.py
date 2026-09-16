import json
from pathlib import Path
from typing import Any

import pytest

from app.models import Severity
from app.services.analyzers.base import AnalyzerFinding
from app.services.analyzers.semgrep import SemgrepError, map_severity, parse_semgrep_output

FIXTURES = Path(__file__).parents[1] / "fixtures"
# Real `semgrep --json` output from scanning fixtures/vulnerable_flask_app in the sandbox.
SEMGREP_OUTPUT = FIXTURES / "semgrep_output.json"
SOURCE_ROOT = FIXTURES / "vulnerable_flask_app"


@pytest.fixture
def payload() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(SEMGREP_OUTPUT.read_text())
    return data


def test_maps_real_semgrep_output_to_findings(payload: dict[str, Any]) -> None:
    findings = parse_semgrep_output(payload, source_root=SOURCE_ROOT)

    assert len(findings) == 5
    first_raw = payload["results"][0]
    assert findings[0] == AnalyzerFinding(
        analyzer="semgrep",
        # "rules." prefix from the local rules mount is stripped
        rule_id="python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_SECRET_KEY",
        severity=Severity.ERROR,
        file_path="app.py",
        start_line=13,
        end_line=13,
        message=first_raw["extra"]["message"].strip(),
        # semgrep CE returns "requires login" for extra.lines; read from source instead
        code_snippet='app.config["SECRET_KEY"] = "dev-secret-key-do-not-use-in-prod"',
        raw=first_raw,
    )


def test_sql_injection_findings(payload: dict[str, Any]) -> None:
    findings = parse_semgrep_output(payload, source_root=SOURCE_ROOT)

    sqli = [f for f in findings if f.rule_id.endswith("tainted-sql-string")]
    assert [(f.start_line, f.severity) for f in sqli] == [
        (26, Severity.ERROR),
        (33, Severity.ERROR),
    ]
    assert sqli[0].code_snippet is not None and "cursor.execute(" in sqli[0].code_snippet
    assert sorted(f.severity for f in findings).count(Severity.WARNING) == 2


def test_without_source_root_snippet_is_none(payload: dict[str, Any]) -> None:
    findings = parse_semgrep_output(payload)

    assert all(f.code_snippet is None for f in findings)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("INFO", Severity.INFO),
        ("WARNING", Severity.WARNING),
        ("ERROR", Severity.ERROR),
        ("CRITICAL", Severity.CRITICAL),
        ("HIGH", Severity.ERROR),
        ("medium", Severity.WARNING),
        ("LOW", Severity.INFO),
        ("something-new", Severity.INFO),
        (None, Severity.INFO),
    ],
)
def test_severity_mapping(raw: object, expected: Severity) -> None:
    assert map_severity(raw) is expected


def test_prefers_semgrep_lines_dedupes_and_strips_nul() -> None:
    result = {
        "check_id": "rules.js.eval",
        "path": "./web/app.js",
        "start": {"line": 3, "col": 1},
        "end": {"line": 4, "col": 9},
        "extra": {"severity": "WARNING", "message": " eval\x00 is bad ", "lines": "eval(x)\n"},
    }
    findings = parse_semgrep_output({"results": [result, dict(result), {"bogus": True}]})

    assert len(findings) == 1
    finding = findings[0]
    assert (finding.rule_id, finding.file_path, finding.start_line, finding.end_line) == (
        "js.eval",
        "web/app.js",
        3,
        4,
    )
    assert finding.message == "eval is bad"
    assert finding.code_snippet == "eval(x)\n"


def test_missing_results_list_raises() -> None:
    with pytest.raises(SemgrepError):
        parse_semgrep_output({"errors": []})

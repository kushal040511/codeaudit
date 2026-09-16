import json
from pathlib import Path
from typing import Any

import pytest

from app.models import Severity
from app.services.analyzers.base import FindingData
from app.services.analyzers.sandbox import AnalyzerOutputError
from app.services.analyzers.semgrep import (
    SemgrepAnalyzer,
    map_severity,
    parse_semgrep_output,
    semgrep_warnings,
)

FIXTURES = Path(__file__).parents[1] / "fixtures"
# Real `semgrep --json` output from scanning fixtures/vulnerable_flask_app in the sandbox.
SEMGREP_OUTPUT = FIXTURES / "semgrep_output.json"
# Real output from scanning fixtures/polyglot_app (Python + JavaScript).
POLYGLOT_OUTPUT = FIXTURES / "semgrep_polyglot_output.json"


@pytest.fixture
def payload() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(SEMGREP_OUTPUT.read_text())
    return data


def test_maps_real_semgrep_output_to_findings(payload: dict[str, Any]) -> None:
    findings = parse_semgrep_output(payload)

    assert len(findings) == 5
    first_raw = payload["results"][0]
    assert findings[0] == FindingData(
        analyzer="semgrep",
        # "rules." prefix from the local rules mount is stripped
        rule_id="python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_SECRET_KEY",
        severity=Severity.ERROR,
        file_path="app.py",
        start_line=13,
        end_line=13,
        message=first_raw["extra"]["message"].strip(),
        # semgrep CE returns "requires login" for extra.lines; the pipeline reads the source
        code_snippet=None,
        category="hardcoded-secret",
        cwe_ids=(489,),
        raw=first_raw,
    )


def test_sql_injection_findings(payload: dict[str, Any]) -> None:
    findings = parse_semgrep_output(payload)

    sqli = [f for f in findings if f.rule_id.endswith("tainted-sql-string")]
    assert [(f.start_line, f.severity) for f in sqli] == [
        (26, Severity.ERROR),
        (33, Severity.ERROR),
    ]
    # Semgrep tags this rule CWE-704; the keyword category is what dedup needs.
    assert {f.category for f in sqli} == {"sql-injection"}
    assert sorted(f.severity for f in findings).count(Severity.WARNING) == 2


def test_polyglot_output_covers_python_and_javascript() -> None:
    findings = SemgrepAnalyzer().parse(POLYGLOT_OUTPUT.read_text())

    assert len(findings) == 16
    by_file: dict[str, set[str | None]] = {}
    for finding in findings:
        by_file.setdefault(finding.file_path, set()).add(finding.category)
    assert by_file["web/server.js"] == {"command-injection", "code-injection", "xss"}
    assert {"sql-injection", "command-injection", "insecure-deserialization"} <= by_file[
        "api/app.py"
    ]


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
    assert finding.category == "code-injection"


def test_missing_results_list_raises() -> None:
    with pytest.raises(AnalyzerOutputError):
        parse_semgrep_output({"errors": []})


def test_invalid_json_raises() -> None:
    with pytest.raises(AnalyzerOutputError):
        SemgrepAnalyzer().parse("not json")


def test_non_fatal_errors_become_warnings() -> None:
    payload = {"results": [], "errors": [{"path": "/src/a.py"}, {"path": "b.js"}, {"code": 3}]}

    assert semgrep_warnings(payload) == (
        "Semgrep reported 3 non-fatal error(s) in a.py, b.js; coverage may be incomplete.",
    )
    assert semgrep_warnings({"results": [], "errors": []}) == ()

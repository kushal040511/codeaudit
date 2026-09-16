from pathlib import Path

import pytest

from app.models import Severity
from app.services.analyzers.bandit import BanditAnalyzer, bandit_warnings, normalize_severity
from app.services.analyzers.sandbox import AnalyzerOutputError

# Real `bandit -r . -f json` output from scanning fixtures/polyglot_app in the sandbox.
BANDIT_OUTPUT = Path(__file__).parents[1] / "fixtures" / "bandit_output.json"


def test_maps_real_bandit_output() -> None:
    findings = BanditAnalyzer().parse(BANDIT_OUTPUT.read_text())

    assert [(f.rule_id, f.start_line, f.severity) for f in findings] == [
        ("B403", 8, Severity.INFO),
        ("B404", 10, Severity.INFO),
        ("B105", 17, Severity.INFO),
        ("B608", 29, Severity.WARNING),
        ("B602", 37, Severity.ERROR),
        ("B301", 44, Severity.WARNING),
        ("B506", 50, Severity.WARNING),
        ("B324", 56, Severity.ERROR),
        ("B110", 62, Severity.INFO),
        ("B201", 67, Severity.ERROR),
        ("B104", 67, Severity.WARNING),
    ]
    assert {f.analyzer for f in findings} == {"bandit"}
    assert {f.file_path for f in findings} == {"api/app.py"}  # "./" stripped


def test_bandit_finding_details() -> None:
    findings = {f.rule_id: f for f in BanditAnalyzer().parse(BANDIT_OUTPUT.read_text())}

    shell = findings["B602"]
    assert shell.message.startswith("subprocess call with shell=True")
    assert shell.category == "command-injection"
    assert shell.cwe_ids == (78,)
    assert shell.code_snippet is None  # read from source by the pipeline
    assert shell.raw["test_name"] == "subprocess_popen_with_shell_equals_true"

    # try/except/pass spans two lines
    assert (findings["B110"].start_line, findings["B110"].end_line) == (62, 63)
    # Categories that must line up with Semgrep's for deduplication
    assert findings["B608"].category == "sql-injection"
    assert findings["B301"].category == "insecure-deserialization"
    assert findings["B403"].category == "insecure-deserialization"  # from CWE-502 only
    assert findings["B506"].category == "insecure-deserialization"  # tagged CWE-20
    assert findings["B201"].category == "debug-enabled"  # tagged CWE-94
    assert findings["B324"].category == "weak-crypto"
    assert findings["B104"].category == "bind-all-interfaces"
    assert findings["B105"].category == "hardcoded-secret"


@pytest.mark.parametrize(
    ("severity", "confidence", "expected"),
    [
        ("HIGH", "HIGH", Severity.ERROR),
        ("HIGH", "MEDIUM", Severity.ERROR),
        ("HIGH", "LOW", Severity.WARNING),
        ("MEDIUM", "HIGH", Severity.WARNING),
        ("MEDIUM", "LOW", Severity.INFO),
        ("LOW", "HIGH", Severity.INFO),
        ("LOW", "LOW", Severity.INFO),
        ("UNDEFINED", "HIGH", Severity.INFO),
        ("high", "high", Severity.ERROR),
    ],
)
def test_severity_normalization(severity: str, confidence: str, expected: Severity) -> None:
    assert normalize_severity(severity, confidence) is expected


def test_skips_malformed_results() -> None:
    raw = '{"results": [{"test_id": "B101"}, {"test_id": "B101", "filename": "a.py", "line_number": 3, "issue_severity": "LOW", "issue_text": "assert"}]}'  # noqa: E501

    findings = BanditAnalyzer().parse(raw)

    assert [(f.file_path, f.start_line, f.end_line) for f in findings] == [("a.py", 3, 3)]


@pytest.mark.parametrize("raw", ["not json", "[]", '{"errors": []}'])
def test_invalid_output_raises(raw: str) -> None:
    with pytest.raises(AnalyzerOutputError):
        BanditAnalyzer().parse(raw)


def test_unscannable_files_become_warnings() -> None:
    payload = {"results": [], "errors": [{"filename": "./legacy/py2.py", "reason": "syntax error"}]}

    assert bandit_warnings(payload) == ("Bandit could not scan 1 file(s): legacy/py2.py.",)

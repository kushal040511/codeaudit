from pathlib import Path

from app.models import Severity
from app.services.analyzers.bandit import BanditAnalyzer
from app.services.analyzers.dedup import deduplicate
from app.services.analyzers.dependency import DependencyAnalyzer
from app.services.analyzers.ruff import RuffAnalyzer
from app.services.analyzers.semgrep import SemgrepAnalyzer
from tests.fakes import make_finding

FIXTURES = Path(__file__).parents[1] / "fixtures"


def test_merges_same_issue_from_two_analyzers_and_records_corroboration() -> None:
    semgrep = make_finding(
        "semgrep",
        "python.flask.security.injection.tainted-sql-string",
        start_line=29,
        severity=Severity.WARNING,
        message="Detected user input used to manually construct a SQL string.",
        category="sql-injection",
    )
    bandit = make_finding(
        "bandit",
        "B608",
        file_path="./app.py",  # path spelled differently
        start_line=29,
        severity=Severity.ERROR,
        message="Possible SQL injection.",
        category="sql-injection",
    )

    [merged] = deduplicate([semgrep, bandit])

    assert merged.analyzer == "semgrep"  # richest message kept
    assert merged.rule_id == semgrep.rule_id
    assert merged.message == semgrep.message
    assert merged.severity is Severity.ERROR  # highest severity in the group
    assert merged.corroborated_by == ("bandit",)
    assert merged.merged_from == (
        {
            "analyzer": "bandit",
            "rule_id": "B608",
            "severity": "error",
            "start_line": 29,
            "message": "Possible SQL injection.",
        },
    )


def test_same_analyzer_duplicates_merge_without_self_corroboration() -> None:
    a = make_finding(
        "semgrep", "subprocess-shell-true", start_line=37, category="command-injection"
    )
    b = make_finding(
        "semgrep",
        "dangerous-subprocess-use",
        start_line=37,
        message="longer message about subprocess",
        category="command-injection",
    )

    [merged] = deduplicate([a, b])

    assert merged.rule_id == "dangerous-subprocess-use"
    assert merged.corroborated_by == ()
    assert [m["rule_id"] for m in merged.merged_from] == ["subprocess-shell-true"]


def test_keeps_findings_that_differ_in_file_line_or_category() -> None:
    base = make_finding("semgrep", "sqli", start_line=10, category="sql-injection")
    findings = [
        base,
        make_finding(
            "bandit", "B608", file_path="other.py", start_line=10, category="sql-injection"
        ),
        make_finding("bandit", "B608", start_line=20, category="sql-injection"),
        make_finding("bandit", "B104", start_line=10, category="bind-all-interfaces"),
    ]

    assert deduplicate(findings) == findings


def test_uncategorized_findings_only_merge_with_the_same_rule() -> None:
    a = make_finding("bandit", "B110", start_line=62)
    b = make_finding("ruff", "E722", start_line=62)
    c = make_finding("bandit", "B110", start_line=62, message="a longer duplicate")

    result = deduplicate([a, b, c])

    assert [(f.analyzer, f.rule_id) for f in result] == [("bandit", "B110"), ("ruff", "E722")]
    assert result[0].message == "a longer duplicate"


def test_short_multiline_range_matches_inner_start_line() -> None:
    call = make_finding(
        "semgrep", "subprocess", start_line=36, end_line=39, category="command-injection"
    )
    arg = make_finding("bandit", "B602", start_line=38, category="command-injection")
    whole_function = make_finding(
        "semgrep", "taint", start_line=30, end_line=60, category="command-injection"
    )

    result = deduplicate([call, arg, whole_function])

    assert len(result) == 2
    assert result[0].corroborated_by == ("bandit",)
    assert result[1] is whole_function  # too broad to prove it's the same issue


def test_groups_do_not_chain_along_adjacent_lines() -> None:
    findings = [
        make_finding("a", "r1", start_line=1, end_line=2, category="xss"),
        make_finding("b", "r2", start_line=2, end_line=3, category="xss"),
        make_finding("c", "r3", start_line=3, end_line=4, category="xss"),
    ]

    result = deduplicate(findings)

    assert [(f.start_line, f.corroborated_by) for f in result] == [(1, ("b",)), (3, ())]


def test_preserves_existing_corroboration_and_input_order() -> None:
    first = make_finding("x", "r", file_path="b.py", start_line=5, category="xss")
    second = make_finding("y", "r", file_path="a.py", start_line=1, category="xss")

    assert deduplicate([first, second]) == [first, second]
    assert deduplicate([]) == []


def test_real_polyglot_outputs() -> None:
    findings = [
        *SemgrepAnalyzer().parse((FIXTURES / "semgrep_polyglot_output.json").read_text()),
        *BanditAnalyzer().parse((FIXTURES / "bandit_output.json").read_text()),
        *RuffAnalyzer().parse((FIXTURES / "ruff_output.json").read_text()),
        *DependencyAnalyzer().parse((FIXTURES / "osv_scanner_output.json").read_text()),
    ]
    assert len(findings) == 52

    result = deduplicate(findings)

    assert len(result) == 39
    corroborated = {
        (f.file_path, f.start_line, f.category): f.corroborated_by
        for f in result
        if f.corroborated_by
    }
    assert corroborated == {
        ("api/app.py", 29, "sql-injection"): ("bandit",),
        ("api/app.py", 37, "command-injection"): ("bandit",),
        ("api/app.py", 44, "insecure-deserialization"): ("bandit",),
        ("api/app.py", 50, "insecure-deserialization"): ("bandit",),
        ("api/app.py", 56, "weak-crypto"): ("bandit",),
        ("api/app.py", 67, "bind-all-interfaces"): ("bandit",),
        ("api/app.py", 67, "debug-enabled"): ("bandit",),
    }
    # Command injection: three Semgrep rules and Bandit's B602 are one issue.
    [shell] = [f for f in result if f.category == "command-injection" and f.start_line == 37]
    assert sorted(m["analyzer"] for m in shell.merged_from) == ["bandit", "semgrep", "semgrep"]
    assert shell.severity is Severity.ERROR
    # Nothing from Ruff or the dependency scan is merged away.
    assert sum(f.analyzer == "ruff" for f in result) == 2
    assert sum(f.analyzer == "dependency" for f in result) == 23
    # Bandit-only findings survive (import pickle, hardcoded password, try/except/pass).
    assert {f.rule_id for f in result if f.analyzer == "bandit"} == {"B403", "B404", "B105", "B110"}

from pathlib import Path
from typing import Any

import pytest

from app.models import Finding, Severity
from app.services.llm.context import (
    ProjectConventions,
    code_window,
    dependency_manifest,
    detect_conventions,
    is_major_bump,
    merge_windows,
)
from app.services.llm.fix_suggester import build_prompt, group_findings
from app.services.scoring.priority import top_fixable

FIXTURES = Path(__file__).parents[2] / "fixtures"
MIXED = FIXTURES / "architecture" / "mixed_repo"
POLYGLOT = FIXTURES / "polyglot_app"


def finding(id: int, **overrides: Any) -> Finding:
    values: dict[str, Any] = {
        "id": id,
        "analyzer": "semgrep",
        "rule_id": "rule",
        "severity": Severity.WARNING,
        "file_path": "api/app.py",
        "start_line": 10,
        "end_line": 10,
        "message": "issue",
        "corroborated_by": [],
        "dependency": None,
        "score_impact": None,
    }
    return Finding(**(values | overrides))


def test_top_fixable_orders_by_score_impact() -> None:
    small = finding(1, severity=Severity.CRITICAL, score_impact=0.4)
    big = finding(2, severity=Severity.WARNING, score_impact=2.5)
    tie_more_severe = finding(3, severity=Severity.ERROR, score_impact=0.4)
    unknown = finding(4, severity=Severity.CRITICAL, score_impact=None)  # scored before the rubric
    structural = finding(5, analyzer="architecture", severity=Severity.CRITICAL, score_impact=9.0)

    ranked = top_fixable([small, big, tie_more_severe, unknown, structural], limit=3)

    assert [p.finding.id for p in ranked] == [2, 1, 3]
    assert [p.priority for p in ranked] == [2.5, 0.4, 0.4]
    assert top_fixable([small], limit=0) == []


def test_groups_same_rule_same_file_and_same_package() -> None:
    findings = [
        finding(1, rule_id="sqli"),
        finding(2, rule_id="xss"),
        finding(3, rule_id="sqli", start_line=40),
        finding(4, rule_id="sqli", file_path="other.py"),
        finding(
            5,
            analyzer="dependency",
            file_path="req.txt",
            rule_id="CVE-1",
            dependency={"package": "yaml"},
        ),
        finding(
            6,
            analyzer="dependency",
            file_path="req.txt",
            rule_id="CVE-2",
            dependency={"package": "yaml"},
        ),
        finding(7, rule_id="sqli", start_line=80),
    ]

    groups = group_findings(findings, max_per_request=2)

    assert [[f.id for f in g.findings] for g in groups] == [[1, 3], [2], [4], [5, 6], [7]]


@pytest.mark.parametrize(
    ("installed", "fixed", "major"),
    [
        ("5.3", "5.4", False),
        ("4.17.15", "4.18.0", False),
        ("2.0.1", "3.1.3", True),
        ("0.4.1", "0.5.0", True),
        ("0.4.1", "0.4.9", False),
        ("1.2", None, None),
        ("abc", "1.0", None),
    ],
)
def test_major_bump_detection(installed: str, fixed: str | None, major: bool | None) -> None:
    assert is_major_bump(installed, fixed) is major


def test_dependency_manifest_prefers_package_json_for_lockfiles() -> None:
    assert dependency_manifest(POLYGLOT, "web/package-lock.json", "npm") == "web/package.json"
    assert dependency_manifest(POLYGLOT, "api/requirements.txt", "PyPI") == "api/requirements.txt"


def test_code_windows_merge_overlaps() -> None:
    first = code_window(POLYGLOT, "api/app.py", 29, 29, 3)
    second = code_window(POLYGLOT, "api/app.py", 33, 33, 3)
    far = code_window(POLYGLOT, "api/app.py", 60, 60, 2)
    assert first and second and far

    merged = merge_windows([far, second, first])

    assert [(w.start_line, w.end_line) for w in merged] == [(26, 36), (58, 62)]
    assert (
        merged[0].text.splitlines()[0] == (POLYGLOT / "api" / "app.py").read_text().splitlines()[25]
    )
    assert len(merged[0].text.splitlines()) == 11
    assert code_window(POLYGLOT, "../../conftest.py", 1, 1, 2) is None


def test_detect_conventions() -> None:
    conventions = detect_conventions(MIXED, ["python", "typescript"])

    assert conventions.frameworks == ["FastAPI", "React", "Vite"]
    polyglot = detect_conventions(POLYGLOT, ["python", "javascript"])
    assert {"Flask", "Express"} <= set(polyglot.frameworks)


def test_prompt_contains_findings_code_hint_and_dependency_facts() -> None:
    sqli = finding(
        11,
        rule_id="tainted-sql",
        file_path="api/app.py",
        start_line=29,
        end_line=29,
        message="SQL built from input",
    )
    lodash = finding(
        12,
        analyzer="dependency",
        rule_id="CVE-2021-23337",
        file_path="web/package-lock.json",
        start_line=20,
        end_line=20,
        dependency={
            "package": "lodash",
            "ecosystem": "npm",
            "installed_version": "4.17.15",
            "fixed_version": "4.18.0",
            "fixed_versions": ["4.17.21", "4.18.0"],
            "advisory_id": "CVE-2021-23337",
        },
    )
    conventions = ProjectConventions(languages=["python"], frameworks=["Flask"])

    groups = group_findings([sqli, lodash], 5)
    code_prompt = build_prompt(
        groups[0], POLYGLOT, conventions, 20, user_hint="Use parameterized queries via sqlite3"
    )
    dep_prompt = build_prompt(groups[1], POLYGLOT, conventions, 20)

    assert '<finding id="11">' in code_prompt and "SQL built from input" in code_prompt
    assert '<code path="api/app.py" first_line="9"' in code_prompt
    assert 'cursor.execute("SELECT id, name FROM users WHERE name' in code_prompt
    assert "<reviewer_hint>\nUse parameterized queries via sqlite3\n</reviewer_hint>" in code_prompt
    assert code_prompt.rstrip().endswith("finding ids: 11.")
    assert "Major version upgrade: no" in dep_prompt
    assert "Edit this manifest: web/package.json" in dep_prompt
    assert '<code path="web/package.json" first_line="1"' in dep_prompt

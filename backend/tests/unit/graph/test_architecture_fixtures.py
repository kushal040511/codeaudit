"""Exact structural results for the committed fixture repositories."""

from pathlib import Path

import pytest

from app.models import ArchitectureIssueType, Severity
from app.services.analyzers.architecture import ArchitectureAnalyzer
from app.services.analyzers.base import ScanContext
from app.services.graph.analysis import ArchitectureReport, analyze_architecture

FIXTURES = Path(__file__).parents[2] / "fixtures" / "architecture"


def issues_of(report: ArchitectureReport, issue_type: ArchitectureIssueType) -> list[list[str]]:
    return [i.involved_modules for i in report.metrics.issues if i.issue_type is issue_type]


def test_clean_layered_repo_has_no_issues() -> None:
    report = analyze_architecture(FIXTURES / "clean_layered")

    assert report.metrics.issues == []
    summary = report.summary
    assert (summary["node_count"], summary["edge_count"]) == (18, 9)
    assert summary["cycle_count"] == 0 and summary["layer_violation_count"] == 0
    assert summary["resolution"]["coverage"] == 1.0
    layers = {
        node: data["layer"]
        for node, data in report.graph.graph.nodes(data=True)
        if not data["is_entrypoint"]
    }
    assert layers == {
        "app/api/routes/users": "presentation",
        "app/services/user_service": "service",
        "app/repositories/user_repository": "data",
        "app/models/user": "data",
        "app/db/base": "data",
        "app/db/session": "data",
        "app/core/config": None,
    }
    # routes -> service -> repository -> session -> config
    assert summary["max_depth"] == 5


def test_cycle_repo_reports_exactly_the_runtime_cycle() -> None:
    report = analyze_architecture(FIXTURES / "cycle_repo")

    assert issues_of(report, ArchitectureIssueType.CIRCULAR_DEPENDENCY) == [
        ["pkg/a", "pkg/b", "pkg/c"]
    ]
    [cycle] = report.metrics.issues
    assert cycle.severity is Severity.ERROR
    assert cycle.involved_edges == [("pkg/a", "pkg/b"), ("pkg/b", "pkg/c"), ("pkg/c", "pkg/a")]
    assert cycle.description.startswith(
        "Import cycle of 3 modules: pkg/a.py → pkg/b.py → pkg/c.py → pkg/a.py."
    )
    # d <-> e only through `if TYPE_CHECKING:`: an edge, but not a runtime cycle.
    assert report.graph.edges[("pkg/d", "pkg/e")].type_only
    assert report.summary["cyclic_module_count"] == 3
    assert report.summary["type_only_edge_count"] == 1


def test_layer_violation_repo_flags_route_importing_model() -> None:
    report = analyze_architecture(FIXTURES / "layer_violation")

    assert [
        (i.issue_type, i.severity, i.involved_edges, i.details["skipped_layers"])
        for i in report.metrics.issues
    ] == [
        (
            ArchitectureIssueType.LAYER_VIOLATION,
            Severity.WARNING,
            [("app/routes/orders", "app/models/order")],
            ["service"],
        )
    ]
    assert report.metrics.issues[0].description == (
        "app/routes/orders.py (presentation layer) imports app/models/order.py (data layer)"
        " directly, bypassing the service layer."
    )


def test_mixed_python_typescript_repo() -> None:
    report = analyze_architecture(FIXTURES / "mixed_repo")
    summary = report.summary

    assert [
        (i.issue_type.value, i.severity.value, i.involved_modules) for i in report.metrics.issues
    ] == [
        (
            "layer_violation",
            "error",
            ["frontend/src/store/cartSlice", "frontend/src/components/Price"],
        ),
        ("orphan_module", "info", ["frontend/src/components/OldBanner"]),
    ]
    assert summary["languages"] == {"python": 8, "typescript": 12, "javascript": 2}
    assert sorted(report.graph.edges) == [
        ("backend/app/api/routes", "backend/app/services/pricing"),
        ("backend/app/services/pricing", "backend/app/models"),
        ("backend/app/services/pricing", "backend/app/services/utils"),
        ("backend/main", "backend/app/api/routes"),
        ("frontend/scripts/build", "frontend/scripts/helpers"),
        ("frontend/src/App", "frontend/src/components/CartBadge"),
        ("frontend/src/App", "frontend/src/pages/Settings"),  # dynamic import()
        ("frontend/src/api/client", "frontend/src/store/cartSlice"),
        ("frontend/src/api/client", "frontend/src/types/index"),  # import type via @/ alias
        ("frontend/src/components/CartBadge", "frontend/src/hooks/useCart"),
        ("frontend/src/hooks/useCart", "frontend/src/api/client"),  # "../api/client.js"
        ("frontend/src/main", "frontend/src/App"),
        ("frontend/src/pages/Settings", "frontend/src/hooks/useCart"),
        ("frontend/src/store/cartSlice", "frontend/src/components/Price"),
        ("frontend/src/store/cartSlice", "frontend/src/types/index"),
    ]
    assert summary["resolution"] == {
        "total": 29,
        "internal": 15,
        "external": 10,
        "asset": 2,
        "unresolved": 2,
        "undeclared_external": 1,  # react-dom/client: only react is declared
        "coverage": 0.931,
        "unresolved_by_reason": {
            "dynamic import with a non-literal specifier": 1,
            "file not found": 1,
        },
        "unresolved_by_form": {"require (non-literal)": 1, "require (relative)": 1},
    }
    externals = {(e.package, e.evidence) for e in report.graph.external}
    assert {("yaml", "declared"), ("fastapi", "declared"), ("json", "stdlib")} <= externals
    assert {
        ("axios", "declared"),
        ("path", "node-builtin"),
        ("react-dom", "undeclared"),
    } <= externals


def test_syntax_errors_keep_the_module_in_the_graph(tmp_path: Path) -> None:
    report = analyze_architecture(FIXTURES / "mixed_repo")

    parse = report.summary["parse"]
    assert parse["skipped"] == 0  # nothing is dropped outright
    assert parse["partial_files"] == [
        {
            "path": "backend/app/legacy.py",
            "reason": "partial parse near line 2; some imports may be missing",
        },
        {
            "path": "frontend/src/broken.ts",
            "reason": "partial parse near line 2; some imports may be missing",
        },
    ]
    broken = report.graph.graph.nodes["frontend/src/broken"]
    assert broken["parse_error"] == "partial parse near line 2; some imports may be missing"
    # Still a node (other modules may import it), never reported as an orphan.
    assert "frontend/src/broken" not in {
        m for i in report.metrics.issues for m in i.involved_modules
    }

    result = ArchitectureAnalyzer().run(
        FIXTURES / "mixed_repo", ScanContext(scan_id="s", work_dir=tmp_path, languages=[])
    )
    assert result.success
    assert result.warnings == (
        "2 file(s) used syntax the parser doesn't fully support; they are in the graph but may be"
        " missing imports: backend/app/legacy.py, frontend/src/broken.ts.",
    )


def test_analyzer_emits_findings_for_each_issue(tmp_path: Path) -> None:
    analyzer = ArchitectureAnalyzer()

    result = analyzer.run(
        FIXTURES / "cycle_repo", ScanContext(scan_id="s", work_dir=tmp_path, languages=[])
    )

    [finding] = result.findings
    assert (finding.analyzer, finding.rule_id, finding.severity) == (
        "architecture",
        "architecture/circular_dependency",
        Severity.ERROR,
    )
    assert (finding.file_path, finding.start_line) == ("pkg/a.py", 1)
    assert finding.category is not None and finding.category.startswith("architecture:")
    assert finding.raw["involved_modules"] == ["pkg/a", "pkg/b", "pkg/c"]
    assert isinstance(result.artifact, ArchitectureReport)
    assert analyzer.parse(result.raw_output) == result.findings


def test_deadline_stops_analysis() -> None:
    from app.core.errors import AnalyzerTimeoutError

    with pytest.raises(AnalyzerTimeoutError, match="ran out of time while parsing"):
        analyze_architecture(FIXTURES / "mixed_repo", deadline=0.0)

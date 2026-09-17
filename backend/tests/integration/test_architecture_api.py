"""Architecture analyzer -> persistence -> graph and issue endpoints (Postgres, no Docker)."""

import shutil
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.db import SessionLocal
from app.models import ArchitectureIssue, Finding, GraphEdge, GraphNode, Scan, ScanStatus
from app.services.analyzers.architecture import ArchitectureAnalyzer
from app.services.analyzers.registry import AnalyzerRegistry
from app.services.languages import detect_languages
from app.services.scan_pipeline import analyze_and_persist

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).parents[1] / "fixtures" / "architecture"


def scan_fixture(name: str, tmp_path: Path) -> uuid.UUID:
    source = tmp_path / "src"
    shutil.copytree(FIXTURES / name, source)
    with SessionLocal() as db:
        scan = Scan(status=ScanStatus.RUNNING, original_filename=f"{name}.zip", storage_key="x")
        db.add(scan)
        db.commit()
        analyze_and_persist(
            db,
            scan,
            source,
            tmp_path,
            detect_languages(source),
            AnalyzerRegistry([ArchitectureAnalyzer()]),
        )
        return scan.id


def test_mixed_repo_graph_is_persisted_and_served(
    database: None, tmp_path: Path, api: TestClient
) -> None:
    scan_id = scan_fixture("mixed_repo", tmp_path)

    scan = api.get(f"/api/scans/{scan_id}").json()
    # A file with a syntax error doesn't fail the scan; it is reported as a warning.
    assert scan["status"] == "completed"
    [run] = scan["analyzer_runs"]
    assert (run["analyzer"], run["status"], run["finding_count"]) == (
        "architecture",
        "completed",
        2,
    )
    assert "may be missing imports" in run["warnings"][0]

    with SessionLocal() as db:
        assert db.scalar(select(func.count()).where(GraphNode.scan_id == scan_id)) == 22
        kinds = dict(
            db.execute(
                select(GraphEdge.kind, func.count())
                .where(GraphEdge.scan_id == scan_id)
                .group_by(GraphEdge.kind)
            ).all()
        )
        findings = db.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()
    assert {k.value: v for k, v in kinds.items()} == {
        "internal": 15,
        "external": 10,
        "unresolved": 2,
    }
    assert sorted(f.rule_id for f in findings) == [
        "architecture/layer_violation",
        "architecture/orphan_module",
    ]
    inversion = next(f for f in findings if f.rule_id == "architecture/layer_violation")
    assert inversion.file_path == "frontend/src/store/cartSlice.ts"
    assert inversion.code_snippet == "import { Price } from '@/components/Price'"

    graph = api.get(f"/api/scans/{scan_id}/graph").json()
    assert graph["view"] == {
        "total_modules": 22,
        "aggregated": False,
        "depth": None,
        "max_nodes": 300,
        "expanded": [],
        "collapsed": [],
    }
    assert len(graph["nodes"]) == 22 and len(graph["edges"]) == 15
    assert graph["summary"]["resolution"]["coverage"] == 0.931
    violation_edges = [e["id"] for e in graph["edges"] if e["layer_violation"]]
    assert violation_edges == ["frontend/src/store/cartSlice->frontend/src/components/Price"]
    price = next(n for n in graph["nodes"] if n["id"] == "frontend/src/components/Price")
    assert (price["layer"], price["fan_in"], price["kind"]) == ("ui", 1, "module")
    externals = {(d["name"], d["language"]): d for d in graph["external_dependencies"]}
    assert externals[("react", "typescript")]["importer_count"] == 1
    assert externals[("yaml", "python")]["evidence"] == "declared"

    aggregated = api.get(f"/api/scans/{scan_id}/graph", params={"max_nodes": 10}).json()
    assert aggregated["view"]["aggregated"] and aggregated["view"]["depth"] == 2
    assert len(aggregated["nodes"]) <= 10
    [issue_ref] = [i for i in aggregated["issues"] if i["issue_type"] == "layer_violation"]
    # Both modules of the violation are inside frontend/src at this depth.
    assert issue_ref["node_ids"] == ["dir:frontend/src"] and issue_ref["edge_ids"] == []

    expanded = api.get(
        f"/api/scans/{scan_id}/graph", params={"max_nodes": 10, "expand": "frontend/src"}
    ).json()
    assert "dir:frontend/src/store" in {n["id"] for n in expanded["nodes"]}
    assert any(e["layer_violation"] for e in expanded["edges"])

    module = api.get(
        f"/api/scans/{scan_id}/graph/module", params={"module_id": "frontend/src/api/client"}
    ).json()
    assert [i["module"] for i in module["importers"]] == ["frontend/src/hooks/useCart"]
    # internal first, then external; each in source order
    assert [(i["kind"], i["module"], i["line"], i["type_only"]) for i in module["imports"]] == [
        ("internal", "frontend/src/types/index", 2, True),
        ("internal", "frontend/src/store/cartSlice", 3, False),
        ("external", "axios", 1, False),
    ]
    assert module["imports"][1]["path"] == "frontend/src/store/cartSlice.ts"

    build = api.get(
        f"/api/scans/{scan_id}/graph/module", params={"module_id": "frontend/scripts/build"}
    ).json()
    unresolved = [
        (i["module"], i["resolution"]) for i in build["imports"] if i["kind"] == "unresolved"
    ]
    assert unresolved == [
        ("process.env.PLUGIN_NAME", "dynamic import with a non-literal specifier"),
        ("./does-not-exist", "file './does-not-exist' not found"),
    ]

    issues = api.get(f"/api/scans/{scan_id}/architecture-issues").json()
    assert [(i["issue_type"], i["severity"]) for i in issues] == [
        ("layer_violation", "error"),
        ("orphan_module", "info"),
    ]
    only_orphans = api.get(
        f"/api/scans/{scan_id}/architecture-issues", params={"issue_type": "orphan_module"}
    ).json()
    assert [i["involved_modules"] for i in only_orphans] == [["frontend/src/components/OldBanner"]]


def test_cycle_repo_issue_rows_and_highlights(
    database: None, tmp_path: Path, api: TestClient
) -> None:
    scan_id = scan_fixture("cycle_repo", tmp_path)

    with SessionLocal() as db:
        [issue] = db.scalars(
            select(ArchitectureIssue).where(ArchitectureIssue.scan_id == scan_id)
        ).all()
    assert issue.involved_modules == ["pkg/a", "pkg/b", "pkg/c"]
    assert issue.involved_edges == [["pkg/a", "pkg/b"], ["pkg/b", "pkg/c"], ["pkg/c", "pkg/a"]]
    assert issue.metric_value == 3.0

    graph = api.get(f"/api/scans/{scan_id}/graph").json()
    [ref] = graph["issues"]
    assert ref["node_ids"] == ["pkg/a", "pkg/b", "pkg/c"]
    assert sorted(ref["edge_ids"]) == ["pkg/a->pkg/b", "pkg/b->pkg/c", "pkg/c->pkg/a"]
    assert {e["id"] for e in graph["edges"] if e["in_cycle"]} == set(ref["edge_ids"])
    type_only = [e["id"] for e in graph["edges"] if e["type_only"]]
    assert type_only == ["pkg/d->pkg/e"]


def test_graph_endpoints_404(database: None, api: TestClient) -> None:
    missing = uuid.uuid4()
    assert api.get(f"/api/scans/{missing}/graph").status_code == 404
    assert api.get(f"/api/scans/{missing}/architecture-issues").status_code == 404
    with SessionLocal() as db:
        scan = Scan(status=ScanStatus.QUEUED, original_filename="x.zip", storage_key="x")
        db.add(scan)
        db.commit()
        pending = scan.id
    response = api.get(f"/api/scans/{pending}/graph")
    assert response.status_code == 404
    assert "has no architecture graph" in response.json()["error"]["message"]

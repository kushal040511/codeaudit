"""Scoring through the pipeline and the API (Postgres, no Docker)."""

import shutil
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.db import SessionLocal
from app.models import Finding, Scan, ScanScore, ScanStatus, Severity
from app.services.analyzers.architecture import ArchitectureAnalyzer
from app.services.analyzers.base import FindingData
from app.services.analyzers.registry import AnalyzerRegistry
from app.services.languages import count_source_lines, detect_languages
from app.services.scan_pipeline import analyze_and_persist
from app.services.scoring import backfill
from tests.fakes import FakeAnalyzer

pytestmark = pytest.mark.integration

MIXED = Path(__file__).parents[1] / "fixtures" / "architecture" / "mixed_repo"
FINDINGS = [
    FindingData(
        "semgrep", "sqli", Severity.CRITICAL, "backend/app/api/routes.py", 8, 8, "SQL injection"
    ),
    FindingData(
        "semgrep", "sqli", Severity.ERROR, "backend/app/services/pricing.py", 8, 8, "SQL injection"
    ),
    FindingData("semgrep", "xss", Severity.WARNING, "frontend/src/App.tsx", 5, 5, "XSS"),
    FindingData("dependency", "CVE-1", Severity.ERROR, "backend/requirements.txt", 2, 2, "pyyaml"),
    FindingData(
        "semgrep", "weak-test", Severity.ERROR, "backend/tests/test_x.py", 1, 1, "in a test"
    ),
]


def analyze(tmp_path: Path, registry: AnalyzerRegistry) -> uuid.UUID:
    source = tmp_path / "src"
    shutil.copytree(MIXED, source, dirs_exist_ok=True)
    with SessionLocal() as db:
        scan = Scan(status=ScanStatus.RUNNING, original_filename="mixed.zip", storage_key="x")
        scan.source_loc = count_source_lines(source)
        db.add(scan)
        db.commit()
        analyze_and_persist(db, scan, source, tmp_path, detect_languages(source), registry)
        return scan.id


@pytest.fixture
def scan_id(database: None, tmp_path: Path) -> uuid.UUID:
    registry = AnalyzerRegistry(
        [
            ArchitectureAnalyzer(),
            FakeAnalyzer("semgrep", [f for f in FINDINGS if f.analyzer == "semgrep"]),
            FakeAnalyzer("dependency", [f for f in FINDINGS if f.analyzer == "dependency"]),
        ]
    )
    return analyze(tmp_path, registry)


def test_pipeline_stores_score_and_exact_impacts(scan_id: uuid.UUID, api: TestClient) -> None:
    score = api.get(f"/api/scans/{scan_id}/score").json()
    assert score["rubric_version"] == "1.1.0"
    # No experimental signal flag is on by default: scored exactly like rubric 1.0.
    assert score["rubric_config"] == "base"
    assert all(c["deductions"] == [] for c in score["categories"])
    assert score["incomplete"] is False
    categories = {c["category"]: c for c in score["categories"]}
    assert (
        categories["code_health"]["excluded_reason"] == "not applicable to this codebase"
    )  # no ruff run
    assert categories["security"]["finding_count"] == 4
    assert categories["architecture"]["finding_count"] == 2  # layer inversion + orphan
    assert score["source_loc"] > 0 and score["module_count"] == 22
    assert sum(c["weight"] for c in score["categories"]) == pytest.approx(1.0, abs=1e-3)

    scan = api.get(f"/api/scans/{scan_id}").json()
    assert scan["score"] == {
        "overall": score["overall"],
        "grade": score["grade"],
        "incomplete": False,
        "rubric_version": "1.1.0",
    }

    items = api.get(f"/api/scans/{scan_id}/findings", params={"page_size": 100}).json()["items"]
    by_rule = {(i["rule_id"], i["file_path"]): i for i in items}
    critical = by_rule[("sqli", "backend/app/api/routes.py")]
    error = by_rule[("sqli", "backend/app/services/pricing.py")]
    in_test = by_rule[("weak-test", "backend/tests/test_x.py")]
    assert critical["score_impact"] > error["score_impact"] > in_test["score_impact"] > 0

    for item in items:
        projection = api.post(
            f"/api/scans/{scan_id}/score/projection", json={"finding_ids": [item["id"]]}
        ).json()
        assert projection["delta"] == pytest.approx(item["score_impact"], abs=0.011), item[
            "rule_id"
        ]


def test_projection_for_a_selection(scan_id: uuid.UUID, api: TestClient, tmp_path: Path) -> None:
    items = api.get(f"/api/scans/{scan_id}/findings", params={"page_size": 100}).json()["items"]
    security_ids = [i["id"] for i in items if i["analyzer"] == "semgrep"]
    with SessionLocal() as db:
        other_scan_finding = db.scalar(
            select(Finding.id).where(Finding.scan_id != scan_id).limit(1)
        )

    projection = api.post(
        f"/api/scans/{scan_id}/score/projection",
        json={
            "finding_ids": security_ids
            + ([other_scan_finding] if other_scan_finding else [])
            + [security_ids[0]]
        },
    ).json()

    assert projection["included_finding_ids"] == security_ids
    assert projection["ignored_finding_ids"] == ([other_scan_finding] if other_scan_finding else [])
    projected = {c["category"]: c for c in projection["projected"]["categories"]}
    assert projected["security"]["score"] == 100.0
    assert (
        projection["delta"]
        > sum(i["score_impact"] for i in items if i["id"] in security_ids) - 1e-6
    )
    assert (
        projection["current"]["overall"] == api.get(f"/api/scans/{scan_id}/score").json()["overall"]
    )

    empty = api.post(f"/api/scans/{scan_id}/score/projection", json={"finding_ids": []}).json()
    assert empty["delta"] == 0


def test_failed_analyzer_marks_score_incomplete(
    database: None, tmp_path: Path, api: TestClient
) -> None:
    def fail() -> list[FindingData]:
        raise RuntimeError("osv crashed")

    registry = AnalyzerRegistry(
        [FakeAnalyzer("semgrep", FINDINGS[:1]), FakeAnalyzer("dependency", behavior=fail)]
    )
    scan_id = analyze(tmp_path, registry)

    score = api.get(f"/api/scans/{scan_id}/score").json()
    assert score["incomplete"] is True
    assert score["incomplete_reasons"] == ["Dependencies: dependency failed"]


def test_backfill_rescoring_is_idempotent(scan_id: uuid.UUID) -> None:
    with SessionLocal() as db:
        before = db.get(ScanScore, scan_id)
        assert before is not None
        overall = before.overall
        impacts = dict(
            db.execute(
                select(Finding.id, Finding.score_impact).where(Finding.scan_id == scan_id)
            ).all()
        )

    assert backfill.main(["--all"]) == 0

    with SessionLocal() as db:
        after = db.get(ScanScore, scan_id)
        assert after is not None and after.overall == overall
        rescored = dict(
            db.execute(
                select(Finding.id, Finding.score_impact).where(Finding.scan_id == scan_id)
            ).all()
        )
    assert rescored == pytest.approx(impacts)


def test_score_404s(database: None, api: TestClient) -> None:
    missing = uuid.uuid4()
    assert api.get(f"/api/scans/{missing}/score").status_code == 404
    assert (
        api.post(f"/api/scans/{missing}/score/projection", json={"finding_ids": []}).status_code
        == 404
    )

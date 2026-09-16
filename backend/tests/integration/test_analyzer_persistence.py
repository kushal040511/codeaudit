"""Orchestration + persistence against Postgres, with fake analyzers (no Docker)."""

import uuid
from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.db import SessionLocal
from app.core.errors import AnalysisError, TransientInfraError
from app.models import AnalyzerRun, AnalyzerRunStatus, Finding, Scan, ScanStatus, Severity
from app.services.analyzers.base import FindingData
from app.services.analyzers.registry import AnalyzerRegistry
from app.services.analyzers.sandbox import SandboxTimeoutError, SandboxUnavailableError
from app.services.languages import DetectedLanguage
from app.services.scan_pipeline import analyze_and_persist
from tests.fakes import FakeAnalyzer, make_finding

pytestmark = pytest.mark.integration

PYTHON = [DetectedLanguage(language="python", file_count=1, manifests=[])]


def raises(exc: Exception) -> Callable[[], list[FindingData]]:
    def behavior() -> list[FindingData]:
        raise exc

    return behavior


def create_scan() -> uuid.UUID:
    with SessionLocal() as db:
        scan = Scan(
            status=ScanStatus.RUNNING, original_filename="repo.zip", storage_key="uploads/x"
        )
        db.add(scan)
        db.commit()
        return scan.id


def analyze(scan_id: uuid.UUID, tmp_path: Path, registry: AnalyzerRegistry) -> None:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    (source / "app.py").write_text("\n".join(f"line {n}" for n in range(1, 40)) + "\n")
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None
        analyze_and_persist(db, scan, source, tmp_path, PYTHON, registry)


def runs_by_name(scan_id: uuid.UUID) -> dict[str, AnalyzerRun]:
    with SessionLocal() as db:
        runs = db.scalars(select(AnalyzerRun).where(AnalyzerRun.scan_id == scan_id)).all()
        return {run.analyzer_name: run for run in runs}


def test_failing_analyzers_do_not_prevent_others_from_persisting(
    database: None, tmp_path: Path, api: TestClient
) -> None:
    scan_id = create_scan()
    registry = AnalyzerRegistry(
        [
            FakeAnalyzer(
                "semgrep",
                [
                    make_finding(
                        "semgrep",
                        "tainted-sql",
                        start_line=10,
                        severity=Severity.ERROR,
                        message="User input flows into a SQL query built by concatenation.",
                        category="sql-injection",
                    ),
                    make_finding("semgrep", "xss", start_line=20, category="xss"),
                ],
            ),
            FakeAnalyzer("bandit", behavior=raises(RuntimeError("segfault"))),
            FakeAnalyzer(
                "ruff",
                languages=frozenset({"python"}),
                behavior=raises(SandboxTimeoutError("killed")),
                timeout_seconds=120,
            ),
            FakeAnalyzer(
                "osv",
                [
                    make_finding(
                        "osv",
                        "B608",
                        start_line=10,
                        message="Possible SQL injection.",
                        category="sql-injection",
                    )
                ],
            ),
            FakeAnalyzer("eslint", languages=frozenset({"javascript"})),
        ]
    )

    analyze(scan_id, tmp_path, registry)

    runs = runs_by_name(scan_id)
    assert {name: run.status for name, run in runs.items()} == {
        "semgrep": AnalyzerRunStatus.COMPLETED,
        "bandit": AnalyzerRunStatus.FAILED,
        "ruff": AnalyzerRunStatus.TIMED_OUT,
        "osv": AnalyzerRunStatus.COMPLETED,
        "eslint": AnalyzerRunStatus.SKIPPED,
    }
    assert runs["semgrep"].finding_count == 2 and runs["osv"].finding_count == 1
    assert runs["bandit"].error_message == "Bandit crashed with an internal error."
    assert runs["ruff"].error_message == "Ruff timed out after 120s and was stopped."
    assert runs["eslint"].error_message == "Not applicable: no javascript code detected."
    assert all(
        r.duration_ms is not None and r.completed_at for n, r in runs.items() if n != "eslint"
    )

    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None and scan.status is ScanStatus.PARTIAL
        findings = db.scalars(
            select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.start_line)
        ).all()
    # The SQL injection reported by two analyzers is stored once, with corroboration.
    assert [(f.analyzer, f.start_line, f.corroborated_by) for f in findings] == [
        ("semgrep", 10, ["osv"]),
        ("semgrep", 20, []),
    ]
    assert findings[0].merged_from[0]["rule_id"] == "B608"
    assert findings[0].code_snippet == "line 10"  # filled from the source tree

    body = api.get(f"/api/scans/{scan_id}").json()
    assert body["status"] == "partial"
    assert body["analyzer_summary"] == {
        "total": 4,
        "completed": 2,
        "failed": 2,
        "running": 0,
        "skipped": 1,
    }
    assert body["findings_before_dedup"] == 3
    assert body["total_findings"] == 2
    assert body["findings_by_analyzer"] == {"semgrep": 2, "osv": 1}
    ruff = next(r for r in body["analyzer_runs"] if r["analyzer"] == "ruff")
    assert ruff["status"] == "timed_out" and ruff["warnings"] == []

    # Filtering by an analyzer includes findings it corroborated.
    page = api.get(f"/api/scans/{scan_id}/findings", params={"analyzer": ["osv"]}).json()
    assert [(i["analyzer"], i["corroborated_by"]) for i in page["items"]] == [("semgrep", ["osv"])]
    assert page["items"][0]["merged_from"][0]["analyzer"] == "osv"
    page = api.get(
        f"/api/scans/{scan_id}/findings", params={"analyzer": ["semgrep", "bandit"]}
    ).json()
    assert page["total"] == 2
    # Corroborated findings sort first within a severity.
    assert api.get(f"/api/scans/{scan_id}/findings").json()["items"][0]["corroborated_by"] == [
        "osv"
    ]


def test_all_analyzers_succeeding_is_completed_and_rerun_replaces_results(
    database: None, tmp_path: Path
) -> None:
    scan_id = create_scan()
    registry = AnalyzerRegistry([FakeAnalyzer("a", [make_finding("a")]), FakeAnalyzer("b")])

    analyze(scan_id, tmp_path, registry)
    analyze(scan_id, tmp_path, registry)  # e.g. a retried task

    runs = runs_by_name(scan_id)
    assert {r.status for r in runs.values()} == {AnalyzerRunStatus.COMPLETED}
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        assert scan is not None and scan.status is ScanStatus.COMPLETED
        count = len(db.scalars(select(Finding).where(Finding.scan_id == scan_id)).all())
    assert count == 1


def test_every_analyzer_failing_fails_the_scan(database: None, tmp_path: Path) -> None:
    scan_id = create_scan()
    registry = AnalyzerRegistry(
        [
            FakeAnalyzer("a", behavior=raises(AnalysisError("A exited with code 2"))),
            FakeAnalyzer("b", behavior=raises(SandboxTimeoutError("killed"))),
        ]
    )

    with pytest.raises(AnalysisError, match="Every analyzer failed"):
        analyze(scan_id, tmp_path, registry)

    assert {r.status for r in runs_by_name(scan_id).values()} == {
        AnalyzerRunStatus.FAILED,
        AnalyzerRunStatus.TIMED_OUT,
    }


def test_infrastructure_outage_for_every_analyzer_is_retryable(
    database: None, tmp_path: Path
) -> None:
    scan_id = create_scan()
    registry = AnalyzerRegistry(
        [
            FakeAnalyzer("a", behavior=raises(SandboxUnavailableError("daemon down"))),
            FakeAnalyzer("b", behavior=raises(AnalysisError("B crashed"))),
        ]
    )

    with pytest.raises(TransientInfraError, match="No analyzer could run"):
        analyze(scan_id, tmp_path, registry)

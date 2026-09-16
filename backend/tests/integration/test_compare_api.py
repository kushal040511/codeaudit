"""POST /api/scans/compare: new/resolved findings across commits, and the score delta."""

import uuid
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.core.db import SessionLocal
from app.models import (
    AnalyzerRun,
    AnalyzerRunStatus,
    Finding,
    Scan,
    ScanSource,
    ScanStatus,
    Severity,
)
from app.services.scoring.service import rescore_scan

pytestmark = pytest.mark.integration


def make_scan(
    findings: list[tuple[str, Severity, str, int, str | None]],
    sha: str,
    *,
    status: ScanStatus = ScanStatus.COMPLETED,
) -> uuid.UUID:
    with SessionLocal() as db:
        scan = Scan(
            id=uuid.uuid4(),
            status=status,
            source=ScanSource.GITHUB,
            original_filename="o/r",
            repo_owner="o",
            repo_name="r",
            commit_sha=sha,
            source_loc=5000,
            completed_at=datetime.now(UTC),
        )
        db.add(scan)
        db.add(
            AnalyzerRun(
                scan_id=scan.id, analyzer_name="semgrep", status=AnalyzerRunStatus.COMPLETED
            )
        )
        for rule, severity, path, line, snippet in findings:
            db.add(
                Finding(
                    scan_id=scan.id,
                    analyzer="semgrep",
                    rule_id=rule,
                    severity=severity,
                    file_path=path,
                    start_line=line,
                    end_line=line,
                    message=f"{rule} at line {line}",
                    code_snippet=snippet,
                    raw={},
                )
            )
        db.flush()
        rescore_scan(db, scan)
        db.commit()
        return scan.id


def test_compare_matches_findings_across_line_shifts(api: TestClient) -> None:
    base = make_scan(
        [
            ("sqli", Severity.CRITICAL, "app/db.py", 10, 'execute("..." % name)'),
            ("xss", Severity.WARNING, "app/views.py", 5, "render(raw)"),
            ("weak-hash", Severity.ERROR, "app/auth.py", 3, None),
        ],
        "a" * 40,
    )
    head = make_scan(
        [
            # Same issue, moved down 20 lines and re-indented: unchanged.
            ("sqli", Severity.CRITICAL, "app/db.py", 30, 'execute(\n  "..." % name)'),
            # Message embeds the line number, which moved: still unchanged.
            ("weak-hash", Severity.ERROR, "app/auth.py", 9, None),
            # Genuinely new: a second copy of an existing issue, and a new rule.
            ("sqli", Severity.CRITICAL, "app/db.py", 50, 'execute("..." % name)'),
            ("ssrf", Severity.ERROR, "app/fetch.py", 2, "get(url)"),
        ],
        "b" * 40,
    )
    result = api.post(
        "/api/scans/compare", json={"base_scan_id": str(base), "head_scan_id": str(head)}
    )
    assert result.status_code == 200, result.text
    body = result.json()
    assert body["new_count"] == 2 and body["resolved_count"] == 1 and body["unchanged_count"] == 2
    assert body["new_by_severity"]["critical"] == 1 and body["new_by_severity"]["error"] == 1
    assert [f["rule_id"] for f in body["new_findings"]] == ["sqli", "ssrf"]  # most severe first
    assert [f["rule_id"] for f in body["resolved_findings"]] == ["xss"]
    assert body["base"]["commit_sha"] == "a" * 40 and body["head"]["commit_sha"] == "b" * 40
    assert body["comparable"] is True and body["warnings"] == []
    assert body["score_delta"] == pytest.approx(
        body["head"]["score"] - body["base"]["score"], abs=0.01
    )
    assert body["score_delta"] < 0
    security = next(c for c in body["categories"] if c["category"] == "security")
    assert security["delta"] < 0


def test_compare_requires_finished_readable_scans(api: TestClient) -> None:
    done = make_scan([], "c" * 40)
    running = make_scan([], "d" * 40, status=ScanStatus.RUNNING)
    not_ready = api.post(
        "/api/scans/compare", json={"base_scan_id": str(done), "head_scan_id": str(running)}
    )
    assert not_ready.status_code == 409 and not_ready.json()["error"]["code"] == "scan_not_ready"
    missing = api.post(
        "/api/scans/compare", json={"base_scan_id": str(done), "head_scan_id": str(uuid.uuid4())}
    )
    assert missing.status_code == 404

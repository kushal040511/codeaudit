"""End-to-end: upload -> queue -> every sandboxed analyzer -> dedup -> persist -> read API.

CELERY_TASK_ALWAYS_EAGER is set in tests/conftest.py, so the scan task runs
synchronously inside the upload request. The first run downloads the Semgrep
rule packs and the PyPI and npm vulnerability databases (~240 MB).
"""

import io
import uuid
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.db import SessionLocal
from app.models import Finding, Scan, ScanStatus

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).parents[1] / "fixtures"
POLYGLOT_APP = FIXTURES / "polyglot_app"
SQLI_RULE = "python.flask.security.injection.tainted-sql-string.tainted-sql-string"


def zip_directory(directory: Path, top_level: str) -> bytes:
    """Zip like a GitHub "Download ZIP": everything under one top-level folder."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(directory.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                zf.write(path, f"{top_level}/{path.relative_to(directory).as_posix()}")
    return buf.getvalue()


def test_upload_scan_runs_every_analyzer_and_dedupes(client: TestClient) -> None:
    archive = zip_directory(POLYGLOT_APP, "polyglot-app-main")

    response = client.post(
        "/api/scans", files={"file": ("polyglot-app.zip", archive, "application/zip")}
    )

    assert response.status_code == 202, response.text
    scan_id = response.json()["scan_id"]

    scan = client.get(f"/api/scans/{scan_id}").json()
    runs = {run["analyzer"]: run for run in scan["analyzer_runs"]}
    assert scan["status"] == "completed", (scan["error_message"], runs)
    assert sorted(lang["language"] for lang in scan["detected_languages"]) == [
        "javascript",
        "python",
    ]
    assert {name: run["status"] for name, run in runs.items()} == {
        "semgrep": "completed",
        "bandit": "completed",
        "ruff": "completed",
        "dependency": "completed",
    }
    assert all(run["duration_ms"] > 0 and run["warnings"] == [] for run in runs.values())
    assert runs["bandit"]["display_name"] == "Bandit"
    assert runs["bandit"]["finding_count"] == 11
    assert runs["ruff"]["finding_count"] == 2
    assert runs["dependency"]["finding_count"] >= 20  # advisories are added over time
    assert runs["semgrep"]["finding_count"] >= 12
    assert scan["findings_before_dedup"] == sum(run["finding_count"] for run in runs.values())
    assert scan["total_findings"] < scan["findings_before_dedup"]
    assert scan["analyzer_summary"]["completed"] == 4

    with SessionLocal() as db:
        stored = db.scalars(select(Finding).where(Finding.scan_id == uuid.UUID(scan_id))).all()
        db_scan = db.get(Scan, uuid.UUID(scan_id))
        assert db_scan is not None and db_scan.status is ScanStatus.COMPLETED

    sqli = next(f for f in stored if f.rule_id == SQLI_RULE)
    assert sqli.analyzer == "semgrep"
    assert sqli.file_path == "polyglot-app-main/api/app.py"
    assert sqli.start_line == 29
    assert sqli.corroborated_by == ["bandit"]
    assert sqli.code_snippet is not None and "cursor.execute(" in sqli.code_snippet

    js = {f.category for f in stored if f.file_path.endswith("web/server.js")}
    assert {"command-injection", "code-injection", "xss"} <= js

    lodash = next(
        f
        for f in stored
        if f.dependency and f.dependency["package"] == "lodash" and f.rule_id == "CVE-2021-23337"
    )
    assert lodash.file_path == "polyglot-app-main/web/package-lock.json"
    assert lodash.dependency is not None and lodash.dependency["fixed_version"] == "4.18.0"
    assert lodash.code_snippet is not None and "node_modules/lodash" in lodash.code_snippet

    page = client.get(
        f"/api/scans/{scan_id}/findings",
        params={"analyzer": "bandit", "severity": ["error", "critical"], "page_size": 50},
    ).json()
    assert page["total"] >= 4
    assert all("bandit" in (item["analyzer"], *item["corroborated_by"]) for item in page["items"])


def test_rejects_zip_slip_upload(client: TestClient) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("repo/app.py", "print('ok')\n")
        zf.writestr("../../etc/cron.d/evil", "* * * * * root id\n")

    response = client.post(
        "/api/scans", files={"file": ("evil.zip", buf.getvalue(), "application/zip")}
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_archive"


def test_unknown_scan_returns_404_error_shape(client: TestClient) -> None:
    missing = uuid.uuid4()

    for path in (f"/api/scans/{missing}", f"/api/scans/{missing}/findings"):
        response = client.get(path)
        assert response.status_code == 404
        assert response.json() == {
            "error": {"code": "not_found", "message": f"Scan {missing} not found."}
        }

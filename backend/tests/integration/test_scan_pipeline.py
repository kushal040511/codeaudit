"""End-to-end: upload -> queue -> sandboxed Semgrep -> persist -> read API.

CELERY_TASK_ALWAYS_EAGER is set in tests/conftest.py, so the scan task runs
synchronously inside the upload request.
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

VULNERABLE_APP = Path(__file__).parents[1] / "fixtures" / "vulnerable_flask_app"
SQLI_RULE = "python.flask.security.injection.tainted-sql-string.tainted-sql-string"
SECRET_KEY_RULE = "python.flask.security.audit.hardcoded-config.avoid_hardcoded_config_SECRET_KEY"


def zip_directory(directory: Path, top_level: str) -> bytes:
    """Zip like a GitHub "Download ZIP": everything under one top-level folder."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(directory.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                zf.write(path, f"{top_level}/{path.relative_to(directory).as_posix()}")
    return buf.getvalue()


def test_upload_scan_persists_semgrep_findings(client: TestClient) -> None:
    archive = zip_directory(VULNERABLE_APP, "vulnerable-flask-app-main")

    response = client.post(
        "/api/scans",
        files={"file": ("vulnerable-flask-app.zip", archive, "application/zip")},
    )

    assert response.status_code == 202, response.text
    scan_id = response.json()["scan_id"]

    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "completed", scan["error_message"]
    assert scan["started_at"] and scan["completed_at"]
    assert scan["detected_languages"] == [
        {
            "language": "python",
            "file_count": 1,
            "manifests": ["vulnerable-flask-app-main/requirements.txt"],
        }
    ]
    assert scan["finding_counts"]["error"] >= 3

    with SessionLocal() as db:
        stored = db.scalars(
            select(Finding)
            .where(Finding.scan_id == uuid.UUID(scan_id))
            .order_by(Finding.start_line)
        ).all()
        db_scan = db.get(Scan, uuid.UUID(scan_id))
        assert db_scan is not None and db_scan.status is ScanStatus.COMPLETED

    rule_ids = {f.rule_id for f in stored}
    assert {SQLI_RULE, SECRET_KEY_RULE} <= rule_ids

    sqli = next(f for f in stored if f.rule_id == SQLI_RULE)
    assert sqli.analyzer == "semgrep"
    assert sqli.file_path == "vulnerable-flask-app-main/app.py"
    assert sqli.start_line == 26
    assert sqli.code_snippet is not None and "cursor.execute(" in sqli.code_snippet
    assert sqli.raw["check_id"].endswith(SQLI_RULE)

    page = client.get(
        f"/api/scans/{scan_id}/findings",
        params={"severity": ["error", "critical"], "file_path": "APP.PY", "page_size": 2},
    ).json()
    assert page["total"] == scan["finding_counts"]["error"] + scan["finding_counts"]["critical"]
    assert len(page["items"]) == 2
    assert all(item["severity"] in {"error", "critical"} for item in page["items"])


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

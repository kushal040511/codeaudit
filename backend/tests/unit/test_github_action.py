"""The GitHub Action script (action/codeaudit_action.py), with CodeAudit and GitHub faked."""

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from app.schemas.compare import CompareRead
from app.schemas.scan import ScanRead

ACTION = Path(__file__).parents[3] / "action" / "codeaudit_action.py"
spec = importlib.util.spec_from_file_location("codeaudit_action", ACTION)
assert spec and spec.loader
action = importlib.util.module_from_spec(spec)
sys.modules["codeaudit_action"] = action  # dataclasses resolve annotations through it
spec.loader.exec_module(action)

HEAD, BASE = "h" * 40, "b" * 40
API = "https://codeaudit.test"


def finding(severity: str, rule: str, path: str = "app/x.py") -> dict[str, Any]:
    return {
        "id": 1,
        "analyzer": "semgrep",
        "rule_id": rule,
        "severity": severity,
        "file_path": path,
        "start_line": 3,
        "end_line": 3,
        "message": "Bad | thing\nhere",
        "code_snippet": None,
        "category": None,
        "corroborated_by": [],
        "merged_from": [],
        "dependency": None,
        "score_impact": None,
        "fix_status": None,
        "fix_validation_status": None,
    }


def compare_payload(new_critical: int = 1) -> dict[str, Any]:
    new = [finding("critical", f"sqli-{i}") for i in range(new_critical)] + [
        finding("warning", "xss")
    ]
    side = {
        "status": "completed",
        "repository": "acme/shop",
        "rubric_version": "1.0",
        "incomplete": False,
        "finding_count": 4,
    }
    payload = {
        "base": {
            **side,
            "scan_id": "00000000-0000-0000-0000-00000000000b",
            "commit_sha": BASE,
            "score": 82.0,
            "grade": "B",
        },
        "head": {
            **side,
            "scan_id": "00000000-0000-0000-0000-00000000000a",
            "commit_sha": HEAD,
            "score": 74.5,
            "grade": "C",
        },
        "score_delta": -7.5,
        "comparable": True,
        "warnings": [],
        "categories": [],
        "new_count": len(new),
        "resolved_count": 1,
        "unchanged_count": 3,
        "new_by_severity": {"info": 0, "warning": 1, "error": 0, "critical": new_critical},
        "resolved_by_severity": {"info": 0, "warning": 0, "error": 1, "critical": 0},
        "new_findings": new,
        "resolved_findings": [finding("error", "old")],
    }
    CompareRead.model_validate(payload)  # the fixture matches the real API schema
    return payload


class FakeServers:
    def __init__(self, compare: dict[str, Any], existing: dict[str, str] | None = None) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.compare = compare
        self.existing = existing or {}
        self.polls = 0
        self.comments: list[dict[str, Any]] = [{"id": 5, "body": "unrelated"}]

    def __call__(self, method: str, url: str, token: str, body: Any = None) -> tuple[int, Any]:
        self.calls.append((method, url, body))
        if url.startswith(API):
            assert token == "cat_secret"  # noqa: S105
            path = url[len(API) :]
            if method == "GET" and path.startswith("/api/scans?"):
                sha = path.split("commit_sha=")[1].split("&")[0]
                scan_id = self.existing.get(sha)
                items = [{"id": scan_id, "status": "completed"}] if scan_id else []
                return 200, {"items": items, "total": len(items)}
            if method == "POST" and path == "/api/scans":
                return 202, {"scan_id": f"new-{body['ref'][:1]}", "status": "queued"}
            if method == "GET" and path.startswith("/api/scans/"):
                self.polls += 1
                status = "running" if self.polls <= 2 else "completed"
                scan_id = path.rsplit("/", 1)[1]
                return 200, {
                    "id": scan_id,
                    "status": status,
                    "score": {"overall": 74.5, "grade": "C"},
                    "repository": {"commit_sha": HEAD},
                }
            if method == "POST" and path == "/api/scans/compare":
                return 200, self.compare
        if "api.github.com" in url:
            assert token == "ghs_token"  # noqa: S105
            if method == "GET":
                return 200, self.comments
            if method == "POST":
                self.comments.append({"id": 6, "body": body["body"]})
                return 201, {"id": 6}
            if method == "PATCH":
                comment_id = int(url.rsplit("/", 1)[1])
                next(c for c in self.comments if c["id"] == comment_id)["body"] = body["body"]
                return 200, {}
        raise AssertionError(f"unexpected {method} {url}")


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps({"pull_request": {"number": 12, "head": {"sha": HEAD}, "base": {"sha": BASE}}})
    )
    (tmp_path / "out").write_text("")
    (tmp_path / "summary").write_text("")
    return {
        "CODEAUDIT_API_URL": API + "/",
        "CODEAUDIT_API_TOKEN": "cat_secret",
        "CODEAUDIT_FAIL_UNDER": "",
        "CODEAUDIT_FAIL_ON_NEW_CRITICAL": "false",
        "CODEAUDIT_COMMENT": "true",
        "CODEAUDIT_TIMEOUT_MINUTES": "5",
        "GITHUB_TOKEN": "ghs_token",
        "GITHUB_REPOSITORY": "acme/shop",
        "GITHUB_EVENT_PATH": str(event),
        "GITHUB_OUTPUT": str(tmp_path / "out"),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        "GITHUB_SHA": HEAD,
    }


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(action.time, "sleep", lambda seconds: None)


def outputs(env: dict[str, str]) -> dict[str, str]:
    return dict(line.split("=", 1) for line in Path(env["GITHUB_OUTPUT"]).read_text().splitlines())


def test_pull_request_run_reuses_base_scan_comments_and_passes(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    servers = FakeServers(compare_payload(new_critical=1), existing={BASE: "base-scan"})
    monkeypatch.setattr(action, "request", servers)

    assert action.main(env) == 0

    posted = [c for c in servers.calls if c[0] == "POST" and c[1] == f"{API}/api/scans"]
    assert [c[2] for c in posted] == [{"repo_url": "https://github.com/acme/shop", "ref": HEAD}]
    compare = next(c for c in servers.calls if c[1].endswith("/api/scans/compare"))
    assert compare[2] == {"base_scan_id": "base-scan", "head_scan_id": "new-h"}

    comment = servers.comments[-1]["body"]
    assert comment.startswith(action.MARKER)
    assert "| Base `bbbbbbb` | 82.0 | B | 4 |" in comment
    assert "| This PR `hhhhhhh` | **74.5** | **C** | 4 |" in comment
    assert "Score change: ▼ -7.50" in comment and "2 new · 1 resolved" in comment
    assert "🔴 critical | `app/x.py:3` | Bad \\| thing here (`sqli-0`)" in comment
    assert "[Full report](https://codeaudit.test/scans/new-h)" in comment
    assert outputs(env) == {
        "scan-id": "new-h",
        "score": "74.5",
        "grade": "C",
        "score-delta": "-7.5",
        "new-findings": "2",
        "new-critical": "1",
    }
    assert "::add-mask::cat_secret" in capsys.readouterr().out
    assert "Score change" in Path(env["GITHUB_STEP_SUMMARY"]).read_text()


def test_second_run_updates_the_same_comment_and_gates(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    servers = FakeServers(compare_payload(new_critical=2), existing={BASE: "b1", HEAD: "h1"})
    servers.comments.append({"id": 9, "body": f"{action.MARKER}\nold report"})
    monkeypatch.setattr(action, "request", servers)
    env |= {"CODEAUDIT_FAIL_UNDER": "80", "CODEAUDIT_FAIL_ON_NEW_CRITICAL": "true"}

    assert action.main(env) == 1

    assert not any(c[0] == "POST" and c[1] == f"{API}/api/scans" for c in servers.calls)
    assert [c["id"] for c in servers.comments] == [5, 9]  # updated, not duplicated
    body = servers.comments[1]["body"]
    assert "### ❌ Check failed" in body
    assert "Score 74.5 is below the threshold of 80." in body
    assert "This pull request adds 2 critical findings." in body
    assert "::error::Score 74.5 is below the threshold of 80." in capsys.readouterr().out


def test_configuration_and_api_errors_are_actionable(
    env: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    with pytest.raises(action.ActionError, match="api-token"):
        action.main(env | {"CODEAUDIT_API_TOKEN": ""})
    with pytest.raises(action.ActionError, match="fail-under"):
        action.main(env | {"CODEAUDIT_FAIL_UNDER": "high"})

    def unauthorized(method: str, url: str, token: str, body: Any = None) -> tuple[int, Any]:
        return 401, {"error": {"code": "invalid_token", "message": "Invalid or revoked API token."}}

    monkeypatch.setattr(action, "request", unauthorized)
    with pytest.raises(action.ActionError, match="rejected the API token"):
        action.main(env)

    def failing_scan(method: str, url: str, token: str, body: Any = None) -> tuple[int, Any]:
        if "/api/scans?" in url:
            return 200, {"items": [], "total": 0}
        if method == "POST":
            return 202, {"scan_id": "s1", "status": "queued"}
        return 200, {"id": "s1", "status": "failed", "error_message": "Could not clone."}

    monkeypatch.setattr(action, "request", failing_scan)
    with pytest.raises(action.ActionError, match="Could not clone"):
        action.main(env)


def test_scan_payload_fields_used_by_the_action_exist() -> None:
    fields = ScanRead.model_fields
    assert {"id", "status", "score", "repository", "error_message"} <= set(fields)

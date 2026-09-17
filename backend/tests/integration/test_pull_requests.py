"""Fix pull requests: preview, explicit confirmation, and every failure mode (GitHub faked)."""

import ast
import difflib
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select

from app.core.db import SessionLocal
from app.models import (
    AnalyzerRun,
    AnalyzerRunStatus,
    BreakingRisk,
    Confidence,
    Finding,
    FixStatus,
    FixSuggestion,
    PullRequest,
    PullRequestStatus,
    Scan,
    ScanSource,
    ScanStatus,
    Severity,
    ValidationStatus,
)
from app.services.github.pr_builder import (
    AI_NOTICE,
    PullRequestError,
    create_pull_request_from_preview,
)
from app.services.scoring.service import rescore_scan
from app.workers.tasks import create_pull_request_task
from tests.github_fakes import FakeGitHub, FakeRepo
from tests.integration.conftest import SignedIn, SignIn

pytestmark = pytest.mark.integration

APP = Path(__file__).parents[2] / "app"

DB_PY = """import sqlite3

import yaml


def find_user(conn, name):
    query = "SELECT * FROM users WHERE name = '%s'" % name
    return conn.execute(query).fetchall()


def count_users(conn):
    return conn.execute("SELECT count(*) FROM users").fetchone()[0]


def audit_log(conn):
    return conn.execute("SELECT * FROM audit").fetchall()


def load_config(path):
    with open(path) as fh:
        return yaml.load(fh)
"""
VIEWS_PY = """import subprocess


def run(cmd):
    return subprocess.call(cmd, shell=True)
"""


def patch(path: str, before: str, old: str, new: str) -> str:
    after = before.replace(old, new)
    assert after != before
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            f"a/{path}",
            f"b/{path}",
        )
    )


SQLI_FIX = patch(
    "app/db.py",
    DB_PY,
    """    query = "SELECT * FROM users WHERE name = '%s'" % name
    return conn.execute(query).fetchall()""",
    """    return conn.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall()""",
)
YAML_FIX = patch("app/db.py", DB_PY, "yaml.load(fh)", "yaml.safe_load(fh)")
SHELL_FIX = patch(
    "app/views.py", VIEWS_PY, "subprocess.call(cmd, shell=True)", "subprocess.call(cmd)"
)
# A competing fix for the same lines as SQLI_FIX.
SQLI_ALTERNATIVE = patch(
    "app/db.py",
    DB_PY,
    """    query = "SELECT * FROM users WHERE name = '%s'" % name""",
    """    query = "SELECT * FROM users WHERE name = %s" """,
)


@dataclass
class Scenario:
    owner: SignedIn
    repo: FakeRepo
    scan_id: uuid.UUID
    suggestions: dict[str, int]  # name -> suggestion id
    findings: dict[str, int]
    base_sha: str


def seed(
    sign_in: Any,
    fake: FakeGitHub,
    *,
    login: str = "maintainer",
    repo_owner: str | None = None,
    **repo_options: Any,
) -> Scenario:
    owner: SignedIn = sign_in(login)
    repo = fake.add_repo(
        repo_owner or login,
        "shop",
        {"app/db.py": DB_PY, "app/views.py": VIEWS_PY, "README.md": "# shop\n"},
        **repo_options,
    )
    base_sha = repo.branches["main"]
    specs = {
        "sqli": (
            "semgrep",
            "python.sqli",
            Severity.CRITICAL,
            "app/db.py",
            8,
            SQLI_FIX,
            ValidationStatus.VALID,
        ),
        "yaml": (
            "bandit",
            "B506",
            Severity.ERROR,
            "app/db.py",
            22,
            YAML_FIX,
            ValidationStatus.VALID,
        ),
        "shell": (
            "bandit",
            "B602",
            Severity.ERROR,
            "app/views.py",
            5,
            SHELL_FIX,
            ValidationStatus.VALID,
        ),
        "broken": (
            "semgrep",
            "python.weak-hash",
            Severity.WARNING,
            "app/views.py",
            1,
            "--- a/app/views.py\n",
            ValidationStatus.FAILED_TO_APPLY,
        ),
        "sqli_alt": (
            "semgrep",
            "python.sqli-format",
            Severity.ERROR,
            "app/db.py",
            7,
            SQLI_ALTERNATIVE,
            ValidationStatus.VALID,
        ),
    }
    with SessionLocal() as db:
        scan = Scan(
            id=uuid.uuid4(),
            status=ScanStatus.COMPLETED,
            source=ScanSource.GITHUB,
            user_id=owner.user_id,
            original_filename=f"{repo.full_name}@main",
            repo_owner=repo.owner,
            repo_name=repo.name,
            repo_ref="main",
            repo_default_branch="main",
            commit_sha=base_sha,
            repo_private=False,
            source_loc=40,
            completed_at=datetime.now(UTC),
        )
        db.add(scan)
        for analyzer in ("semgrep", "bandit"):
            db.add(
                AnalyzerRun(
                    scan_id=scan.id, analyzer_name=analyzer, status=AnalyzerRunStatus.COMPLETED
                )
            )
        findings: dict[str, Finding] = {}
        for name, (analyzer, rule, severity, path, line, _, _) in specs.items():
            findings[name] = Finding(
                scan_id=scan.id,
                analyzer=analyzer,
                rule_id=rule,
                severity=severity,
                file_path=path,
                start_line=line,
                end_line=line,
                message=f"{rule} issue",
                raw={},
            )
            db.add(findings[name])
        db.flush()
        suggestions: dict[str, FixSuggestion] = {}
        for name, (_, _, _, _, _, diff, validation) in specs.items():
            suggestions[name] = FixSuggestion(
                scan_id=scan.id,
                finding_id=findings[name].id,
                status=FixStatus.READY,
                validation_status=validation,
                explanation=f"Explanation for {name}.",
                confidence=Confidence.HIGH,
                breaking_risk=BreakingRisk.LOW,
                test_suggestion=f"Test {name}.",
                patch=diff,
            )
            db.add(suggestions[name])
        db.flush()
        rescore_scan(db, scan)
        db.commit()
        return Scenario(
            owner,
            repo,
            scan.id,
            {name: s.id for name, s in suggestions.items()},
            {name: f.id for name, f in findings.items()},
            base_sha,
        )


def preview(user: SignedIn, scenario: Scenario, names: list[str], **options: Any) -> Any:
    return user.client.post(
        f"/api/scans/{scenario.scan_id}/pull-requests/preview",
        json={"suggestion_ids": [scenario.suggestions[n] for n in names], **options},
        headers=user.headers,
    )


def confirm(user: SignedIn, pr_id: int, **body: Any) -> Any:
    return user.client.post(
        f"/api/pull-requests/{pr_id}/confirm", json={"confirm": True, **body}, headers=user.headers
    )


def test_fix_candidates_are_only_verified_patches(sign_in: SignIn, fake_github: FakeGitHub) -> None:
    scenario = seed(sign_in, fake_github)
    candidates = scenario.owner.client.get(f"/api/scans/{scenario.scan_id}/fixes").json()
    ids = {c["suggestion_id"] for c in candidates}
    assert scenario.suggestions["broken"] not in ids
    assert ids == {scenario.suggestions[n] for n in ("sqli", "yaml", "shell", "sqli_alt")}
    assert candidates[0]["severity"] == "critical"  # highest impact first


def test_preview_shows_exact_change_and_writes_nothing(
    sign_in: SignIn, fake_github: FakeGitHub
) -> None:
    scenario = seed(sign_in, fake_github)
    response = preview(scenario.owner, scenario, ["sqli", "yaml", "shell", "broken"])
    assert response.status_code == 201, response.text
    plan = response.json()

    assert fake_github.writes() == []
    assert plan["status"] == "previewed"
    assert plan["writes_to"] == "maintainer/shop" and plan["repo_full_name"] == "maintainer/shop"
    assert plan["base_branch"] == "main" and plan["base_sha"] == scenario.base_sha
    assert plan["head_moved"] is False and plan["blocking"] == []
    assert plan["branch"] == f"codeaudit/fix-{scenario.scan_id.hex[:8]}"
    assert plan["excluded"] == [
        {
            "suggestion_id": scenario.suggestions["broken"],
            "reason": "patch not verified (failed_to_apply); only verified patches can be included",
        }
    ]
    assert sorted(plan["included_suggestion_ids"]) == sorted(
        scenario.suggestions[n] for n in ("sqli", "yaml", "shell")
    )
    assert [c["message"].split("\n")[0] for c in plan["planned_commits"]] == [
        "fix(security): address sqli in app/db.py",
        "fix(security): address B506 in app/db.py",
        "fix(security): address B602 in app/views.py",
    ]

    files = {f["path"]: f for f in plan["files"]}
    assert set(files) == {"app/db.py", "app/views.py"}
    assert (
        "safe_load" in files["app/db.py"]["patched"] and "name = ?" in files["app/db.py"]["patched"]
    )
    assert files["app/views.py"]["patched"] == VIEWS_PY.replace(", shell=True", "")
    for f in files.values():
        ast.parse(f["patched"])
    diff = plan["combined_diff"]
    assert "--- a/app/db.py" in diff and "+++ b/app/views.py" in diff
    assert "-        return yaml.load(fh)" in diff and "+        return yaml.safe_load(fh)" in diff

    body = plan["body"]
    assert AI_NOTICE in body
    assert "| critical | 1 |" in body and "| error | 2 |" in body
    assert plan["score"]["projected"] > plan["score"]["current"]
    assert (
        f"**{plan['score']['current']:.1f}**" in body
        and f"{plan['score']['delta']:+.2f} points" in body
    )
    assert "Explanation for sqli." in body and "Suggested regression test: Test yaml." in body
    assert "Confidence: high · Breaking risk: low" in body
    assert "patch not verified" in body  # excluded suggestion is reported

    # Previews aren't listed as pull requests.
    assert scenario.owner.client.get(f"/api/scans/{scenario.scan_id}/pull-requests").json() == []


def test_no_pull_request_without_explicit_confirmation(
    sign_in: SignIn, fake_github: FakeGitHub
) -> None:
    scenario = seed(sign_in, fake_github)
    pr_id = preview(scenario.owner, scenario, ["sqli"]).json()["id"]
    user = scenario.owner
    url = f"/api/pull-requests/{pr_id}/confirm"

    for body in ({}, {"confirm": False}, {"confirm": "yes"}, {"confirm": None}, {"title": "x"}):
        assert user.client.post(url, json=body, headers=user.headers).status_code == 422, body
    assert user.client.post(url, json={"confirm": True}).status_code == 403  # no CSRF token

    # The public id is a UUID; the job takes the internal row id.
    with SessionLocal() as db:
        internal_id = db.scalar(
            select(PullRequest.id).where(PullRequest.public_id == uuid.UUID(pr_id))
        )
    assert isinstance(internal_id, int)
    # Running the job or the builder directly on an unconfirmed preview does nothing.
    assert create_pull_request_task.run(internal_id)["status"] == "skipped"
    with SessionLocal() as db:
        row = db.get(PullRequest, internal_id)
        scan = db.get(Scan, scenario.scan_id)
        assert row is not None and scan is not None and row.status is PullRequestStatus.PREVIEWED
        from app.models import User

        owner = db.get(User, scenario.owner.user_id)
        assert owner is not None
        with pytest.raises(PullRequestError) as info:
            create_pull_request_from_preview(db, row, scan, owner)
        assert info.value.code == "not_confirmed"

    assert fake_github.writes() == []
    assert scenario.repo.pulls == [] and set(scenario.repo.branches) == {"main"}


def test_only_the_confirm_endpoint_can_start_pull_request_creation() -> None:
    """Static guard: nothing else (scan pipeline, enrichment, other routes) queues the job."""
    callers: dict[str, list[str]] = {
        "create_pull_request_task": [],
        "create_pull_request_from_preview": [],
    }
    for path in APP.rglob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
                target = func.value if isinstance(func, ast.Attribute) else None
                if name in ("delay", "apply_async", "s", "si", "signature") and isinstance(
                    target, ast.Name
                ):
                    name = target.id
                if name in callers:
                    callers[name].append(path.relative_to(APP).as_posix())
    assert callers == {
        "create_pull_request_task": ["api/routes/pull_requests.py"],
        "create_pull_request_from_preview": ["workers/tasks.py"],
    }


def test_confirm_creates_branch_one_commit_per_fix_and_pull_request(
    sign_in: SignIn, fake_github: FakeGitHub, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    scenario = seed(sign_in, fake_github)
    plan = preview(scenario.owner, scenario, ["sqli", "yaml", "shell"]).json()
    edited_body = "My own description."
    response = confirm(scenario.owner, plan["id"], title="Fix security issues", body=edited_body)
    assert response.status_code == 202, response.text

    pr = scenario.owner.client.get(f"/api/pull-requests/{plan['id']}").json()
    assert pr["status"] == "open", pr
    assert pr["pr_number"] == 1 and pr["pr_url"] == "https://github.com/maintainer/shop/pull/1"
    assert pr["confirmed_at"] is not None

    github_pr = scenario.repo.pulls[0]
    assert github_pr["title"] == "Fix security issues"
    assert github_pr["head"] == plan["branch"] and github_pr["base"] == "main"
    # The AI-generated warning can't be edited away.
    assert github_pr["body"].startswith(AI_NOTICE) and edited_body in github_pr["body"]

    # Branch -> three commits, each on top of the previous, rooted at the scanned commit.
    head = scenario.repo.branches[plan["branch"]]
    chain = []
    sha = head
    while sha != scenario.base_sha:
        chain.append(fake_github.commits[sha])
        sha = fake_github.commits[sha]["parents"][0]
    assert len(chain) == 3 == len(pr["commits"])
    assert [c["sha"] for c in pr["commits"]][-1] == head
    assert [c["message"].split("\n")[0] for c in reversed(chain)] == [
        c["message"] for c in pr["commits"]
    ]
    assert all(f"CodeAudit-Scan: {scenario.scan_id}" in c["message"] for c in chain)

    final = fake_github.files_at(head)
    assert final["app/db.py"] == {f["path"]: f for f in plan["files"]}["app/db.py"]["patched"]
    assert final["app/views.py"] == VIEWS_PY.replace(", shell=True", "")
    assert final["README.md"] == "# shop\n"
    # The first commit contains only the first fix.
    first = fake_github.files_at([c["sha"] for c in pr["commits"]][0])
    assert "name = ?" in first["app/db.py"] and "yaml.load(fh)" in first["app/db.py"]
    assert first["app/views.py"] == VIEWS_PY

    assert scenario.repo.branches["main"] == scenario.base_sha  # base untouched
    again = confirm(scenario.owner, plan["id"])
    assert again.status_code == 409 and again.json()["error"]["code"] == "already_confirmed"
    listed = scenario.owner.client.get(f"/api/scans/{scenario.scan_id}/pull-requests").json()
    assert [p["id"] for p in listed] == [plan["id"]]
    # The token was used for every write but never logged or returned.
    assert all(
        r.headers["authorization"] == f"Bearer {scenario.owner.token}"
        for r in fake_github.requests
        if r.method == "POST"
    )
    assert scenario.owner.token not in caplog.text
    assert scenario.owner.token not in str(listed) and scenario.owner.token not in str(pr)


def test_moved_head_revalidates_and_reports_patches_that_no_longer_apply(
    sign_in: SignIn, fake_github: FakeGitHub
) -> None:
    scenario = seed(sign_in, fake_github)
    # Someone rewrites load_config after the scan, and adds an unrelated line elsewhere.
    new_head = fake_github.push(
        scenario.repo,
        "main",
        {
            "app/db.py": DB_PY.replace(
                "    with open(path) as fh:\n        return yaml.load(fh)",
                "    return yaml.load(open(path))",
            ).replace("import sqlite3\n", "import sqlite3\nimport logging\n"),
        },
        "refactor",
    )
    plan = preview(scenario.owner, scenario, ["sqli", "yaml", "shell"]).json()
    assert plan["head_moved"] is True
    assert plan["scanned_sha"] == scenario.base_sha and plan["base_sha"] == new_head
    checks = {tuple(c["suggestion_ids"]): c for c in plan["patch_checks"]}
    assert checks[(scenario.suggestions["sqli"],)]["status"] == "applies"  # shifted, still applies
    assert checks[(scenario.suggestions["shell"],)]["status"] == "applies"
    stale = checks[(scenario.suggestions["yaml"],)]
    assert stale["status"] == "no_longer_applies" and stale["detail"]
    assert scenario.suggestions["yaml"] not in plan["included_suggestion_ids"]
    assert "base branch has moved" in plan["body"] and "no longer applies" in plan["body"]
    db_file = {f["path"]: f for f in plan["files"]}["app/db.py"]
    assert "import logging" in db_file["patched"] and "name = ?" in db_file["patched"]

    # Nothing applies at all: blocked with a stale-head error.
    only_stale = preview(scenario.owner, scenario, ["yaml"]).json()
    assert only_stale["blocking"][0]["code"] == "stale_head"
    assert fake_github.writes() == []


def test_confirmation_is_refused_if_the_repository_moved_after_preview(
    sign_in: SignIn, fake_github: FakeGitHub
) -> None:
    scenario = seed(sign_in, fake_github)
    plan = preview(scenario.owner, scenario, ["sqli", "shell"]).json()
    fake_github.push(scenario.repo, "main", {"README.md": "# shop v2\n"}, "docs")
    confirm(scenario.owner, plan["id"])
    pr = scenario.owner.client.get(f"/api/pull-requests/{plan['id']}").json()
    assert pr["status"] == "failed" and pr["error_code"] == "preview_outdated"
    assert "Open a new preview" in pr["error_message"]
    assert fake_github.writes() == [] and scenario.repo.pulls == []


def test_selected_fixes_that_conflict_with_each_other(
    sign_in: SignIn, fake_github: FakeGitHub
) -> None:
    scenario = seed(sign_in, fake_github)
    plan = preview(scenario.owner, scenario, ["sqli", "sqli_alt"]).json()
    statuses = {tuple(c["suggestion_ids"]): c["status"] for c in plan["patch_checks"]}
    assert statuses[(scenario.suggestions["sqli"],)] == "applies"
    assert statuses[(scenario.suggestions["sqli_alt"],)] == "conflicts"
    assert plan["included_suggestion_ids"] == [scenario.suggestions["sqli"]]


def test_without_push_access_a_fork_is_required_and_used(
    sign_in: SignIn, fake_github: FakeGitHub, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.github import pr_builder

    naps: list[float] = []
    monkeypatch.setattr(pr_builder.time, "sleep", naps.append)
    # The contributor scanned someone else's public repository.
    scenario = seed(sign_in, fake_github, login="contributor", repo_owner="upstream")
    user = scenario.owner

    direct = preview(user, scenario, ["sqli"]).json()
    assert direct["can_push"] is False and direct["requires_fork"] is True
    assert direct["blocking"] == [
        {
            "code": "fork_required",
            "message": "Your GitHub account (contributor) can't push to upstream/shop."
            " Confirm opening the pull request from a fork.",
        }
    ]
    confirm(user, direct["id"])
    failed = user.client.get(f"/api/pull-requests/{direct['id']}").json()
    assert failed["status"] == "failed" and failed["error_code"] == "fork_required"
    assert fake_github.writes() == []

    forked = preview(user, scenario, ["sqli", "shell"], use_fork=True).json()
    assert forked["blocking"] == [] and forked["writes_to"] == "contributor/shop"
    assert fake_github.writes() == []  # the fork isn't created by previewing
    fake_github.fork_delay_polls = 2  # GitHub creates forks asynchronously

    confirm(user, forked["id"])
    pr = user.client.get(f"/api/pull-requests/{forked['id']}").json()
    assert pr["status"] == "open", pr
    assert len(naps) == 2  # waited for the fork to become ready
    fork = fake_github.repos["contributor/shop"]
    assert fork.fork and forked["branch"] in fork.branches
    assert forked["branch"] not in scenario.repo.branches
    assert scenario.repo.pulls[0]["head"] == f"contributor:{forked['branch']}"
    assert pr["pr_url"] == "https://github.com/upstream/shop/pull/1"
    writes = fake_github.writes()
    assert writes[0] == "POST /repos/upstream/shop/forks"
    assert all(w.startswith("POST /repos/contributor/shop/") for w in writes[1:-1])
    assert writes[-1] == "POST /repos/upstream/shop/pulls"


def test_write_refused_by_github_is_insufficient_permissions(
    sign_in: SignIn, fake_github: FakeGitHub
) -> None:
    scenario = seed(sign_in, fake_github)
    plan = preview(scenario.owner, scenario, ["sqli"]).json()
    fake_github.write_denied.add("maintainer")
    confirm(scenario.owner, plan["id"])
    pr = scenario.owner.client.get(f"/api/pull-requests/{plan['id']}").json()
    assert pr["status"] == "failed" and pr["error_code"] == "insufficient_permissions"
    assert "fork" in pr["error_message"]
    assert scenario.owner.token not in str(pr)


def test_branch_name_collisions(sign_in: SignIn, fake_github: FakeGitHub) -> None:
    scenario = seed(sign_in, fake_github)
    default = f"codeaudit/fix-{scenario.scan_id.hex[:8]}"
    scenario.repo.branches[default] = scenario.base_sha

    taken = preview(scenario.owner, scenario, ["sqli"]).json()
    assert taken["branch_available"] is False and taken["suggested_branch"] == f"{default}-2"
    assert taken["blocking"][0]["code"] == "branch_exists"

    free = preview(scenario.owner, scenario, ["sqli"], branch=taken["suggested_branch"]).json()
    assert free["blocking"] == []
    # Someone creates the branch between preview and confirmation.
    scenario.repo.branches[free["branch"]] = scenario.base_sha
    confirm(scenario.owner, free["id"])
    pr = scenario.owner.client.get(f"/api/pull-requests/{free['id']}").json()
    assert pr["status"] == "failed" and pr["error_code"] == "branch_exists"
    assert scenario.repo.pulls == []

    invalid = preview(scenario.owner, scenario, ["sqli"], branch="../main")
    assert invalid.status_code == 422


def test_protected_branch_rules(sign_in: SignIn, fake_github: FakeGitHub) -> None:
    scenario = seed(sign_in, fake_github, protected_patterns=["codeaudit/*"])
    plan = preview(scenario.owner, scenario, ["sqli"]).json()
    confirm(scenario.owner, plan["id"])
    pr = scenario.owner.client.get(f"/api/pull-requests/{plan['id']}").json()
    assert pr["status"] == "failed" and pr["error_code"] == "branch_protected"
    assert "protection rule" in pr["error_message"]
    assert scenario.repo.pulls == []


def test_ownership_is_enforced_everywhere(sign_in: SignIn, fake_github: FakeGitHub) -> None:
    scenario = seed(sign_in, fake_github)
    plan = preview(scenario.owner, scenario, ["sqli"]).json()
    intruder: SignedIn = sign_in("intruder")

    assert preview(intruder, scenario, ["sqli"]).status_code == 404
    assert confirm(intruder, plan["id"]).status_code == 404
    assert intruder.client.get(f"/api/pull-requests/{plan['id']}").status_code == 404
    assert intruder.client.get(f"/api/scans/{scenario.scan_id}/pull-requests").status_code == 404
    assert intruder.client.get(f"/api/scans/{scenario.scan_id}/fixes").status_code == 404

    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as anonymous:
        url = f"/api/scans/{scenario.scan_id}/pull-requests/preview"
        assert anonymous.post(url, json={"suggestion_ids": [1]}).status_code == 401
        assert (
            anonymous.post(
                f"/api/pull-requests/{plan['id']}/confirm", json={"confirm": True}
            ).status_code
            == 401
        )

    # Suggestions from another scan can't be smuggled into a preview.
    other = seed(sign_in, fake_github, login="other-owner")
    mixed = scenario.owner.client.post(
        f"/api/scans/{scenario.scan_id}/pull-requests/preview",
        json={"suggestion_ids": [other.suggestions["sqli"], scenario.suggestions["shell"]]},
        headers=scenario.owner.headers,
    ).json()
    assert mixed["included_suggestion_ids"] == [scenario.suggestions["shell"]]
    assert mixed["excluded"] == [
        {"suggestion_id": other.suggestions["sqli"], "reason": "not a suggestion of this scan"}
    ]

    with SessionLocal() as db:
        rows = db.scalars(select(PullRequest).where(PullRequest.user_id == intruder.user_id)).all()
        assert rows == []
    assert fake_github.writes() == []


def test_no_verified_suggestions(sign_in: SignIn, fake_github: FakeGitHub) -> None:
    scenario = seed(sign_in, fake_github)
    response = preview(scenario.owner, scenario, ["broken"])
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "no_valid_suggestions"

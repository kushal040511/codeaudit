"""CodeAudit GitHub Action: scan a pull request, compare with its base, comment and gate.

Standard library only (runs on any GitHub-hosted runner with python3). Reads its
configuration from environment variables set by action.yml and the GitHub event
payload from $GITHUB_EVENT_PATH.

Flow on pull_request events:
  1. Reuse a finished scan of the head commit if one exists, otherwise submit one.
  2. Same for the base commit.
  3. Wait for both, then POST /api/scans/compare.
  4. Create or update one comment on the pull request (found by a hidden marker).
  5. Set outputs and fail if the score is under `fail-under` or, when enabled,
     the pull request adds critical findings.

On other events (push, workflow_dispatch) only the current commit is scanned.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

MARKER = "<!-- codeaudit-report -->"
RESULT_STATUSES = {"analysis_complete", "enriching", "completed", "partial"}
SEVERITY_ICONS = {"critical": "🔴", "error": "🟠", "warning": "🟡", "info": "🔵"}
MAX_LISTED = 15
POLL_SECONDS = 10


class ActionError(Exception):
    """A failure to report with ::error:: and exit 1."""


@dataclass
class Config:
    api_url: str
    api_token: str
    frontend_url: str
    github_token: str
    github_api_url: str
    repository: str
    fail_under: float | None
    fail_on_new_critical: bool
    comment: bool
    timeout_seconds: int

    @classmethod
    def from_env(cls, env: dict[str, str]) -> Config:
        api_url = env.get("CODEAUDIT_API_URL", "").rstrip("/")
        token = env.get("CODEAUDIT_API_TOKEN", "")
        if not api_url.startswith(("https://", "http://")):
            raise ActionError("`api-url` must be the http(s) URL of your CodeAudit server.")
        if not token:
            raise ActionError("`api-token` is empty. Add a CodeAudit API token as a secret.")
        fail_under = env.get("CODEAUDIT_FAIL_UNDER", "").strip()
        try:
            threshold = float(fail_under) if fail_under else None
        except ValueError:
            raise ActionError(f"`fail-under` must be a number, got {fail_under!r}.") from None
        return cls(
            api_url=api_url,
            api_token=token,
            frontend_url=(env.get("CODEAUDIT_FRONTEND_URL") or api_url).rstrip("/"),
            github_token=env.get("GITHUB_TOKEN", ""),
            github_api_url=env.get("GITHUB_API_URL", "https://api.github.com").rstrip("/"),
            repository=env["GITHUB_REPOSITORY"],
            fail_under=threshold,
            fail_on_new_critical=env.get("CODEAUDIT_FAIL_ON_NEW_CRITICAL", "false").lower()
            == "true",
            comment=env.get("CODEAUDIT_COMMENT", "true").lower() == "true",
            timeout_seconds=int(float(env.get("CODEAUDIT_TIMEOUT_MINUTES") or 30) * 60),
        )


# ---------------------------------------------------------------------------- HTTP


def request(
    method: str, url: str, token: str, body: dict[str, Any] | None = None
) -> tuple[int, Any]:
    # urllib also opens file:// and custom schemes; only ever talk HTTP(S).
    if not url.startswith(("https://", "http://")):
        raise ActionError(f"Refusing to request a non-HTTP URL: {url.split(':', 1)[0]}:")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)  # noqa: S310 - checked above
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", "codeaudit-action")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as response:  # noqa: S310
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            payload = {"error": {"message": raw[:300].decode(errors="replace")}}
        return exc.code, payload
    except urllib.error.URLError as exc:
        raise ActionError(
            f"Could not reach {urllib.parse.urlsplit(url).netloc}: {exc.reason}"
        ) from None


def api_error(status: int, payload: Any) -> str:
    error = (payload or {}).get("error") if isinstance(payload, dict) else None
    if isinstance(error, dict):
        return f"{error.get('message')} ({error.get('code')}, HTTP {status})"
    return f"HTTP {status}"


class CodeAudit:
    def __init__(self, config: Config) -> None:
        self.config = config

    def call(self, method: str, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        return request(method, f"{self.config.api_url}/api{path}", self.config.api_token, body)

    def find_scan(self, sha: str) -> dict[str, Any] | None:
        status, payload = self.call(
            "GET",
            "/scans?"
            + urllib.parse.urlencode(
                {"repo": self.config.repository, "commit_sha": sha, "limit": 20}
            ),
        )
        if status == 401:
            raise ActionError("CodeAudit rejected the API token (revoked or mistyped).")
        if status != 200:
            raise ActionError(f"Looking up scans failed: {api_error(status, payload)}")
        for item in payload["items"]:  # newest first
            if item["status"] != "failed":
                return dict(item)
        return None

    def ensure_scan(self, sha: str, label: str) -> str:
        existing = self.find_scan(sha)
        if existing:
            print(f"Reusing {label} scan {existing['id']} of {sha[:12]} ({existing['status']}).")
            return str(existing["id"])
        status, payload = self.call(
            "POST",
            "/scans",
            {"repo_url": f"https://github.com/{self.config.repository}", "ref": sha},
        )
        if status == 429:
            raise ActionError(f"Rate limited: {api_error(status, payload)}")
        if status != 202:
            raise ActionError(f"Submitting the {label} scan failed: {api_error(status, payload)}")
        print(f"Submitted {label} scan {payload['scan_id']} of {sha[:12]}.")
        return str(payload["scan_id"])

    def wait(self, scan_ids: list[str]) -> dict[str, dict[str, Any]]:
        deadline = time.monotonic() + self.config.timeout_seconds
        done: dict[str, dict[str, Any]] = {}
        while True:
            for scan_id in scan_ids:
                if scan_id in done:
                    continue
                status, payload = self.call("GET", f"/scans/{scan_id}")
                if status != 200:
                    raise ActionError(
                        f"Reading scan {scan_id} failed: {api_error(status, payload)}"
                    )
                if payload["status"] == "failed":
                    raise ActionError(
                        f"Scan {scan_id} failed: {payload.get('error_message') or 'unknown error'}"
                    )
                if payload["status"] in RESULT_STATUSES:
                    done[scan_id] = payload
            if len(done) == len(scan_ids):
                return done
            if time.monotonic() > deadline:
                raise ActionError(
                    f"Scans didn't finish within {self.config.timeout_seconds // 60} minutes."
                )
            time.sleep(POLL_SECONDS)


# ---------------------------------------------------------------------------- report


def fmt_score(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.1f}"


def fmt_delta(value: float | None) -> str:
    if value is None:
        return "n/a"
    arrow = "▲" if value > 0 else "▼" if value < 0 else "●"
    return f"{arrow} {value:+.2f}"


def gate(config: Config, head_score: float | None, new_critical: int) -> list[str]:
    """Reasons to fail the check (empty: pass)."""
    reasons = []
    if config.fail_under is not None:
        if head_score is None:
            reasons.append(
                f"No score was computed, so `fail-under: {config.fail_under:g}` can't pass."
            )
        elif head_score < config.fail_under:
            reasons.append(
                f"Score {head_score:.1f} is below the threshold of {config.fail_under:g}."
            )
    if config.fail_on_new_critical and new_critical > 0:
        reasons.append(
            f"This pull request adds {new_critical} critical finding{'s' if new_critical != 1 else ''}."
        )
    return reasons


def render_comment(
    config: Config,
    head: dict[str, Any],
    comparison: dict[str, Any] | None,
    failures: list[str],
) -> str:
    score = head.get("score") or {}
    link = f"{config.frontend_url}/scans/{head['id']}"
    lines = [MARKER, "## CodeAudit", ""]
    if comparison is None:
        lines.append(
            f"**Score {fmt_score(score.get('overall'))}** ({score.get('grade') or 'n/a'})"
            f" for `{(head.get('repository') or {}).get('commit_sha', '')[:12]}`"
        )
    else:
        base, new = comparison["base"], comparison["head"]
        lines += [
            "| | Score | Grade | Findings |",
            "|---|---|---|---|",
            f"| Base `{(base['commit_sha'] or '')[:7]}` | {fmt_score(base['score'])} | {base['grade'] or 'n/a'} | {base['finding_count']} |",
            f"| This PR `{(new['commit_sha'] or '')[:7]}` | **{fmt_score(new['score'])}** | **{new['grade'] or 'n/a'}** | {new['finding_count']} |",
            "",
            f"**Score change: {fmt_delta(comparison['score_delta'])}** · "
            f"{comparison['new_count']} new · {comparison['resolved_count']} resolved",
        ]
        if not comparison["comparable"]:
            lines += ["", "> [!NOTE]", *[f"> {w}" for w in comparison["warnings"]]]
        new_findings = comparison["new_findings"]
        if new_findings:
            lines += [
                "",
                "### New findings",
                "",
                "| Severity | Location | Issue |",
                "|---|---|---|",
            ]
            for finding in new_findings[:MAX_LISTED]:
                icon = SEVERITY_ICONS.get(finding["severity"], "")
                message = finding["message"].replace("|", "\\|").replace("\n", " ")[:140]
                lines.append(
                    f"| {icon} {finding['severity']} | `{finding['file_path']}:{finding['start_line']}` | {message} (`{finding['rule_id']}`) |"
                )
            if comparison["new_count"] > MAX_LISTED:
                lines.append(f"\n…and {comparison['new_count'] - MAX_LISTED} more.")
        elif comparison["new_count"] == 0:
            lines += ["", "No new findings. ✅"]
    if failures:
        lines += ["", "### ❌ Check failed", "", *[f"- {reason}" for reason in failures]]
    lines += ["", f"[Full report]({link})"]
    return "\n".join(lines)


def upsert_comment(config: Config, pr_number: int, body: str) -> None:
    if not config.github_token:
        print("::warning::No github-token; skipping the pull request comment.")
        return
    base = f"{config.github_api_url}/repos/{config.repository}/issues/{pr_number}/comments"
    existing = None
    page = 1
    while existing is None:
        status, comments = request("GET", f"{base}?per_page=100&page={page}", config.github_token)
        if status != 200:
            print(f"::warning::Couldn't list comments (HTTP {status}); posting a new one.")
            break
        existing = next((c for c in comments if MARKER in (c.get("body") or "")), None)
        if len(comments) < 100:
            break
        page += 1
    if existing:
        url = f"{config.github_api_url}/repos/{config.repository}/issues/comments/{existing['id']}"
        status, payload = request("PATCH", url, config.github_token, {"body": body})
    else:
        status, payload = request("POST", base, config.github_token, {"body": body})
    if status not in (200, 201):
        hint = " Grant the workflow `pull-requests: write`." if status in (403, 404) else ""
        print(f"::warning::Couldn't post the comment (HTTP {status}).{hint}")


def set_outputs(values: dict[str, Any], env: dict[str, str]) -> None:
    path = env.get("GITHUB_OUTPUT")
    lines = [f"{k}={'' if v is None else v}" for k, v in values.items()]
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    else:
        print("\n".join(lines))


def main(env: dict[str, str]) -> int:
    config = Config.from_env(env)
    print(f"::add-mask::{config.api_token}")
    with open(env["GITHUB_EVENT_PATH"], encoding="utf-8") as fh:
        event = json.load(fh)
    pull = event.get("pull_request")
    client = CodeAudit(config)

    if pull:
        head_sha, base_sha = pull["head"]["sha"], pull["base"]["sha"]
        head_id = client.ensure_scan(head_sha, "head")
        base_id = client.ensure_scan(base_sha, "base")
        scans = client.wait([head_id, base_id])
        status, comparison = client.call(
            "POST", "/scans/compare", {"base_scan_id": base_id, "head_scan_id": head_id}
        )
        if status != 200:
            raise ActionError(f"Comparing scans failed: {api_error(status, comparison)}")
    else:
        head_id = client.ensure_scan(env["GITHUB_SHA"], "commit")
        scans = client.wait([head_id])
        comparison = None

    head = scans[head_id]
    head_score = (head.get("score") or {}).get("overall")
    new_critical = comparison["new_by_severity"]["critical"] if comparison else 0
    failures = gate(config, head_score, new_critical)
    report = render_comment(config, head, comparison, failures)

    set_outputs(
        {
            "scan-id": head_id,
            "score": head_score,
            "grade": (head.get("score") or {}).get("grade"),
            "score-delta": comparison["score_delta"] if comparison else None,
            "new-findings": comparison["new_count"] if comparison else None,
            "new-critical": new_critical if comparison else None,
        },
        env,
    )
    if summary := env.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report.replace(MARKER, "") + "\n")
    if pull and config.comment:
        upsert_comment(config, int(pull["number"]), report)

    for reason in failures:
        print(f"::error::{reason}")
    return 1 if failures else 0


if __name__ == "__main__":
    try:
        sys.exit(main(dict(os.environ)))
    except ActionError as exc:
        print(f"::error::{exc}")
        sys.exit(1)

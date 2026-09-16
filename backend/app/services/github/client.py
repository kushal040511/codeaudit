"""Minimal GitHub REST client with explicit, user-facing error types.

Tokens are passed in per call and never appear in exceptions, logs or reprs.
Redirects are not followed (a redirect off api.github.com is never trusted).
"""

import base64
import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

from app.config import get_settings
from app.core.errors import TransientInfraError

logger = logging.getLogger(__name__)

API_VERSION = "2022-11-28"
MAX_ERROR_DETAIL = 300
UNAUTHENTICATED_LIMIT_HINT = (
    " Unauthenticated requests are limited to 60 per hour; connect GitHub for a higher limit."
)


class GitHubError(Exception):
    """User-facing GitHub failure. `code` is stable and safe to show."""

    code = "github_error"
    http_status = 502

    def __init__(
        self, message: str, *, status: int | None = None, details: dict[str, Any] | None = None
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status = status
        self.details = details or {}


class GitHubAuthError(GitHubError):
    code = "github_auth_required"
    http_status = 401


class GitHubPermissionError(GitHubError):
    code = "insufficient_permissions"
    http_status = 403


class GitHubNotFoundError(GitHubError):
    code = "repository_not_found"
    http_status = 404


class GitHubRateLimitError(GitHubError, TransientInfraError):
    code = "github_rate_limited"
    http_status = 429


class GitHubValidationError(GitHubError):
    code = "github_validation_failed"
    http_status = 422


class GitHubUnavailableError(GitHubError, TransientInfraError):
    code = "github_unavailable"
    http_status = 503


@dataclass(frozen=True)
class RepoInfo:
    owner: str
    name: str
    private: bool
    default_branch: str
    size_kb: int
    archived: bool
    can_push: bool | None  # None: unknown (unauthenticated)
    fork: bool

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


# Tests install a fake GitHub here; production leaves it None (real network).
_transport_override: httpx.BaseTransport | None = None


def set_transport_override(transport: httpx.BaseTransport | None) -> None:
    global _transport_override
    _transport_override = transport


def transport_override() -> httpx.BaseTransport | None:
    return _transport_override


def _reset_time(response: httpx.Response) -> str | None:
    reset = response.headers.get("x-ratelimit-reset")
    if reset and reset.isdigit():
        return datetime.fromtimestamp(int(reset), UTC).strftime("%H:%M UTC")
    return None


class GitHubClient:
    def __init__(
        self,
        token: str | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        settings = get_settings()
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "CodeAudit",
        }
        self._authenticated = token is not None
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._http = httpx.Client(
            base_url=settings.github_api_url,
            headers=headers,
            timeout=settings.github_timeout_seconds,
            follow_redirects=False,
            transport=transport or _transport_override,
        )

    def __repr__(self) -> str:
        return f"GitHubClient(authenticated={self._authenticated})"

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # ------------------------------------------------------------------ plumbing

    def request(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            response = self._http.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise GitHubUnavailableError(
                f"Could not reach GitHub ({type(exc).__name__})."
            ) from None
        if response.status_code in (204, 205):
            return None
        if response.is_success:
            if not response.content:
                return None
            if "json" not in response.headers.get("content-type", ""):
                return response.text  # e.g. application/vnd.github.sha
            return response.json()
        raise self._error(response, method, path)

    def _error(self, response: httpx.Response, method: str, path: str) -> GitHubError:
        status = response.status_code
        try:
            payload = response.json()
        except ValueError:
            payload = {}
        message = str(payload.get("message", ""))[:MAX_ERROR_DETAIL]
        details: dict[str, Any] = {"github_message": message} if message else {}
        if errors := payload.get("errors"):
            details["github_errors"] = [
                str(e.get("message") or e.get("code") or e)[:200] for e in errors[:5]
            ]
        logger.info("github %s %s -> %d %s", method, path, status, message)

        remaining = response.headers.get("x-ratelimit-remaining")
        if status == 429 or (
            status == 403 and (remaining == "0" or "rate limit" in message.lower())
        ):
            reset = _reset_time(response)
            who = "" if self._authenticated else UNAUTHENTICATED_LIMIT_HINT
            return GitHubRateLimitError(
                f"GitHub API rate limit reached{f', resets at {reset}' if reset else ''}.{who}",
                status=status,
                details=details,
            )
        if status == 401:
            return GitHubAuthError(
                "GitHub rejected the stored credentials (revoked or expired). Reconnect GitHub.",
                status=status,
                details=details,
            )
        if status == 403:
            return GitHubPermissionError(
                f"GitHub denied this action: {message or 'insufficient permissions'}.",
                status=status,
                details=details,
            )
        if status == 404:
            return GitHubNotFoundError(
                "Not found on GitHub, or the connected account has no access to it.",
                status=status,
                details=details,
            )
        if status in (409, 422):
            return GitHubValidationError(
                message or "GitHub rejected the request.", status=status, details=details
            )
        if status >= 500:
            return GitHubUnavailableError(
                f"GitHub is having problems (HTTP {status}). Try again later.", status=status
            )
        return GitHubError(
            message or f"GitHub request failed (HTTP {status}).", status=status, details=details
        )

    # ------------------------------------------------------------------ endpoints

    def get_repo(self, owner: str, name: str) -> RepoInfo:
        data = self.request("GET", f"/repos/{owner}/{name}")
        permissions = data.get("permissions")
        return RepoInfo(
            owner=data["owner"]["login"],
            name=data["name"],
            private=bool(data.get("private")),
            default_branch=data["default_branch"],
            size_kb=int(data.get("size") or 0),
            archived=bool(data.get("archived")),
            can_push=(bool(permissions.get("push")) if isinstance(permissions, dict) else None),
            fork=bool(data.get("fork")),
        )

    def resolve_commit(self, owner: str, name: str, ref: str) -> str:
        data = self.request(
            "GET",
            f"/repos/{owner}/{name}/commits/{ref}",
            headers={"Accept": "application/vnd.github.sha"},
        )
        return str(data).strip() if isinstance(data, str) else str(data["sha"])

    def get_branch_head(self, owner: str, name: str, branch: str) -> str:
        data = self.request("GET", f"/repos/{owner}/{name}/git/ref/heads/{branch}")
        return str(data["object"]["sha"])

    def branch_exists(self, owner: str, name: str, branch: str) -> bool:
        try:
            self.request("GET", f"/repos/{owner}/{name}/git/ref/heads/{branch}")
        except GitHubNotFoundError:
            return False
        return True

    def get_file(self, owner: str, name: str, path: str, ref: str) -> str | None:
        """File content at `ref`, or None if it doesn't exist there."""
        try:
            data = self.request(
                "GET", f"/repos/{owner}/{name}/contents/{path}", params={"ref": ref}
            )
        except GitHubNotFoundError:
            return None
        if not isinstance(data, dict) or data.get("type") != "file":
            return None
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="surrogateescape")
        blob = self.request("GET", f"/repos/{owner}/{name}/git/blobs/{data['sha']}")
        return base64.b64decode(blob["content"]).decode("utf-8", errors="surrogateescape")

    def get_commit_tree(self, owner: str, name: str, commit_sha: str) -> str:
        return str(
            self.request("GET", f"/repos/{owner}/{name}/git/commits/{commit_sha}")["tree"]["sha"]
        )

    def get_file_mode(self, owner: str, name: str, commit_sha: str, path: str) -> str:
        """Git file mode of `path` at `commit_sha` (walks one tree per directory level)."""
        tree = self.get_commit_tree(owner, name, commit_sha)
        parts = path.split("/")
        for depth, part in enumerate(parts):
            entries = self.request("GET", f"/repos/{owner}/{name}/git/trees/{tree}")["tree"]
            entry = next((e for e in entries if e["path"] == part), None)
            if entry is None:
                raise GitHubNotFoundError(f"{path} does not exist at {commit_sha[:12]}.")
            if depth == len(parts) - 1:
                return str(entry["mode"])
            tree = entry["sha"]
        raise GitHubNotFoundError(f"{path} does not exist at {commit_sha[:12]}.")

    def get_authenticated_user(self) -> dict[str, Any]:
        return dict(self.request("GET", "/user"))

    def list_user_repos(self, page: int = 1, per_page: int = 50) -> list[dict[str, Any]]:
        return list(
            self.request(
                "GET",
                "/user/repos",
                params={
                    "per_page": per_page,
                    "page": page,
                    "sort": "pushed",
                    "affiliation": "owner,collaborator,organization_member",
                },
            )
        )

    # --- writes: only reachable from the confirmed pull request flow ---

    def create_blob(self, owner: str, name: str, content: str) -> str:
        data = self.request(
            "POST",
            f"/repos/{owner}/{name}/git/blobs",
            json={"content": content, "encoding": "utf-8"},
        )
        return str(data["sha"])

    def create_tree(
        self, owner: str, name: str, base_tree: str, files: dict[str, tuple[str, str]]
    ) -> str:
        """files: path -> (blob sha, mode)."""
        tree = [
            {"path": path, "mode": mode, "type": "blob", "sha": sha}
            for path, (sha, mode) in files.items()
        ]
        return str(
            self.request(
                "POST",
                f"/repos/{owner}/{name}/git/trees",
                json={"base_tree": base_tree, "tree": tree},
            )["sha"]
        )

    def create_commit(self, owner: str, name: str, message: str, tree: str, parent: str) -> str:
        data = self.request(
            "POST",
            f"/repos/{owner}/{name}/git/commits",
            json={"message": message, "tree": tree, "parents": [parent]},
        )
        return str(data["sha"])

    def create_branch(self, owner: str, name: str, branch: str, sha: str) -> None:
        self.request(
            "POST",
            f"/repos/{owner}/{name}/git/refs",
            json={"ref": f"refs/heads/{branch}", "sha": sha},
        )

    def create_fork(self, owner: str, name: str, *, default_branch_only: bool) -> dict[str, Any]:
        return dict(
            self.request(
                "POST",
                f"/repos/{owner}/{name}/forks",
                json={"default_branch_only": default_branch_only},
            )
        )

    def sync_fork(self, owner: str, name: str, branch: str) -> None:
        """Bring a fork's branch up to date with its upstream."""
        self.request("POST", f"/repos/{owner}/{name}/merge-upstream", json={"branch": branch})

    def create_pull_request(
        self, owner: str, name: str, *, title: str, body: str, head: str, base: str
    ) -> dict[str, Any]:
        return dict(
            self.request(
                "POST",
                f"/repos/{owner}/{name}/pulls",
                json={
                    "title": title,
                    "body": body,
                    "head": head,
                    "base": base,
                    "maintainer_can_modify": True,
                },
            )
        )

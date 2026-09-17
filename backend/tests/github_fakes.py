"""An in-memory GitHub (REST API + OAuth endpoints) served through httpx.MockTransport.

Implements only what CodeAudit calls, with GitHub's status codes and error
messages for the failure modes the product handles. Every request is recorded
so tests can assert what was (not) written.
"""

import base64
import fnmatch
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs

import httpx

API = "api.github.com"
WEB = "github.com"


def _sha(*parts: str) -> str:
    # Fake git object ids.
    return hashlib.sha1("\0".join(parts).encode(), usedforsecurity=False).hexdigest()


@dataclass
class FakeRepo:
    owner: str
    name: str
    private: bool = False
    default_branch: str = "main"
    size_kb: int = 100
    fork: bool = False
    parent: "FakeRepo | None" = None
    # Logins allowed to push (the owner always can).
    collaborators: set[str] = field(default_factory=set)
    # Branch name globs that reject new refs (a ruleset).
    protected_patterns: list[str] = field(default_factory=list)
    branches: dict[str, str] = field(default_factory=dict)
    pulls: list[dict[str, Any]] = field(default_factory=list)

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.name}"


class FakeGitHub:
    def __init__(self) -> None:
        self.repos: dict[str, FakeRepo] = {}
        # Objects are shared across forks, like GitHub's fork network.
        self.blobs: dict[str, str] = {}
        self.trees: dict[str, dict[str, tuple[str, str]]] = {}  # sha -> path -> (blob, mode)
        self.commits: dict[str, dict[str, Any]] = {}
        self.tokens: dict[str, dict[str, Any]] = {}  # token -> {login, id, scopes}
        self.oauth_codes: dict[str, dict[str, Any]] = {}  # code -> token payload
        self.revoked: list[str] = []
        self.requests: list[httpx.Request] = []
        self.fork_delay_polls = 0
        # Logins whose writes GitHub refuses although the repo reports push access
        # (e.g. an OAuth app restricted by the organization).
        self.write_denied: set[str] = set()
        self.transport = httpx.MockTransport(self.handle)

    # ------------------------------------------------------------------ setup

    def add_user(self, login: str, token: str, *, user_id: int, scopes: str = "") -> None:
        self.tokens[token] = {"login": login, "id": user_id, "scopes": scopes}

    def add_repo(self, owner: str, name: str, files: dict[str, str], **options: Any) -> FakeRepo:
        repo = FakeRepo(owner, name, **options)
        self.repos[repo.full_name.lower()] = repo
        repo.branches[repo.default_branch] = self.commit(files, "initial commit", parents=[])
        return repo

    def commit(
        self, files: dict[str, str], message: str, parents: list[str], mode: str = "100644"
    ) -> str:
        tree: dict[str, tuple[str, str]] = {}
        for path, content in files.items():
            blob = _sha("blob", content)
            self.blobs[blob] = content
            tree[path] = (blob, mode)
        tree_sha = _sha("tree", json.dumps(sorted(tree.items())))
        self.trees[tree_sha] = tree
        sha = _sha("commit", tree_sha, message, *parents)
        self.commits[sha] = {"tree": tree_sha, "parents": parents, "message": message}
        return sha

    def push(self, repo: FakeRepo, branch: str, files: dict[str, str], message: str) -> str:
        """Add a commit on top of `branch` changing `files`."""
        head = repo.branches[branch]
        current = {p: self.blobs[b] for p, (b, _) in self.trees[self.commits[head]["tree"]].items()}
        sha = self.commit({**current, **files}, message, parents=[head])
        repo.branches[branch] = sha
        return sha

    def files_at(self, sha: str) -> dict[str, str]:
        tree = self.trees[self.commits[sha]["tree"]]
        return {path: self.blobs[blob] for path, (blob, _) in tree.items()}

    def writes(self) -> list[str]:
        return [
            f"{r.method} {r.url.path}"
            for r in self.requests
            if r.method in {"POST", "PATCH", "PUT", "DELETE"} and r.url.host == API
        ]

    # ------------------------------------------------------------------ plumbing

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == WEB:
            return self._oauth(request)
        if request.url.host != API:
            raise AssertionError(f"unexpected host {request.url.host}")
        auth = request.headers.get("authorization", "")
        login = None
        if auth.startswith("Bearer "):
            user = self.tokens.get(auth[7:])
            if user is None:
                return _error(401, "Bad credentials")
            login = user["login"]
        try:
            return self._route(request, login)
        except KeyError:
            return _error(404, "Not Found")

    def _repo(self, owner: str, name: str, login: str | None) -> FakeRepo:
        repo = self.repos[f"{owner}/{name}".lower()]
        if repo.private and login != repo.owner and login not in repo.collaborators:
            raise KeyError(name)
        return repo

    def _can_push(self, repo: FakeRepo, login: str | None) -> bool:
        return login is not None and (login == repo.owner or login in repo.collaborators)

    def _route(self, request: httpx.Request, login: str | None) -> httpx.Response:
        path, method = request.url.path, request.method
        body = json.loads(request.content) if request.content else {}

        if path == "/user" and method == "GET":
            if login is None:
                return _error(401, "Requires authentication")
            user = next(u for u in self.tokens.values() if u["login"] == login)
            return _json(
                {"login": login, "id": user["id"], "name": login.title(), "avatar_url": None}
            )
        if path == "/user/repos":
            return _json(
                [
                    {
                        "full_name": r.full_name,
                        "private": r.private,
                        "default_branch": r.default_branch,
                        "description": None,
                        "pushed_at": None,
                        "html_url": f"https://github.com/{r.full_name}",
                    }
                    for r in self.repos.values()
                    if login in (r.owner, *r.collaborators)
                ]
            )
        if match := re.fullmatch(r"/applications/([^/]+)/grant", path):
            self.revoked.append(json.loads(request.content)["access_token"])
            return httpx.Response(204)

        match = re.fullmatch(r"/repos/([^/]+)/([^/]+)(/.*)?", path)
        if not match:
            return _error(404, "Not Found")
        repo = self._repo(match.group(1), match.group(2), login)
        rest = match.group(3) or ""

        if rest == "" and method == "GET":
            return _json(
                {
                    "owner": {"login": repo.owner},
                    "name": repo.name,
                    "full_name": repo.full_name,
                    "private": repo.private,
                    "default_branch": repo.default_branch,
                    "size": repo.size_kb,
                    "archived": False,
                    "fork": repo.fork,
                    **(
                        {"permissions": {"push": self._can_push(repo, login), "pull": True}}
                        if login
                        else {}
                    ),
                }
            )
        if m := re.fullmatch(r"/commits/(.+)", rest):
            ref = m.group(1)
            sha = repo.branches.get(ref) or (ref if ref in self.commits else None)
            if sha is None:
                return _error(422, f"No commit found for SHA: {ref}")
            return httpx.Response(200, text=sha)
        if m := re.fullmatch(r"/git/ref/heads/(.+)", rest):
            if repo.fork and repo.parent and self.fork_delay_polls > 0:
                self.fork_delay_polls -= 1
                return _error(404, "Not Found")
            sha = repo.branches[m.group(1)]
            return _json({"ref": f"refs/heads/{m.group(1)}", "object": {"sha": sha}})
        if m := re.fullmatch(r"/contents/(.+)", rest):
            ref = request.url.params["ref"]
            sha = repo.branches.get(ref, ref)
            blob, _ = self.trees[self.commits[sha]["tree"]][m.group(1)]
            content = base64.b64encode(self.blobs[blob].encode()).decode()
            return _json({"type": "file", "encoding": "base64", "content": content, "sha": blob})
        if m := re.fullmatch(r"/git/commits/([0-9a-f]{40})", rest):
            commit = self.commits[m.group(1)]
            return _json({"sha": m.group(1), "tree": {"sha": commit["tree"]}})
        if m := re.fullmatch(r"/git/trees/(.+)", rest):
            return _json({"tree": self._tree_listing(m.group(1))})

        # --- writes ---
        if method != "GET" and login in self.write_denied:
            return _error(403, "Resource not accessible by integration")
        if method != "GET" and not self._can_push(repo, login) and not rest == "/forks":
            if rest == "/pulls" and login is not None:
                pass  # anyone with read access may open a PR from a fork
            else:
                return _error(403, "Resource not accessible by integration")
        if rest == "/git/blobs" and method == "POST":
            blob = _sha("blob", body["content"])
            self.blobs[blob] = body["content"]
            return _json({"sha": blob}, 201)
        if rest == "/git/trees" and method == "POST":
            tree = dict(self.trees[body["base_tree"]])
            for entry in body["tree"]:
                tree[entry["path"]] = (entry["sha"], entry["mode"])
            sha = _sha("tree", json.dumps(sorted(tree.items())))
            self.trees[sha] = tree
            return _json({"sha": sha}, 201)
        if rest == "/git/commits" and method == "POST":
            sha = _sha("commit", body["tree"], body["message"], *body["parents"])
            self.commits[sha] = {
                "tree": body["tree"],
                "parents": body["parents"],
                "message": body["message"],
            }
            return _json({"sha": sha}, 201)
        if rest == "/git/refs" and method == "POST":
            branch = body["ref"].removeprefix("refs/heads/")
            if any(fnmatch.fnmatch(branch, p) for p in repo.protected_patterns):
                return _error(
                    422,
                    "Repository rule violations found",
                    errors=["Cannot create ref due to creations being restricted."],
                )
            if branch in repo.branches:
                return _error(422, "Reference already exists")
            repo.branches[branch] = body["sha"]
            return _json({"ref": body["ref"], "object": {"sha": body["sha"]}}, 201)
        if rest == "/forks" and method == "POST":
            if login is None:
                return _error(401, "Requires authentication")
            fork = FakeRepo(login, repo.name, fork=True, parent=repo)
            fork.default_branch = repo.default_branch
            fork.branches = (
                {repo.default_branch: repo.branches[repo.default_branch]}
                if body.get("default_branch_only")
                else dict(repo.branches)
            )
            self.repos.setdefault(fork.full_name.lower(), fork)
            return _json({"full_name": fork.full_name}, 202)
        if rest == "/merge-upstream" and method == "POST":
            if repo.parent is None:
                return _error(422, "Not a fork")
            repo.branches[body["branch"]] = repo.parent.branches[body["branch"]]
            return _json({"merge_type": "fast-forward"})
        if rest == "/pulls" and method == "POST":
            head_owner, _, head_branch = body["head"].rpartition(":")
            head_repo = self.repos[f"{head_owner}/{repo.name}".lower()] if head_owner else repo
            if head_branch not in head_repo.branches:
                return _error(422, "Validation Failed", errors=["head invalid"])
            if any(p["head"] == body["head"] for p in repo.pulls):
                return _error(422, "Validation Failed", errors=["A pull request already exists"])
            number = len(repo.pulls) + 1
            pull = {
                **body,
                "number": number,
                "html_url": f"https://github.com/{repo.full_name}/pull/{number}",
            }
            repo.pulls.append(pull)
            return _json(pull, 201)
        return _error(404, "Not Found")

    def _tree_listing(self, tree_id: str) -> list[dict[str, str]]:
        tree_sha, _, prefix = tree_id.partition("|")
        entries: dict[str, dict[str, str]] = {}
        for path, (blob, mode) in self.trees[tree_sha].items():
            if not path.startswith(prefix):
                continue
            head, sep, _ = path[len(prefix) :].partition("/")
            if sep:
                entries[head] = {
                    "path": head,
                    "mode": "040000",
                    "type": "tree",
                    "sha": f"{tree_sha}|{prefix}{head}/",
                }
            else:
                entries[head] = {"path": head, "mode": mode, "type": "blob", "sha": blob}
        return list(entries.values())

    def _oauth(self, request: httpx.Request) -> httpx.Response:
        if request.url.path != "/login/oauth/access_token":
            return _error(404, "Not Found")
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        if form.get("grant_type") == "refresh_token":
            payload = self.oauth_codes.get(f"refresh:{form.get('refresh_token')}")
        else:
            payload = self.oauth_codes.pop(form.get("code", ""), None)
        if payload is None:
            return _json({"error": "bad_verification_code"})
        return _json(payload)


def _json(data: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=data)


def _error(status: int, message: str, errors: list[str] | None = None) -> httpx.Response:
    payload: dict[str, Any] = {"message": message}
    if errors:
        payload["errors"] = [{"message": e} for e in errors]
    return httpx.Response(status, json=payload)

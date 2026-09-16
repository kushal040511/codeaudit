"""Creating scans from an uploaded archive or a GitHub repository URL."""

import logging
import uuid
from typing import BinaryIO

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.errors import AppError, PayloadTooLargeError, RateLimitedError, UnauthorizedError
from app.config import get_settings
from app.models import GitHubIdentity, Scan, ScanSource, ScanStatus
from app.services.archive import UnsafeArchiveError, archive_limits_from_settings, inspect_zip
from app.services.auth.oauth import access_token
from app.services.auth.sessions import Principal
from app.services.github.client import (
    GitHubClient,
    GitHubError,
    GitHubNotFoundError,
    GitHubValidationError,
)
from app.services.github.urls import SHA, InvalidRepoUrlError, parse_repo_url
from app.services.rate_limit import hit

logger = logging.getLogger(__name__)

WINDOW_SECONDS = 3600


class GitHubApiError(AppError):
    """A GitHubError rendered as an API error with GitHub's status mapping."""

    def __init__(self, error: GitHubError) -> None:
        super().__init__(error.message, code=error.code, details=error.details or None)
        self.status_code = error.http_status


def enforce_scan_rate_limit(principal: Principal | None, client_ip: str) -> None:
    settings = get_settings()
    if principal is not None:
        key, limit = f"scans:user:{principal.user.id}", settings.scans_per_hour_per_user
    else:
        key, limit = f"scans:ip:{client_ip}", settings.scans_per_hour_anonymous
    result = hit(key, limit, WINDOW_SECONDS)
    if not result.allowed:
        who = "" if principal else " Sign in for a higher limit."
        raise RateLimitedError(
            f"Scan limit reached ({limit} per hour). Try again in"
            f" {result.retry_after_seconds // 60 + 1} minutes.{who}",
            details={"retry_after_seconds": result.retry_after_seconds},
        )


def validate_upload(filename: str, size: int, fileobj: BinaryIO) -> int:
    settings = get_settings()
    if not filename.lower().endswith(".zip"):
        raise AppError("Only .zip archives are accepted.", code="invalid_file_type")
    if size == 0:
        raise AppError("The uploaded file is empty.", code="invalid_archive")
    if size > settings.max_upload_bytes:
        raise PayloadTooLargeError(f"Archive exceeds the {settings.max_upload_size_mb} MB limit.")
    try:
        return inspect_zip(fileobj, archive_limits_from_settings(settings)).file_count
    except UnsafeArchiveError as exc:
        raise AppError(str(exc), code="invalid_archive") from exc


def build_repo_scan(
    db: Session, principal: Principal | None, repo_url: str, ref: str | None
) -> Scan:
    """Resolve the repository and exact commit on GitHub. Nothing is cloned here."""
    settings = get_settings()
    try:
        repo = parse_repo_url(repo_url, ref)
    except InvalidRepoUrlError as exc:
        raise AppError(str(exc), code="invalid_repo_url") from None

    identity = (
        db.scalar(select(GitHubIdentity).where(GitHubIdentity.user_id == principal.user.id))
        if principal
        else None
    )
    token: str | None = None
    try:
        if identity is not None and identity.access_token_encrypted is not None:
            token = access_token(db, identity)
        with GitHubClient(token) as github:
            try:
                info = github.get_repo(repo.owner, repo.name)
            except GitHubNotFoundError:
                hint = (
                    " If it's private, connect GitHub with private repository access."
                    if token is None or "repo" not in (identity.scopes if identity else [])
                    else ""
                )
                raise AppError(
                    f"Repository {repo.full_name} was not found or isn't accessible.{hint}",
                    code="repository_not_found",
                ) from None
            if info.private:
                if principal is None:
                    raise UnauthorizedError(
                        "Scanning a private repository requires signing in with GitHub.",
                        code="github_auth_required",
                    )
                if identity is None or "repo" not in identity.scopes:
                    raise AppError(
                        "This repository is private. Connect GitHub with private repository access"
                        " (the `repo` scope) to scan it.",
                        code="private_repo_access_required",
                    )
            max_kb = settings.github_max_repo_size_mb * 1024
            if info.size_kb > max_kb:
                raise PayloadTooLargeError(
                    f"{repo.full_name} is about {info.size_kb // 1024} MB; repositories over"
                    f" {settings.github_max_repo_size_mb} MB can't be scanned.",
                    code="repository_too_large",
                )
            requested = repo.ref or info.default_branch
            sha = (
                requested.lower()
                if SHA.match(requested.lower())
                else github.resolve_commit(repo.owner, repo.name, requested)
            )
    # GitHub answers 422 "No commit found for SHA" for unknown refs.
    except (GitHubNotFoundError, GitHubValidationError):
        raise AppError(
            f"Branch, tag or commit {repo.ref!r} was not found in {repo.full_name}.",
            code="ref_not_found",
        ) from None
    except GitHubError as exc:
        raise GitHubApiError(exc) from None

    return Scan(
        id=uuid.uuid4(),
        status=ScanStatus.QUEUED,
        source=ScanSource.GITHUB,
        user_id=principal.user.id if principal else None,
        original_filename=f"{info.full_name}@{requested}"[:255],
        repo_owner=info.owner,
        repo_name=info.name,
        repo_ref=requested,
        repo_default_branch=info.default_branch,
        commit_sha=sha,
        repo_private=info.private,
    )

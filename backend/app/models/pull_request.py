import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import BigInteger, DateTime, ForeignKey, Identity, Integer, String, Text, Uuid, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, pg_enum


class PullRequestStatus(enum.StrEnum):
    # A preview was shown; nothing has been written to GitHub.
    PREVIEWED = "previewed"
    # The user confirmed; branch, commits and PR are being created.
    CREATING = "creating"
    OPEN = "open"
    FAILED = "failed"


class PullRequest(Base):
    """A fix pull request: previewed first, created only after explicit confirmation."""

    __tablename__ = "pull_requests"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    # Exposed in URLs and responses instead of the sequential primary key.
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[PullRequestStatus] = mapped_column(
        pg_enum(PullRequestStatus, "pull_request_status")
    )
    # Repository the PR is opened against, and where the branch lives (a fork if needed).
    repo_full_name: Mapped[str] = mapped_column(String(255))
    head_repo_full_name: Mapped[str] = mapped_column(String(255))
    base_branch: Mapped[str] = mapped_column(String(255))
    # The base commit the preview was built on; confirmation fails if the branch moved.
    base_sha: Mapped[str] = mapped_column(String(40))
    branch: Mapped[str] = mapped_column(String(255))
    use_fork: Mapped[bool] = mapped_column(default=False)
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    included_suggestion_ids: Mapped[list[int]] = mapped_column(JSONB)
    # Hash of the exact changes previewed (suggestions, patches, base sha, branch).
    preview_fingerprint: Mapped[str] = mapped_column(String(64))
    combined_diff: Mapped[str] = mapped_column(Text)
    # [{sha, message, suggestion_ids}] once created.
    commits: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, server_default="[]")
    pr_number: Mapped[int | None] = mapped_column(Integer)
    pr_url: Mapped[str | None] = mapped_column(String(1024))
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

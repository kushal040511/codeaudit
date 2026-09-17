import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Identity,
    Integer,
    LargeBinary,
    String,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    display_name: Mapped[str] = mapped_column(String(255))
    avatar_url: Mapped[str | None] = mapped_column(String(1024))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Quota tier (free | pro) and per-user overrides; NULL = the tier default.
    quota_tier: Mapped[str] = mapped_column(String(16), default="free", server_default="free")
    quota_scans: Mapped[int | None] = mapped_column(Integer)
    quota_site_analyses: Mapped[int | None] = mapped_column(Integer)
    quota_pull_requests: Mapped[int | None] = mapped_column(Integer)
    quota_pr_previews: Mapped[int | None] = mapped_column(Integer)
    quota_requests: Mapped[int | None] = mapped_column(Integer)
    quota_llm_tokens: Mapped[int | None] = mapped_column(Integer)
    # Operators: can read the cost dashboard and use the LLM kill switch.
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")

    github: Mapped["GitHubIdentity | None"] = relationship(back_populates="user", uselist=False)


class GitHubIdentity(Base):
    """A user's GitHub account. The access token is only ever stored encrypted."""

    __tablename__ = "github_identities"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), unique=True
    )
    github_user_id: Mapped[int] = mapped_column(BigInteger, unique=True)
    login: Mapped[str] = mapped_column(String(255))
    # Fernet ciphertext; None once disconnected.
    access_token_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    refresh_token_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)
    # Only set for expiring user tokens.
    access_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    refresh_token_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scopes: Mapped[list[str]] = mapped_column(ARRAY(String(64)), default=list, server_default="{}")
    connected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    user: Mapped[User] = relationship(back_populates="github")

    def __repr__(self) -> str:  # never include token material
        return f"GitHubIdentity(login={self.login!r}, scopes={self.scopes!r})"


class UserSession(Base):
    """Browser session. The cookie holds a random secret; only its hash is stored."""

    __tablename__ = "user_sessions"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    # Sent back in X-CSRF-Token on state-changing requests made with the cookie.
    csrf_token: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ApiToken(Base):
    """Personal API token (e.g. for the GitHub Action). Only the hash is stored."""

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(BigInteger, Identity(), primary_key=True)
    # Exposed in URLs and responses instead of the sequential primary key.
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    # First characters, to recognise a token in the UI without revealing it.
    prefix: Mapped[str] = mapped_column(String(16))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

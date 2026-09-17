import uuid
from datetime import datetime

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class GitHubConnectionRead(BaseModel):
    login: str
    connected: bool
    scopes: list[str]
    private_repo_access: bool
    token_expires_at: datetime | None


class MeRead(BaseModel):
    id: str
    display_name: str
    avatar_url: str | None
    github: GitHubConnectionRead | None
    # Echo in X-CSRF-Token on state-changing requests (session auth only).
    csrf_token: str | None
    auth_method: str


class AuthConfigRead(BaseModel):
    github_enabled: bool


class ApiTokenRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    # The public UUID; the sequential primary key is never exposed.
    id: uuid.UUID = Field(validation_alias=AliasChoices("public_id", "id"))
    name: str
    prefix: str
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class ApiTokenCreated(ApiTokenRead):
    # Shown exactly once.
    token: str


class GitHubRepoRead(BaseModel):
    full_name: str
    private: bool
    default_branch: str
    description: str | None
    pushed_at: datetime | None
    html_url: str

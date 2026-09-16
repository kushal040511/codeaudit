from functools import lru_cache
from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

MB = 1024 * 1024


class Settings(BaseSettings):
    """Application settings, loaded from environment variables (and .env files).

    `.env` in the repo root is shared with docker-compose; `backend/.env` can
    override it for running the API directly on the host.
    """

    model_config = SettingsConfigDict(
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- App ---
    app_name: str = "CodeAudit"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    log_level: str = "INFO"
    api_prefix: str = "/api"
    cors_origins: list[str] = ["http://localhost:5173"]

    # --- PostgreSQL ---
    database_url: str = "postgresql+psycopg2://codeaudit:codeaudit@localhost:5432/codeaudit"

    # --- Redis / Celery ---
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"
    # Run tasks synchronously in the calling process. Tests only.
    celery_task_always_eager: bool = False

    # --- Object storage (S3-compatible; MinIO locally) ---
    s3_endpoint_url: str | None = "http://localhost:9000"
    s3_region: str = "us-east-1"
    s3_access_key_id: str = "codeaudit"
    s3_secret_access_key: SecretStr = SecretStr("codeaudit-secret")
    s3_bucket_uploads: str = "codeaudit-uploads"

    # --- LLM ---
    anthropic_api_key: SecretStr | None = None
    anthropic_model: str = "claude-opus-5"

    # --- Uploads ---
    max_upload_size_mb: int = 50
    max_archive_files: int = 10_000
    # Enforced on actual decompressed bytes during extraction, not on zip headers.
    max_extracted_size_mb: int = 500
    max_extracted_file_size_mb: int = 50

    # --- Scans ---
    scan_workspace_dir: str = "/var/lib/codeaudit/workspace"
    scan_timeout_seconds: int = 900
    scan_max_retries: int = 2

    # --- Sandbox (analyzers run in throwaway Docker containers) ---
    # Named volume backing scan_workspace_dir when the worker itself runs in a
    # container. Empty means the worker runs on the host and paths are bind-mounted.
    sandbox_workspace_volume: str = ""
    semgrep_image: str = "returntocorp/semgrep:1.177.0"
    semgrep_timeout_seconds: int = 300
    semgrep_memory_limit: str = "2g"
    semgrep_cpus: float = 2.0
    semgrep_rules_max_age_hours: int = 24

    # --- Analyzers ---
    # Analyzers of one scan run concurrently, each in its own sandbox container.
    analyzer_max_workers: int = 4
    # No version tags are published for this image; pinned by digest (bandit 1.9.4).
    bandit_image: str = (
        "ghcr.io/pycqa/bandit/bandit"
        "@sha256:67e9ecb7cfa64a398b59f125d27a193a13679affc79edf6bcb95f05cb82d2600"
    )
    bandit_timeout_seconds: int = 180
    bandit_memory_limit: str = "1g"
    bandit_cpus: float = 1.0
    ruff_image: str = "ghcr.io/astral-sh/ruff:0.16.7"
    ruff_timeout_seconds: int = 120
    ruff_memory_limit: str = "512m"
    ruff_cpus: float = 1.0
    osv_scanner_image: str = "ghcr.io/google/osv-scanner:v2.5.1"
    osv_scanner_timeout_seconds: int = 300
    osv_scanner_memory_limit: str = "2g"
    osv_scanner_cpus: float = 1.0
    # Offline vulnerability databases are fetched by the worker and cached.
    osv_db_max_age_hours: int = 24

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_size_mb * MB


@lru_cache
def get_settings() -> Settings:
    return Settings()

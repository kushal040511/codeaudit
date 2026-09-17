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

    # --- LLM (fix suggestions, architecture review) ---
    anthropic_api_key: SecretStr | None = None
    anthropic_model: str = "claude-sonnet-4-6"
    # Master switch; the stage is also skipped when no API key is configured.
    llm_enabled: bool = True
    # Hard ceiling on input + output tokens across all calls for one scan. A call that
    # could exceed it (counted input + max output) is refused, not sent.
    llm_token_budget_per_scan: int = 400_000
    # Separate, smaller budget for a site analysis (one vision call on screenshots).
    llm_token_budget_per_site: int = 60_000
    llm_max_output_tokens: int = 16_000
    # Adaptive thinking effort: low | medium | high | max (Sonnet 4.6).
    llm_effort: str = "medium"
    llm_timeout_seconds: float = 180.0
    llm_max_retries: int = 4  # rate limits, overload, 5xx, connection errors
    llm_retry_max_delay_seconds: float = 60.0
    # Findings that get fix suggestions (highest priority first) and the most
    # similar findings sent together in one request.
    llm_max_fix_findings: int = 20
    llm_max_findings_per_request: int = 5
    llm_context_lines: int = 20
    # Hard limit for the enrichment task (download, fixes, review).
    llm_task_timeout_seconds: int = 1800

    # --- Auth / sessions ---
    # Public URL of the frontend; OAuth sign-in returns there.
    frontend_url: str = "http://localhost:5173"
    session_ttl_hours: int = 24 * 14
    # Set true behind HTTPS so session cookies are never sent in the clear.
    session_cookie_secure: bool = False
    # Fernet keys (urlsafe base64, 32 bytes), comma-separated; the first encrypts,
    # all decrypt, so keys can be rotated. Required to store GitHub tokens.
    token_encryption_keys: SecretStr | None = None

    # --- GitHub ---
    github_client_id: str | None = None
    github_client_secret: SecretStr | None = None
    github_oauth_url: str = "https://github.com"
    github_api_url: str = "https://api.github.com"
    github_timeout_seconds: float = 20.0
    github_max_repo_size_mb: int = 200
    # Git clone runs in its own sandbox container (the only one with network).
    git_image: str = (
        "alpine/git@sha256:0b5f57d22181e8b8fbe8ac5ca8754faa0d577f101b9857418f1acc43955ad464"
    )
    git_clone_timeout_seconds: int = 300
    git_clone_memory_limit: str = "1g"
    # Scans per rolling hour.
    scans_per_hour_per_user: int = 30
    scans_per_hour_anonymous: int = 10
    # Waiting for GitHub to create a fork before opening a PR from it.
    github_fork_wait_seconds: int = 60

    # --- Website analyzer ---
    # Built from docker/web-capture (Playwright 1.63 Chromium, base pinned by digest).
    web_capture_image: str = "codeaudit-web-capture:1.63.0"
    # Internal Docker network shared only with the egress proxy.
    web_capture_network: str = "codeaudit_web_capture"
    web_egress_proxy_url: str = "http://egress-proxy:8888"
    web_capture_timeout_seconds: int = 30
    web_page_timeout_ms: int = 20_000
    web_capture_memory_limit: str = "1536m"
    web_capture_cpus: float = 1.5
    web_max_redirects: int = 10
    # Completed analyses of the same normalized URL are reused within this window.
    site_cache_ttl_seconds: int = 6 * 3600
    site_analyses_per_hour_per_user: int = 30
    site_analyses_per_hour_anonymous: int = 10
    web_http_timeout_seconds: float = 10.0
    google_safe_browsing_api_key: SecretStr | None = None
    openphish_feed_url: str = "https://openphish.com/feed.txt"
    openphish_cache_seconds: int = 3600
    rdap_bootstrap_url: str = "https://rdap.org"

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
    # Runs in a child process of the worker (tree-sitter parsing, no sandbox container).
    architecture_timeout_seconds: int = 300

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_size_mb * MB


@lru_cache
def get_settings() -> Settings:
    return Settings()

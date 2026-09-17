"""production hardening: quotas, admin flag, finding fingerprints, public ids, scan cache

Revision ID: 8aecabc45c80
Revises: a182eb19a3c8
Create Date: 2026-09-17 16:32:41.293894

Existing rows are backfilled before constraints are added:
- findings.fingerprint is computed in SQL exactly like app.models.finding.finding_fingerprint.
  Pre-existing exact duplicates within a scan are kept (fix suggestions may point at them)
  and made distinct by rehashing with their id.
- pull_requests/api_tokens.public_id get gen_random_uuid().
- llm_calls.created_at is indexed for the spend and quota checks.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "8aecabc45c80"
down_revision: str | Sequence[str] | None = "a182eb19a3c8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FINGERPRINT_SQL = """
UPDATE findings SET fingerprint = encode(sha256(convert_to(
    coalesce(analyzer, '') || '|' || coalesce(rule_id, '') || '|' || coalesce(file_path, '')
    || '|' || coalesce(start_line::text, '') || '|' || coalesce(end_line::text, '')
    || '|' || coalesce(message, '') || '|' || coalesce(dependency->>'package', '')
    || '|' || coalesce(dependency->>'installed_version', ''),
    'UTF8')), 'hex')
"""

DISAMBIGUATE_SQL = """
UPDATE findings f SET fingerprint = encode(sha256(convert_to(f.fingerprint || ':' || f.id, 'UTF8')), 'hex')
FROM (
    SELECT id, row_number() OVER (PARTITION BY scan_id, fingerprint ORDER BY id) AS n
    FROM findings
) d
WHERE d.id = f.id AND d.n > 1
"""  # noqa: E501


def upgrade() -> None:
    # Users: quota tier, per-user overrides, operator flag.
    op.add_column(
        "users",
        sa.Column("quota_tier", sa.String(length=16), server_default="free", nullable=False),
    )
    for name in (
        "scans",
        "site_analyses",
        "pull_requests",
        "pr_previews",
        "requests",
        "llm_tokens",
    ):
        op.add_column("users", sa.Column(f"quota_{name}", sa.Integer(), nullable=True))
    op.add_column(
        "users", sa.Column("is_admin", sa.Boolean(), server_default=sa.false(), nullable=False)
    )

    # Findings: idempotent persistence.
    op.add_column("findings", sa.Column("fingerprint", sa.String(length=64), nullable=True))
    op.execute(FINGERPRINT_SQL)
    op.execute(DISAMBIGUATE_SQL)
    op.alter_column("findings", "fingerprint", nullable=False)
    op.create_unique_constraint(
        "uq_findings_scan_id_fingerprint", "findings", ["scan_id", "fingerprint"]
    )

    # Public UUIDs for resources that previously exposed sequential ids.
    for table in ("pull_requests", "api_tokens"):
        op.add_column(
            table,
            sa.Column(
                "public_id", sa.Uuid(), server_default=sa.text("gen_random_uuid()"), nullable=False
            ),
        )
        op.alter_column(table, "public_id", server_default=None)
        op.create_unique_constraint(f"uq_{table}_public_id", table, ["public_id"])

    # Scan result cache.
    op.add_column("scans", sa.Column("content_sha256", sa.String(length=64), nullable=True))
    op.add_column("scans", sa.Column("analysis_version", sa.String(length=32), nullable=True))
    op.create_index("ix_scans_content_sha256", "scans", ["content_sha256"], unique=False)

    # EXPLAIN on 300k llm_calls: today's spend 27 ms (parallel seq scan) -> 1.9 ms.
    op.create_index("ix_llm_calls_created_at", "llm_calls", ["created_at"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_llm_calls_created_at", table_name="llm_calls")
    op.drop_index("ix_scans_content_sha256", table_name="scans")
    op.drop_column("scans", "analysis_version")
    op.drop_column("scans", "content_sha256")
    for table in ("api_tokens", "pull_requests"):
        op.drop_constraint(f"uq_{table}_public_id", table, type_="unique")
        op.drop_column(table, "public_id")
    op.drop_constraint("uq_findings_scan_id_fingerprint", "findings", type_="unique")
    op.drop_column("findings", "fingerprint")
    op.drop_column("users", "is_admin")
    for name in (
        "llm_tokens",
        "requests",
        "pr_previews",
        "pull_requests",
        "site_analyses",
        "scans",
    ):
        op.drop_column("users", f"quota_{name}")
    op.drop_column("users", "quota_tier")

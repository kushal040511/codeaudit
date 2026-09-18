"""experimental signals: scans.signal_metrics, scans.advisory_metrics, scan_scores.rubric_config

Revision ID: b7e1c2d3f4a5
Revises: 8aecabc45c80
Create Date: 2026-09-18 19:00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "b7e1c2d3f4a5"
down_revision: str | Sequence[str] | None = "8aecabc45c80"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("signal_metrics", postgresql.JSONB(), nullable=True))
    op.add_column("scans", sa.Column("advisory_metrics", postgresql.JSONB(), nullable=True))
    op.add_column(
        "scan_scores",
        sa.Column("rubric_config", sa.String(length=200), server_default="base", nullable=False),
    )


def downgrade() -> None:
    op.drop_column("scan_scores", "rubric_config")
    op.drop_column("scans", "advisory_metrics")
    op.drop_column("scans", "signal_metrics")

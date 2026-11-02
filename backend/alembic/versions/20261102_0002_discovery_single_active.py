"""at most one pending/running discovery job per server

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-02 12:00:00
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "uq_discovery_jobs_active_per_server", "discovery_jobs", ["server_id"], unique=True,
        postgresql_where="status IN ('pending', 'running')",
    )
    op.create_index("ix_notification_deliveries_rule_dedupe", "notification_deliveries",
                    ["rule_id", "dedupe_key", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_notification_deliveries_rule_dedupe", table_name="notification_deliveries")
    op.drop_index("uq_discovery_jobs_active_per_server", table_name="discovery_jobs")

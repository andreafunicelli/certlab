"""environments.require_trusted_chain (strict chain enforcement per environment) and deployment dispatch bookkeeping

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-02 15:00:00
"""
import sqlalchemy as sa

from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("environments", sa.Column("require_trusted_chain", sa.Boolean(), server_default="false", nullable=False))
    # queue-loss sweep (K5): how often a pending deployment was handed to the broker, and when last
    op.add_column("deployment_jobs", sa.Column("dispatch_attempts", sa.Integer(), server_default="0", nullable=False))
    op.add_column("deployment_jobs", sa.Column("last_dispatched_at", sa.DateTime(timezone=True), nullable=True))
    op.execute("UPDATE environments SET require_trusted_chain = true WHERE name = 'Production'")


def downgrade() -> None:
    op.drop_column("deployment_jobs", "last_dispatched_at")
    op.drop_column("deployment_jobs", "dispatch_attempts")
    op.drop_column("environments", "require_trusted_chain")

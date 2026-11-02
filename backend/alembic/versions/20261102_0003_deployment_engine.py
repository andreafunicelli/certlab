"""deployment engine: request hash (idempotency), retry link, target working state

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-02 13:00:00
"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("deployment_jobs", sa.Column("request_hash", sa.String(length=64), nullable=True))
    op.add_column("deployment_jobs", sa.Column("retry_of", sa.Uuid(), nullable=True))
    op.create_foreign_key("fk_deployment_jobs_retry_of_deployment_jobs", "deployment_jobs", "deployment_jobs",
                          ["retry_of"], ["id"], ondelete="SET NULL")
    op.add_column("deployment_targets", sa.Column("meta", postgresql.JSONB(), server_default="{}", nullable=False))


def downgrade() -> None:
    op.drop_column("deployment_targets", "meta")
    op.drop_constraint("fk_deployment_jobs_retry_of_deployment_jobs", "deployment_jobs", type_="foreignkey")
    op.drop_column("deployment_jobs", "retry_of")
    op.drop_column("deployment_jobs", "request_hash")

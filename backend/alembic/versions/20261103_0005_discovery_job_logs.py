"""discovery job step timeline, sanitized log and error code

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-03 10:00:00
"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("discovery_jobs", sa.Column("steps", postgresql.JSONB(), nullable=True))
    op.add_column("discovery_jobs", sa.Column("log", postgresql.JSONB(), nullable=True))
    op.add_column("discovery_jobs", sa.Column("error_code", sa.String(length=48), nullable=True))


def downgrade() -> None:
    op.drop_column("discovery_jobs", "error_code")
    op.drop_column("discovery_jobs", "log")
    op.drop_column("discovery_jobs", "steps")

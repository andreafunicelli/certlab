from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, IdMixin, TimestampMixin, in_check

DISCOVERY_STATUSES = ("pending", "running", "completed", "failed", "partial", "cancelled")
DEPLOYMENT_STATUSES = (
    "pending", "preflight", "awaiting_approval", "backing_up", "staging", "validating", "activating",
    "reloading", "verifying", "completed", "failed", "rolling_back", "rolled_back",
    "manual_intervention_required", "cancelled", "partially_failed",
)
TARGET_STATUSES = DEPLOYMENT_STATUSES


class DiscoveryJob(IdMixin, TimestampMixin, Base):
    __tablename__ = "discovery_jobs"
    server_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"), index=True)
    requested_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    stats: Mapped[dict[str, Any] | None]
    error: Mapped[str | None] = mapped_column(Text)
    error_code: Mapped[str | None] = mapped_column(String(48))
    steps: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB)
    log: Mapped[list[dict[str, Any]] | None] = mapped_column(JSONB)

    __table_args__ = (
        in_check("status", DISCOVERY_STATUSES, "status"),
        Index("uq_discovery_jobs_active_per_server", "server_id", unique=True,
              postgresql_where=text("status IN ('pending', 'running')")),
    )


class DiscoveryFinding(IdMixin, Base):
    __tablename__ = "discovery_findings"
    job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("discovery_jobs.id", ondelete="CASCADE"), index=True)
    path: Mapped[str | None] = mapped_column(Text)
    classification: Mapped[str] = mapped_column(String(24))
    message: Mapped[str | None] = mapped_column(Text)
    details: Mapped[dict[str, Any] | None]
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())


class DeploymentJob(IdMixin, TimestampMixin, Base):
    __tablename__ = "deployment_jobs"
    version_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("certificate_versions.id", ondelete="RESTRICT"), index=True)
    initiated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    strategy: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    dry_run_plan: Mapped[dict[str, Any] | None]
    status: Mapped[str] = mapped_column(String(32), default="pending", server_default="pending", index=True)
    approval_required: Mapped[bool] = mapped_column(default=False, server_default="false")
    approved_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    approved_at: Mapped[datetime | None]
    idempotency_key: Mapped[str | None] = mapped_column(String(128), unique=True)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    rollback_status: Mapped[str | None] = mapped_column(String(32))
    error_summary: Mapped[str | None] = mapped_column(Text)
    cancel_requested: Mapped[bool] = mapped_column(default=False, server_default="false")
    acknowledged_warnings: Mapped[list[Any]] = mapped_column(JSONB, server_default="[]", default=list)
    request_hash: Mapped[str | None] = mapped_column(String(64))   # idempotency: sha256 of the canonical request body
    retry_of: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("deployment_jobs.id", ondelete="SET NULL"))
    dispatch_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_dispatched_at: Mapped[datetime | None]

    __table_args__ = (in_check("status", DEPLOYMENT_STATUSES, "status"),)


class DeploymentTarget(IdMixin, TimestampMixin, Base):
    __tablename__ = "deployment_targets"
    job_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("deployment_jobs.id", ondelete="CASCADE"), index=True)
    installation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("certificate_installations.id", ondelete="SET NULL"), index=True
    )
    server_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("servers.id", ondelete="RESTRICT"), index=True)
    batch_index: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    is_canary: Mapped[bool] = mapped_column(default=False, server_default="false")
    status: Mapped[str] = mapped_column(String(32), default="pending", server_default="pending")
    current_step: Mapped[str | None] = mapped_column(String(64))
    steps: Mapped[list[dict[str, Any]]] = mapped_column(server_default="[]", default=list)
    previous_fingerprint: Mapped[str | None] = mapped_column(String(64))
    new_fingerprint: Mapped[str | None] = mapped_column(String(64))
    backup_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("backups.id", ondelete="SET NULL", use_alter=True, name="fk_targets_backup")
    )
    rollback_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    verification: Mapped[dict[str, Any] | None]
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    log: Mapped[list[dict[str, Any]]] = mapped_column(server_default="[]", default=list)
    # engine working state (stage dir, shared-path group, expected hashes, baseline served fingerprint ...)
    meta: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)

    __table_args__ = (in_check("status", TARGET_STATUSES, "status"),)


class DeploymentLock(IdMixin, Base):
    __tablename__ = "deployment_locks"
    resource_key: Mapped[str] = mapped_column(String(512), unique=True)
    job_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("deployment_jobs.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("deployment_targets.id", ondelete="CASCADE"))
    owner: Mapped[str] = mapped_column(String(128))
    acquired_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime] = mapped_column(index=True)
    heartbeat_at: Mapped[datetime] = mapped_column(server_default=func.now())



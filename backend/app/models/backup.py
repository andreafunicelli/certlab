from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, IdMixin, in_check

RESTORE_STATUSES = ("none", "in_progress", "restored", "failed")


class Backup(IdMixin, Base):
    __tablename__ = "backups"
    server_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("servers.id", ondelete="RESTRICT"), index=True)
    installation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("certificate_installations.id", ondelete="SET NULL"), index=True
    )
    deployment_target_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("deployment_targets.id", ondelete="SET NULL", use_alter=True, name="fk_backups_target")
    )
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    manifest: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    integrity_sha256: Mapped[str | None] = mapped_column(String(64))
    verified: Mapped[bool] = mapped_column(default=False, server_default="false")
    retention_until: Mapped[datetime | None] = mapped_column(index=True)
    restore_status: Mapped[str] = mapped_column(String(16), default="none", server_default="none")
    restored_at: Mapped[datetime | None]

    __table_args__ = (in_check("restore_status", RESTORE_STATUSES, "restore_status"),)

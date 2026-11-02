from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, IdMixin, in_check

OUTCOMES = ("success", "failure", "denied")


class AuditEvent(IdMixin, Base):
    __tablename__ = "audit_events"
    ts: Mapped[datetime] = mapped_column(server_default=func.now(), index=True)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    actor_name: Mapped[str | None] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64), index=True)
    resource_type: Mapped[str | None] = mapped_column(String(48))
    resource_id: Mapped[str | None] = mapped_column(String(64))
    before: Mapped[dict[str, Any] | None]
    after: Mapped[dict[str, Any] | None]
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))
    correlation_id: Mapped[str | None] = mapped_column(String(64))
    outcome: Mapped[str] = mapped_column(String(8), default="success", server_default="success")
    error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        in_check("outcome", OUTCOMES, "outcome"),
        Index("ix_audit_events_resource", "resource_type", "resource_id"),
    )

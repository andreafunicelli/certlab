from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, IdMixin, TimestampMixin, in_check

SEVERITIES = ("info", "warning", "high", "critical")


class NotificationChannel(IdMixin, TimestampMixin, Base):
    __tablename__ = "notification_channels"
    type: Mapped[str] = mapped_column(String(16))
    name: Mapped[str] = mapped_column(String(128), unique=True)
    config: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    secret_encrypted: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(default=True, server_default="true")

    __table_args__ = (in_check("type", ("smtp", "webhook"), "type"),)


class NotificationRule(IdMixin, TimestampMixin, Base):
    __tablename__ = "notification_rules"
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    channel_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("notification_channels.id", ondelete="CASCADE"), index=True)
    min_severity: Mapped[str] = mapped_column(String(8), default="info", server_default="info")
    filters: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    reminder_interval_hours: Mapped[int | None] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(default=True, server_default="true")

    __table_args__ = (in_check("min_severity", SEVERITIES, "min_severity"),)


class NotificationDelivery(IdMixin, TimestampMixin, Base):
    __tablename__ = "notification_deliveries"
    rule_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("notification_rules.id", ondelete="SET NULL"))
    channel_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("notification_channels.id", ondelete="SET NULL"), index=True)
    event_type: Mapped[str] = mapped_column(String(64))
    dedupe_key: Mapped[str] = mapped_column(String(255))
    payload: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_error: Mapped[str | None] = mapped_column(Text)
    sent_at: Mapped[datetime | None]

    __table_args__ = (
        in_check("status", ("pending", "sent", "failed", "skipped"), "status"),
        Index("ix_notification_deliveries_dedupe_key", "dedupe_key"),
    )

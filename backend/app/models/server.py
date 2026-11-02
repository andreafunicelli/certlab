from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, IdMixin, TimestampMixin, in_check

CONNECTION_STATUSES = (
    "unknown", "connected", "offline", "auth_error", "host_key_mismatch", "host_key_unknown", "error",
)
PRIVILEGE_MODES = ("helper-sudo", "none")


class Environment(IdMixin, TimestampMixin, Base):
    __tablename__ = "environments"
    name: Mapped[str] = mapped_column(String(64), unique=True)
    description: Mapped[str | None] = mapped_column(String(255))
    is_production: Mapped[bool] = mapped_column(default=False, server_default="false")
    requires_approval: Mapped[bool] = mapped_column(default=False, server_default="false")


class Credential(IdMixin, TimestampMixin, Base):
    __tablename__ = "credentials"
    name: Mapped[str] = mapped_column(String(128), unique=True)
    type: Mapped[str] = mapped_column(String(32), default="ssh_private_key", server_default="ssh_private_key")
    encrypted_artifact_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("encrypted_artifacts.id", ondelete="RESTRICT"))
    passphrase_encrypted: Mapped[str | None] = mapped_column(Text)
    public_key: Mapped[str] = mapped_column(Text)
    fingerprint_sha256: Mapped[str] = mapped_column(String(80))
    key_algorithm: Mapped[str | None] = mapped_column(String(32))
    rotated_at: Mapped[datetime | None]
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

    __table_args__ = (in_check("type", ("ssh_private_key",), "type"),)


class Server(IdMixin, TimestampMixin, Base):
    __tablename__ = "servers"
    name: Mapped[str] = mapped_column(String(128), unique=True)
    hostname: Mapped[str] = mapped_column(String(255))
    address: Mapped[str | None] = mapped_column(String(64))
    ssh_port: Mapped[int] = mapped_column(Integer, default=22, server_default="22")
    ssh_username: Mapped[str] = mapped_column(String(64))
    credential_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("credentials.id", ondelete="RESTRICT"), index=True)
    bastion_server_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("servers.id", ondelete="SET NULL"))
    privilege_mode: Mapped[str] = mapped_column(String(16), default="helper-sudo", server_default="helper-sudo")
    os_family: Mapped[str | None] = mapped_column(String(32))
    os_version: Mapped[str | None] = mapped_column(String(64))
    os_pretty: Mapped[str | None] = mapped_column(String(128))
    environment: Mapped[str] = mapped_column(
        ForeignKey("environments.name", onupdate="CASCADE", ondelete="RESTRICT"), index=True
    )
    tags: Mapped[list[str]] = mapped_column(server_default="{}", default=list)
    description: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(default=True, server_default="true")
    connection_status: Mapped[str] = mapped_column(String(24), default="unknown", server_default="unknown")
    host_key_type: Mapped[str | None] = mapped_column(String(32))
    host_public_key: Mapped[str | None] = mapped_column(Text)
    host_key_fingerprint: Mapped[str | None] = mapped_column(String(80))
    host_key_enrolled_at: Mapped[datetime | None]
    host_key_enrolled_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    last_connected_at: Mapped[datetime | None]
    last_discovery_at: Mapped[datetime | None]
    last_discovery_status: Mapped[str | None] = mapped_column(String(24))
    discovery_error: Mapped[str | None] = mapped_column(Text)
    detected_services: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    credential: Mapped[Credential | None] = relationship(lazy="joined")

    __table_args__ = (
        in_check("connection_status", CONNECTION_STATUSES, "connection_status"),
        in_check("privilege_mode", PRIVILEGE_MODES, "privilege_mode"),
        CheckConstraint("ssh_port BETWEEN 1 AND 65535", name="ssh_port_range"),
        Index("ix_servers_connection_status", "connection_status"),
    )


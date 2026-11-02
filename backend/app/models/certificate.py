from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, IdMixin, TimestampMixin, in_check

CERT_TYPES = ("leaf", "intermediate", "root", "self_signed")
CERT_STATUSES = ("valid", "expiring", "critical", "expired", "error")
DRIFT_STATUSES = ("in_sync", "drifted", "missing", "unknown")
CLASSIFICATIONS = ("managed", "unmanaged", "requires_mapping", "unsupported", "unreadable", "error")
VALIDATION_STATUSES = ("pending", "valid", "warnings", "invalid")
VERSION_STATUSES = ("uploaded", "validated", "deployed", "superseded", "rejected")


class Certificate(IdMixin, TimestampMixin, Base):
    __tablename__ = "certificates"
    fingerprint_sha256: Mapped[str] = mapped_column(String(64), unique=True)
    common_name: Mapped[str | None] = mapped_column(String(255), index=True)
    subject: Mapped[str] = mapped_column(Text)
    sans: Mapped[list[str]] = mapped_column(server_default="{}", default=list)
    issuer: Mapped[str] = mapped_column(Text)
    serial_number: Mapped[str] = mapped_column(String(80))
    public_key_algorithm: Mapped[str] = mapped_column(String(16))
    public_key_size: Mapped[int | None] = mapped_column(Integer)
    public_key_sha256: Mapped[str] = mapped_column(String(64), index=True)
    signature_algorithm: Mapped[str] = mapped_column(String(64))
    not_before: Mapped[datetime]
    not_after: Mapped[datetime] = mapped_column(index=True)
    is_ca: Mapped[bool] = mapped_column(default=False, server_default="false")
    chain_info: Mapped[dict[str, Any] | None]
    certificate_type: Mapped[str] = mapped_column(String(16), default="leaf", server_default="leaf")
    discovery_source: Mapped[str | None] = mapped_column(String(32))
    owner: Mapped[str | None] = mapped_column(String(128))
    tags: Mapped[list[str]] = mapped_column(server_default="{}", default=list)
    status: Mapped[str] = mapped_column(String(16), default="valid", server_default="valid")
    pem: Mapped[str] = mapped_column(Text)

    installations: Mapped[list[CertificateInstallation]] = relationship(back_populates="certificate")

    __table_args__ = (
        in_check("certificate_type", CERT_TYPES, "certificate_type"),
        in_check("status", CERT_STATUSES, "status"),
    )


def make_identity_key(server_id: uuid.UUID, service_type: str, cert_path: str | None, vhost: str | None) -> str:
    raw = "\x1f".join([str(server_id), service_type, cert_path or "", vhost or ""])
    return hashlib.sha256(raw.encode()).hexdigest()


class CertificateInstallation(IdMixin, TimestampMixin, Base):
    __tablename__ = "certificate_installations"
    certificate_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("certificates.id", ondelete="SET NULL"), index=True)
    server_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"), index=True)
    service_type: Mapped[str] = mapped_column(String(16))
    service_identifier: Mapped[str | None] = mapped_column(String(255))
    cert_path: Mapped[str | None] = mapped_column(Text)
    key_path: Mapped[str | None] = mapped_column(Text)
    chain_path: Mapped[str | None] = mapped_column(Text)
    fullchain_path: Mapped[str | None] = mapped_column(Text)
    is_combined_pem: Mapped[bool] = mapped_column(default=False, server_default="false")
    listen_port: Mapped[int | None] = mapped_column(Integer)
    config_file: Mapped[str | None] = mapped_column(Text)
    vhost: Mapped[str | None] = mapped_column(String(255))
    server_names: Mapped[list[str]] = mapped_column(server_default="{}", default=list)
    last_observed_fingerprint: Mapped[str | None] = mapped_column(String(64))
    last_observed_at: Mapped[datetime | None]
    last_deployment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("deployment_jobs.id", ondelete="SET NULL", use_alter=True, name="fk_installations_last_deployment")
    )
    drift_status: Mapped[str] = mapped_column(String(16), default="unknown", server_default="unknown")
    classification: Mapped[str] = mapped_column(String(24), default="unmanaged", server_default="unmanaged")
    discovery_confidence: Mapped[float] = mapped_column(default=1.0, server_default="1.0")
    managed_by_certbot: Mapped[bool] = mapped_column(default=False, server_default="false")
    file_metadata: Mapped[dict[str, Any] | None]
    verify_host: Mapped[str | None] = mapped_column(String(255))
    verify_port: Mapped[int | None] = mapped_column(Integer)
    verify_sni: Mapped[str | None] = mapped_column(String(255))
    last_verification: Mapped[dict[str, Any] | None]
    missing_since: Mapped[datetime | None]
    # sha256(server|service|cert_path|coalesce(vhost,'')) — dedupe key (NULL-safe uniqueness)
    identity_key: Mapped[str] = mapped_column(String(64))

    certificate: Mapped[Certificate | None] = relationship(back_populates="installations")

    __table_args__ = (
        UniqueConstraint("server_id", "identity_key", name="uq_installations_server_identity"),
        in_check("drift_status", DRIFT_STATUSES, "drift_status"),
        in_check("classification", CLASSIFICATIONS, "classification"),
        Index("ix_installations_classification", "classification"),
        Index("ix_installations_drift", "drift_status"),
    )


class CertificateVersion(IdMixin, TimestampMixin, Base):
    __tablename__ = "certificate_versions"
    certificate_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("certificates.id", ondelete="SET NULL"), index=True)
    fingerprint_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    leaf_metadata: Mapped[dict[str, Any] | None]
    cert_artifact_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("encrypted_artifacts.id", ondelete="RESTRICT"))
    key_artifact_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("encrypted_artifacts.id", ondelete="RESTRICT"))
    chain_artifact_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("encrypted_artifacts.id", ondelete="RESTRICT"))
    uploaded_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    validation_status: Mapped[str] = mapped_column(String(16), default="pending", server_default="pending")
    findings: Mapped[list[dict[str, Any]]] = mapped_column(server_default="[]", default=list)
    status: Mapped[str] = mapped_column(String(16), default="uploaded", server_default="uploaded")
    reuses_existing_key: Mapped[bool] = mapped_column(default=False, server_default="false")

    __table_args__ = (
        in_check("validation_status", VALIDATION_STATUSES, "validation_status"),
        in_check("status", VERSION_STATUSES, "status"),
    )

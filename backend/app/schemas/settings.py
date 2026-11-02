from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any
from zoneinfo import available_timezones

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GeneralSettings(_Section):
    app_name: str = Field("Cert Deploy Pro", min_length=1, max_length=64)
    timezone: str = "UTC"
    inventory_refresh_minutes: int = Field(360, ge=5, le=10080)
    backup_retention_days: int = Field(90, ge=1, le=3650)

    @field_validator("timezone")
    @classmethod
    def _tz(cls, v: str) -> str:
        if v not in available_timezones():
            raise ValueError("unknown IANA timezone")
        return v


class Thresholds(_Section):
    info: int = Field(60, ge=1, le=730)
    warning: int = Field(30, ge=1, le=730)
    high: int = Field(14, ge=1, le=730)
    critical: int = Field(7, ge=1, le=730)

    @model_validator(mode="after")
    def _ordered(self):
        if not (self.info > self.warning > self.high > self.critical):
            raise ValueError("thresholds must satisfy info > warning > high > critical")
        return self


class NotificationSettings(_Section):
    thresholds: Thresholds = Thresholds()


class SecuritySettings(_Section):
    session_minutes: int = Field(480, ge=5, le=43200)
    require_production_approval: bool = True
    reauth_minutes: int = Field(10, ge=1, le=240)
    # single-admin installs may enable this so the initiator can approve their own production deployment
    allow_self_approval: bool = False
    # optional extra trust anchors (PEM, public certificates only) used when validating uploads and probing endpoints
    trust_anchors_pem: str = Field("", max_length=200_000)

    @field_validator("trust_anchors_pem")
    @classmethod
    def _anchors(cls, v: str) -> str:
        if not v.strip():
            return ""
        if "PRIVATE KEY" in v:
            raise ValueError("trust anchors must not contain private keys")
        from app.integrations.certificates import parse_pem_certificates

        try:
            if not parse_pem_certificates(v.encode()):
                raise ValueError("no certificates found")
        except Exception as exc:
            raise ValueError("trust_anchors_pem must contain valid PEM certificates") from exc
        return v


class SSHSettings(_Section):
    default_port: int = Field(22, ge=1, le=65535)
    connect_timeout: int = Field(10, ge=1, le=120)
    command_timeout: int = Field(60, ge=1, le=3600)
    deployment_concurrency: int = Field(3, ge=1, le=50)
    canary: bool = True
    failure_threshold: int = Field(1, ge=0, le=100)
    discovery_roots: list[str] = Field(
        default_factory=lambda: ["/etc/nginx", "/etc/apache2", "/etc/httpd", "/etc/haproxy", "/etc/ssl",
                                 "/etc/pki", "/etc/letsencrypt"],
        max_length=50,
    )
    discovery_max_depth: int = Field(6, ge=1, le=20)
    discovery_max_files: int = Field(2000, ge=10, le=100000)
    discovery_exclude: list[str] = Field(
        default_factory=lambda: ["/etc/ssl/certs", "/etc/pki/ca-trust", "/usr/share/ca-certificates",
                                 "*/node_modules/*"],
        max_length=100,
    )

    @field_validator("discovery_roots")
    @classmethod
    def _roots(cls, v: list[str]) -> list[str]:
        for p in v:
            if not p.startswith("/") or ".." in p.split("/") or "\x00" in p or "\n" in p:
                raise ValueError(f"discovery root must be an absolute path without '..': {p!r}")
        return v

    @field_validator("discovery_exclude")
    @classmethod
    def _excl(cls, v: list[str]) -> list[str]:
        if any(("\x00" in p or "\n" in p or len(p) > 512) for p in v):
            raise ValueError("invalid exclude pattern")
        return v


SECTION_MODELS: dict[str, type[_Section]] = {
    "general": GeneralSettings,
    "notifications": NotificationSettings,
    "security": SecuritySettings,
    "ssh": SSHSettings,
}


class SettingsPatch(BaseModel):
    version: int = Field(ge=1)
    data: dict[str, Any]


class SettingsSectionOut(BaseModel):
    section: str
    version: int
    data: dict[str, Any]
    updated_at: datetime | None = None
    updated_by: uuid.UUID | None = None

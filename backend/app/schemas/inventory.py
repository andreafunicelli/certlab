"""Request bodies for inventory, discovery, versions and notifications (responses are plain JSON dicts)."""
from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class _Body(BaseModel):
    model_config = ConfigDict(extra="forbid")


class InstallationPatch(_Body):
    verify_host: str | None = Field(None, max_length=255)
    verify_port: int | None = Field(None, ge=1, le=65535)
    verify_sni: str | None = Field(None, max_length=255)
    classification: Literal["managed", "requires_mapping", "unmanaged"] | None = None
    owner: str | None = Field(None, max_length=128)
    tags: list[str] | None = Field(None, max_length=32)

    @field_validator("verify_host", "verify_sni")
    @classmethod
    def _host(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        if any(c in v for c in " /\\\r\n\t\x00@"):
            raise ValueError("invalid host name")
        return v.strip()

    @field_validator("tags")
    @classmethod
    def _tags(cls, v: list[str] | None) -> list[str] | None:
        if v is not None and any((not t) or len(t) > 48 for t in v):
            raise ValueError("tags must be 1-48 characters")
        return v


class BulkDiscovery(_Body):
    server_ids: list[uuid.UUID] = Field(min_length=1, max_length=200)


class ValidateVersion(_Body):
    installation_ids: list[uuid.UUID] = Field(default_factory=list, max_length=500)


Severity = Literal["info", "warning", "high", "critical"]


class ChannelCreate(_Body):
    name: str = Field(min_length=1, max_length=128)
    type: Literal["smtp", "webhook"]
    config: dict[str, Any] = Field(default_factory=dict)
    secret: str | None = Field(None, max_length=1024, repr=False)       # SMTP password / webhook signing secret
    enabled: bool = True


class ChannelUpdate(_Body):
    name: str | None = Field(None, min_length=1, max_length=128)
    config: dict[str, Any] | None = None
    secret: str | None = Field(None, max_length=1024, repr=False)
    clear_secret: bool = False
    enabled: bool | None = None


class RuleCreate(_Body):
    event_type: str = Field(max_length=64)
    channel_id: uuid.UUID
    min_severity: Severity = "info"
    filters: dict[str, Any] = Field(default_factory=dict)
    reminder_interval_hours: int | None = Field(None, ge=1, le=8760)
    enabled: bool = True


class RuleUpdate(_Body):
    event_type: str | None = Field(None, max_length=64)
    channel_id: uuid.UUID | None = None
    min_severity: Severity | None = None
    filters: dict[str, Any] | None = None
    reminder_interval_hours: int | None = Field(None, ge=1, le=8760)
    enabled: bool | None = None

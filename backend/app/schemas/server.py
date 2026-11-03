from __future__ import annotations

import ipaddress
import re
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import ORMModel

_HOST_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")
_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_./-]{0,31}$")
_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")
PrivilegeMode = Literal["helper-sudo", "none"]


def validate_hostname(v: str) -> str:
    v = v.strip()
    try:
        ipaddress.ip_address(v)
        return v
    except ValueError:
        pass
    host = v.removesuffix(".")
    if not host or len(host) > 253 or not all(_HOST_LABEL.match(p) for p in host.split(".")):
        raise ValueError("must be a valid hostname or IP address")
    return v


def validate_address(v: str | None) -> str | None:
    if v is None or v == "":
        return None
    try:
        return str(ipaddress.ip_address(v.strip()))
    except ValueError as exc:
        raise ValueError("must be a valid IPv4/IPv6 address") from exc


def validate_tags(v: list[str]) -> list[str]:
    if len(v) > 20:
        raise ValueError("at most 20 tags")
    out: list[str] = []
    for t in v:
        t = t.strip()
        if not _TAG.match(t):
            raise ValueError(f"invalid tag {t!r}")
        if t not in out:
            out.append(t)
    return out


def _check_user(v: str) -> str:
    if not _USER.match(v):
        raise ValueError("invalid SSH username")
    return v


class _ServerFields(BaseModel):
    @field_validator("hostname", check_fields=False)
    @classmethod
    def _hostname(cls, v):
        return validate_hostname(v) if v is not None else v

    @field_validator("address", check_fields=False)
    @classmethod
    def _address(cls, v):
        return validate_address(v)

    @field_validator("tags", check_fields=False)
    @classmethod
    def _tags(cls, v):
        return validate_tags(v) if v is not None else v

    @field_validator("ssh_username", check_fields=False)
    @classmethod
    def _user(cls, v):
        return _check_user(v) if v is not None else v


class ServerCreate(_ServerFields):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
    hostname: str = Field(max_length=255)
    address: str | None = None
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    ssh_username: str
    credential_id: uuid.UUID | None = None
    bastion_server_id: uuid.UUID | None = None
    privilege_mode: PrivilegeMode = "helper-sudo"
    environment: str = Field(min_length=1, max_length=64)
    tags: list[str] = Field(default_factory=list)
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool = True


class ServerUpdate(_ServerFields):
    name: str | None = Field(default=None, min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
    hostname: str | None = Field(default=None, max_length=255)
    address: str | None = None
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    ssh_username: str | None = None
    credential_id: uuid.UUID | None = None
    bastion_server_id: uuid.UUID | None = None
    privilege_mode: PrivilegeMode | None = None
    environment: str | None = Field(default=None, min_length=1, max_length=64)
    tags: list[str] | None = None
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool | None = None


class ServerOut(ORMModel):
    id: uuid.UUID
    name: str
    hostname: str
    address: str | None
    ssh_port: int
    ssh_username: str
    credential_id: uuid.UUID | None
    credential_name: str | None = None
    bastion_server_id: uuid.UUID | None
    privilege_mode: str
    os_family: str | None
    os_version: str | None
    os_pretty: str | None
    environment: str
    tags: list[str]
    description: str | None
    enabled: bool
    connection_status: str
    host_key_type: str | None
    host_key_fingerprint: str | None
    host_key_enrolled_at: datetime | None
    last_connected_at: datetime | None
    last_discovery_at: datetime | None
    last_discovery_status: str | None
    discovery_error: str | None
    detected_services: Any | None
    installation_count: int = 0
    certificate_count: int = 0
    host_key_reset: bool = False          # true only in the PATCH response that cleared the enrolled host key
    created_at: datetime
    updated_at: datetime


class HostKeyScanOut(BaseModel):
    key_type: str
    fingerprint_sha256: str
    public_key: str


class HostKeyEnroll(BaseModel):
    public_key: str = Field(min_length=20, max_length=8192)
    fingerprint_sha256: str = Field(min_length=10, max_length=100)
    replace: bool = False


class EnvironmentCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
    description: str | None = Field(default=None, max_length=255)
    is_production: bool = False
    requires_approval: bool = False
    require_trusted_chain: bool = False


class EnvironmentUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
    description: str | None = Field(default=None, max_length=255)
    is_production: bool | None = None
    requires_approval: bool | None = None
    require_trusted_chain: bool | None = None


class EnvironmentOut(ORMModel):
    id: uuid.UUID
    name: str
    description: str | None
    is_production: bool
    requires_approval: bool
    require_trusted_chain: bool = False
    server_count: int = 0


# ------------------------------------------------------------------------------ CSV import / bulk host keys
class ImportFieldError(BaseModel):
    field: str
    message: str


class ImportHostKey(BaseModel):
    status: Literal["not_provided", "enrolled", "mismatch", "unreachable", "pending"] = "not_provided"
    fingerprint_expected: str | None = None
    fingerprint_seen: str | None = None
    error: str | None = None


class ImportRowOut(BaseModel):
    row: int
    name: str | None = None
    status: Literal["valid", "error", "skipped", "created"]
    errors: list[ImportFieldError] = Field(default_factory=list)
    server_id: uuid.UUID | None = None
    host_key: ImportHostKey = Field(default_factory=ImportHostKey)


class ImportResultOut(BaseModel):
    dry_run: bool
    delimiter: str
    total: int
    valid: int
    invalid: int
    skipped: int
    created: int
    rows: list[ImportRowOut]


class HostKeyBulkScan(BaseModel):
    server_ids: list[uuid.UUID] = Field(min_length=1, max_length=200)


class HostKeyBulkScanItem(BaseModel):
    server_id: uuid.UUID
    server_name: str | None = None
    endpoint: str | None = None
    key_type: str | None = None
    fingerprint_sha256: str | None = None
    public_key: str | None = None
    enrolled_fingerprint: str | None = None
    matches_enrolled: bool | None = None
    error_code: str | None = None
    error: str | None = None


class HostKeyBulkScanOut(BaseModel):
    items: list[HostKeyBulkScanItem]


class HostKeyBulkEnrollItem(BaseModel):
    server_id: uuid.UUID
    public_key: str = Field(min_length=20, max_length=8192)
    fingerprint_sha256: str = Field(min_length=10, max_length=100)


class HostKeyBulkEnroll(BaseModel):
    items: list[HostKeyBulkEnrollItem] = Field(min_length=1, max_length=200)
    replace: bool = False


class HostKeyBulkEnrollResult(BaseModel):
    server_id: uuid.UUID
    status: Literal["enrolled", "error"]
    error_code: str | None = None
    error: str | None = None


class HostKeyBulkEnrollOut(BaseModel):
    items: list[HostKeyBulkEnrollResult]

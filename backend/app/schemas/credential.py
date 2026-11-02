from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel


class CredentialCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
    private_key: str = Field(min_length=32, max_length=65536, repr=False)
    passphrase: str | None = Field(default=None, max_length=1024, repr=False)


class CredentialRotate(BaseModel):
    private_key: str = Field(min_length=32, max_length=65536, repr=False)
    passphrase: str | None = Field(default=None, max_length=1024, repr=False)


class CredentialOut(ORMModel):
    """Never contains secret material."""
    id: uuid.UUID
    name: str
    type: str
    fingerprint: str
    public_key: str
    key_algorithm: str | None
    has_passphrase: bool
    created_at: datetime
    rotated_at: datetime | None
    server_count: int = 0

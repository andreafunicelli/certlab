from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.schemas.common import ORMModel

_EMAIL_RE = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
_USERNAME_RE = r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$"


class UserOut(ORMModel):
    id: uuid.UUID
    username: str
    email: str
    display_name: str
    auth_provider: str
    enabled: bool
    mfa_enabled: bool
    roles: list[str] = Field(validation_alias="role_names")
    last_login_at: datetime | None
    created_at: datetime


class UserCreate(BaseModel):
    username: str = Field(pattern=_USERNAME_RE)
    email: str = Field(pattern=_EMAIL_RE, max_length=255)
    display_name: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=12, max_length=256)
    roles: list[str] = Field(default_factory=lambda: ["viewer"], min_length=1)
    enabled: bool = True


class UserUpdate(BaseModel):
    email: str | None = Field(default=None, pattern=_EMAIL_RE, max_length=255)
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    enabled: bool | None = None
    password: str | None = Field(default=None, min_length=12, max_length=256)


class RolesUpdate(BaseModel):
    roles: list[str] = Field(min_length=1)

    @field_validator("roles")
    @classmethod
    def _dedupe(cls, v: list[str]) -> list[str]:
        return sorted(set(v))


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=255)
    password: str = Field(min_length=1, max_length=1024)
    totp: str | None = Field(default=None, max_length=16)


class ReauthRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)
    totp: str | None = Field(default=None, max_length=16)


class PasswordChange(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=256)


class MfaEnableRequest(BaseModel):
    code: str = Field(min_length=6, max_length=8)


class MfaDisableRequest(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class MeResponse(BaseModel):
    user: UserOut
    roles: list[str]
    permissions: list[str]
    csrf_token: str

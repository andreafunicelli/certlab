from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, IdMixin, TimestampMixin, in_check

AUTH_PROVIDERS = ("local", "oidc")


class Role(IdMixin, Base):
    __tablename__ = "roles"
    name: Mapped[str] = mapped_column(String(32), unique=True)
    description: Mapped[str | None] = mapped_column(String(255))


class UserRole(Base):
    __tablename__ = "user_roles"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("roles.id", ondelete="RESTRICT"), primary_key=True)
    assigned_at: Mapped[datetime] = mapped_column(server_default=func.now())


class User(IdMixin, TimestampMixin, Base):
    __tablename__ = "users"
    username: Mapped[str] = mapped_column(String(64))
    email: Mapped[str] = mapped_column(String(255))
    display_name: Mapped[str] = mapped_column(String(128))
    auth_provider: Mapped[str] = mapped_column(String(16), default="local", server_default="local")
    oidc_subject: Mapped[str | None] = mapped_column(String(255))
    password_hash: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(default=True, server_default="true")
    mfa_enabled: Mapped[bool] = mapped_column(default=False, server_default="false")
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(Text)
    failed_login_count: Mapped[int] = mapped_column(default=0, server_default="0")
    locked_until: Mapped[datetime | None]
    password_changed_at: Mapped[datetime | None]
    last_login_at: Mapped[datetime | None]

    roles: Mapped[list[Role]] = relationship(secondary="user_roles", lazy="selectin", order_by="Role.name")

    __table_args__ = (
        in_check("auth_provider", AUTH_PROVIDERS, "auth_provider"),
        UniqueConstraint("username", name="uq_users_username"),
        UniqueConstraint("email", name="uq_users_email"),
        Index("uq_users_oidc_subject", "oidc_subject", unique=True, postgresql_where="oidc_subject IS NOT NULL"),
    )

    @property
    def role_names(self) -> list[str]:
        return [r.name for r in self.roles]


class UserSession(IdMixin, Base):
    __tablename__ = "sessions"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    expires_at: Mapped[datetime]
    last_seen_at: Mapped[datetime] = mapped_column(server_default=func.now())
    reauth_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(300))

    user: Mapped[User] = relationship(lazy="joined")

    __table_args__ = (Index("ix_sessions_expires_at", "expires_at"),)

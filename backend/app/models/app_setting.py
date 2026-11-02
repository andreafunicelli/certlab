from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, IdMixin, TimestampMixin


class AppSetting(IdMixin, TimestampMixin, Base):
    __tablename__ = "app_settings"
    section: Mapped[str] = mapped_column(String(32), unique=True)
    data: Mapped[dict[str, Any]] = mapped_column(server_default="{}", default=dict)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))

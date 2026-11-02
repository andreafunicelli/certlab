from __future__ import annotations

from datetime import datetime

from sqlalchemy import BigInteger, Index, LargeBinary, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, IdMixin


class EncryptedArtifact(IdMixin, Base):
    __tablename__ = "encrypted_artifacts"

    purpose: Mapped[str] = mapped_column(String(64))
    key_id: Mapped[str] = mapped_column(String(32))
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary)
    sha256_plain: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(BigInteger)
    filename: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(server_default=func.now())
    deleted_at: Mapped[datetime | None]

    __table_args__ = (Index("ix_encrypted_artifacts_purpose", "purpose"),)


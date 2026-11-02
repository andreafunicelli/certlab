from __future__ import annotations

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import AppSetting


def get(db: Session, section: str) -> AppSetting | None:
    return db.scalar(select(AppSetting).where(AppSetting.section == section))


def all_sections(db: Session) -> list[AppSetting]:
    return list(db.scalars(select(AppSetting).order_by(AppSetting.section)).all())


def compare_and_set(db: Session, section: str, expected_version: int, data: dict, user_id) -> bool:
    """Atomic optimistic update. Returns False if the version no longer matches."""
    from app.models.base import utcnow

    res = db.execute(
        update(AppSetting)
        .where(AppSetting.section == section, AppSetting.version == expected_version)
        .values(data=data, version=expected_version + 1, updated_by=user_id, updated_at=utcnow())
    )
    return (res.rowcount or 0) == 1

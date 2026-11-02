from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models import Role, User, UserRole, UserSession


def get(db: Session, user_id: uuid.UUID) -> User | None:
    return db.get(User, user_id)


def by_username(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(func.lower(User.username) == username.lower()))


def by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(func.lower(User.email) == email.lower()))


def by_oidc_subject(db: Session, subject: str) -> User | None:
    return db.scalar(select(User).where(User.oidc_subject == subject))


def count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(User)) or 0


def count_enabled_admins(db: Session, exclude: uuid.UUID | None = None) -> int:
    q = (
        select(func.count(func.distinct(User.id)))
        .join(UserRole, UserRole.user_id == User.id)
        .join(Role, Role.id == UserRole.role_id)
        .where(Role.name == "admin", User.enabled.is_(True))
    )
    if exclude:
        q = q.where(User.id != exclude)
    return db.scalar(q) or 0


def list_page(db: Session, q: str | None, offset: int, limit: int) -> tuple[list[User], int]:
    stmt = select(User)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(User.username).like(like), func.lower(User.email).like(like),
                              func.lower(User.display_name).like(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(User.username).offset(offset).limit(limit)).all()
    return list(rows), total


def roles_by_names(db: Session, names: list[str]) -> list[Role]:
    return list(db.scalars(select(Role).where(Role.name.in_(names))).all())


def get_session_by_hash(db: Session, token_hash: str) -> UserSession | None:
    return db.scalar(select(UserSession).where(UserSession.token_hash == token_hash))


def revoke_user_sessions(db: Session, user_id: uuid.UUID, now: datetime, except_id: uuid.UUID | None = None) -> None:
    stmt = select(UserSession).where(UserSession.user_id == user_id, UserSession.revoked_at.is_(None))
    for s in db.scalars(stmt):
        if s.id != except_id:
            s.revoked_at = now


def purge_expired_sessions(db: Session, before: datetime) -> int:
    from sqlalchemy import delete

    res = db.execute(delete(UserSession).where(UserSession.expires_at < before))
    return res.rowcount or 0

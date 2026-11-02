from __future__ import annotations

import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import security
from app.core.errors import AppError, conflict, not_found
from app.models import User
from app.models.base import utcnow
from app.repositories import users as repo
from app.schemas.user import RolesUpdate, UserCreate, UserUpdate
from app.services import audit


def _snapshot(u: User) -> dict:
    return {"username": u.username, "email": u.email, "display_name": u.display_name, "enabled": u.enabled,
            "roles": u.role_names, "mfa_enabled": u.mfa_enabled, "auth_provider": u.auth_provider}


def _roles(db: Session, names: list[str]):
    roles = repo.roles_by_names(db, names)
    missing = set(names) - {r.name for r in roles}
    if missing:
        raise AppError("ROLE_NOT_FOUND", f"Unknown role(s): {', '.join(sorted(missing))}", 422)
    return roles


def get(db: Session, user_id: uuid.UUID) -> User:
    u = repo.get(db, user_id)
    if u is None:
        raise not_found("USER_NOT_FOUND", "User not found")
    return u


def create(db: Session, actor: User | None, data: UserCreate) -> User:
    if repo.by_username(db, data.username) or repo.by_email(db, data.email):
        raise conflict("USER_EXISTS", "A user with this username or email already exists")
    u = User(username=data.username, email=data.email, display_name=data.display_name, auth_provider="local",
             password_hash=security.hash_password(data.password), enabled=data.enabled,
             password_changed_at=utcnow())
    u.roles = _roles(db, data.roles)
    db.add(u)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise conflict("USER_EXISTS", "A user with this username or email already exists") from exc
    audit.record(db, action="USER_CREATED", resource_type="user", resource_id=u.id, actor=actor, after=_snapshot(u))
    db.commit()
    return u


def update(db: Session, actor: User, user_id: uuid.UUID, data: UserUpdate) -> User:
    u = get(db, user_id)
    before = _snapshot(u)
    fields = data.model_fields_set
    if "email" in fields and data.email and data.email.lower() != u.email.lower():
        if repo.by_email(db, data.email):
            raise conflict("USER_EXISTS", "Email already in use")
        u.email = data.email
    if "display_name" in fields and data.display_name:
        u.display_name = data.display_name
    if "enabled" in fields and data.enabled is not None and data.enabled != u.enabled:
        if not data.enabled:
            _guard_last_admin(db, u, actor)
            repo.revoke_user_sessions(db, u.id, utcnow())
        u.enabled = data.enabled
    if "password" in fields and data.password:
        if u.auth_provider != "local":
            raise AppError("NOT_LOCAL_USER", "Password cannot be set for SSO users", 400)
        u.password_hash = security.hash_password(data.password)
        u.password_changed_at = utcnow()
        u.failed_login_count = 0
        u.locked_until = None
        repo.revoke_user_sessions(db, u.id, utcnow())
    audit.record(db, action="USER_UPDATED", resource_type="user", resource_id=u.id, actor=actor,
                 before=before, after={**_snapshot(u), **({"password": "changed"} if data.password else {})})
    db.commit()
    return u


def _guard_last_admin(db: Session, target: User, actor: User) -> None:
    if "admin" in target.role_names and repo.count_enabled_admins(db, exclude=target.id) == 0:
        raise AppError("LAST_ADMIN", "At least one enabled administrator must remain", 409)
    if target.id == actor.id:
        raise AppError("CANNOT_MODIFY_SELF", "You cannot disable your own account", 409)


def set_roles(db: Session, actor: User, user_id: uuid.UUID, data: RolesUpdate) -> User:
    u = get(db, user_id)
    before = _snapshot(u)
    new_roles = _roles(db, data.roles)
    if "admin" in u.role_names and "admin" not in data.roles and repo.count_enabled_admins(db, exclude=u.id) == 0:
        raise AppError("LAST_ADMIN", "At least one enabled administrator must remain", 409)
    u.roles = new_roles
    if u.id != actor.id:
        repo.revoke_user_sessions(db, u.id, utcnow())
    audit.record(db, action="USER_ROLES_CHANGED", resource_type="user", resource_id=u.id, actor=actor,
                 before={"roles": before["roles"]}, after={"roles": u.role_names})
    db.commit()
    return u


def delete(db: Session, actor: User, user_id: uuid.UUID) -> None:
    u = get(db, user_id)
    if u.id == actor.id:
        raise AppError("CANNOT_MODIFY_SELF", "You cannot delete your own account", 409)
    if "admin" in u.role_names and u.enabled and repo.count_enabled_admins(db, exclude=u.id) == 0:
        raise AppError("LAST_ADMIN", "At least one enabled administrator must remain", 409)
    snap = _snapshot(u)
    db.delete(u)
    audit.record(db, action="USER_DELETED", resource_type="user", resource_id=user_id, actor=actor, before=snap)
    db.commit()


def bootstrap_admin(db: Session, username: str, password: str, email: str | None) -> User | None:
    """Create the first admin if (and only if) no users exist. Returns the user or None."""
    if repo.count(db) > 0:
        return None
    u = User(username=username, email=email or f"{username}@localhost.invalid", display_name=username,
             auth_provider="local", password_hash=security.hash_password(password), password_changed_at=utcnow())
    u.roles = _roles(db, ["admin"])
    db.add(u)
    db.flush()
    audit.record(db, action="BOOTSTRAP_ADMIN_CREATED", resource_type="user", resource_id=u.id, actor=u,
                 after=_snapshot(u))
    db.commit()
    return u

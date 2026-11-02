from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import AppError, conflict, not_found
from app.models import Environment, Server, User
from app.repositories import servers as repo
from app.schemas.server import (
    EnvironmentCreate,
    EnvironmentOut,
    EnvironmentUpdate,
    ServerCreate,
    ServerOut,
    ServerUpdate,
)
from app.services import audit
from app.services import settings as settings_service


def to_out(s: Server, counts: tuple[int, int] = (0, 0)) -> ServerOut:
    out = ServerOut.model_validate(s)
    out.credential_name = s.credential.name if s.credential else None
    out.installation_count, out.certificate_count = counts
    return out


def _snapshot(s: Server) -> dict[str, Any]:
    return {
        "name": s.name, "hostname": s.hostname, "address": s.address, "ssh_port": s.ssh_port,
        "ssh_username": s.ssh_username, "credential_id": s.credential_id, "bastion_server_id": s.bastion_server_id,
        "privilege_mode": s.privilege_mode, "environment": s.environment, "tags": list(s.tags or []),
        "description": s.description, "enabled": s.enabled,
    }


def get(db: Session, server_id: uuid.UUID) -> Server:
    s = repo.get(db, server_id)
    if s is None:
        raise not_found("SERVER_NOT_FOUND", "Server not found")
    return s


def get_out(db: Session, server_id: uuid.UUID) -> ServerOut:
    s = get(db, server_id)
    return to_out(s, repo.installation_counts(db, [s.id]).get(s.id, (0, 0)))


def list_servers(db: Session, *, offset: int, limit: int, **filters: Any) -> tuple[list[ServerOut], int]:
    rows, total = repo.list_page(db, offset=offset, limit=limit, **filters)
    counts = repo.installation_counts(db, [r.id for r in rows])
    return [to_out(r, counts.get(r.id, (0, 0))) for r in rows], total


def _validate_refs(db: Session, *, environment: str | None, credential_id, bastion_id, self_id=None) -> None:
    if environment is not None and repo.get_environment_by_name(db, environment) is None:
        raise AppError("ENVIRONMENT_NOT_FOUND", f"Environment '{environment}' does not exist", 422)
    if credential_id is not None and repo.get_credential(db, credential_id) is None:
        raise AppError("CREDENTIAL_NOT_FOUND", "Credential does not exist", 422)
    if bastion_id is not None:
        if self_id is not None and bastion_id == self_id:
            raise AppError("INVALID_BASTION", "A server cannot be its own bastion", 422)
        b = repo.get(db, bastion_id)
        if b is None:
            raise AppError("BASTION_NOT_FOUND", "Bastion server does not exist", 422)
        if b.bastion_server_id is not None:
            raise AppError("INVALID_BASTION", "Chained bastions are not supported", 422)


def create(db: Session, actor: User, data: ServerCreate) -> ServerOut:
    if repo.by_name(db, data.name):
        raise conflict("SERVER_EXISTS", "A server with this name already exists")
    _validate_refs(db, environment=data.environment, credential_id=data.credential_id, bastion_id=data.bastion_server_id)
    port = data.ssh_port or settings_service.get_section_data(db, "ssh")["default_port"]
    s = Server(
        name=data.name, hostname=data.hostname, address=data.address, ssh_port=port, ssh_username=data.ssh_username,
        credential_id=data.credential_id, bastion_server_id=data.bastion_server_id,
        privilege_mode=data.privilege_mode, environment=data.environment, tags=data.tags,
        description=data.description, enabled=data.enabled,
    )
    db.add(s)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise conflict("SERVER_EXISTS", "A server with this name already exists") from exc
    audit.record(db, action="SERVER_CREATED", resource_type="server", resource_id=s.id, actor=actor,
                 after=_snapshot(s))
    db.commit()
    db.refresh(s)
    return to_out(s)


def update(db: Session, actor: User, server_id: uuid.UUID, data: ServerUpdate) -> ServerOut:
    s = get(db, server_id)
    before = _snapshot(s)
    f = data.model_fields_set
    for required in ("name", "hostname", "ssh_username", "environment", "privilege_mode", "enabled", "tags", "ssh_port"):
        if required in f and getattr(data, required) is None:
            raise AppError("VALIDATION_ERROR", f"{required} cannot be null", 422)
    if "name" in f and data.name.lower() != s.name.lower() and repo.by_name(db, data.name):  # type: ignore[union-attr]
        raise conflict("SERVER_EXISTS", "A server with this name already exists")
    _validate_refs(
        db, environment=data.environment if "environment" in f else None,
        credential_id=data.credential_id if "credential_id" in f else None,
        bastion_id=data.bastion_server_id if "bastion_server_id" in f else None, self_id=s.id,
    )
    for field in ("name", "hostname", "address", "ssh_port", "ssh_username", "credential_id", "bastion_server_id",
                  "privilege_mode", "environment", "tags", "description", "enabled"):
        if field in f:
            setattr(s, field, getattr(data, field))
    # connection-relevant changes invalidate the enrolled host key only when the address/port changed
    if ({"hostname", "address", "ssh_port"} & f) and s.connection_status == "connected":
        s.connection_status = "unknown"
    audit.record(db, action="SERVER_UPDATED", resource_type="server", resource_id=s.id, actor=actor,
                 before=before, after=_snapshot(s))
    db.commit()
    db.refresh(s)
    return to_out(s, repo.installation_counts(db, [s.id]).get(s.id, (0, 0)))


def set_enabled(db: Session, actor: User, server_id: uuid.UUID, enabled: bool) -> ServerOut:
    return update(db, actor, server_id, ServerUpdate(enabled=enabled))


def delete(db: Session, actor: User, server_id: uuid.UUID) -> None:
    s = get(db, server_id)
    use = repo.usage(db, s.id)
    if use["bastion_for"]:
        raise conflict("SERVER_IN_USE", "Server is used as a bastion by other servers", use)
    if use["deployments"] or use["backups"]:
        raise conflict("SERVER_IN_USE", "Server has deployment/backup history; disable it instead of deleting", use)
    snap = _snapshot(s)
    db.delete(s)
    audit.record(db, action="SERVER_DELETED", resource_type="server", resource_id=server_id, actor=actor, before=snap)
    db.commit()


# ---------------------------------------------------------------- environments
def _env_out(db: Session, e: Environment) -> EnvironmentOut:
    n = db.scalar(select(func.count()).select_from(Server).where(Server.environment == e.name)) or 0
    out = EnvironmentOut.model_validate(e)
    out.server_count = n
    return out


def list_environments(db: Session) -> list[EnvironmentOut]:
    return [_env_out(db, e) for e in db.scalars(select(Environment).order_by(Environment.name))]


def _env(db: Session, env_id: uuid.UUID) -> Environment:
    e = db.get(Environment, env_id)
    if e is None:
        raise not_found("ENVIRONMENT_NOT_FOUND", "Environment not found")
    return e


def create_environment(db: Session, actor: User, data: EnvironmentCreate) -> EnvironmentOut:
    if repo.get_environment_by_name(db, data.name):
        raise conflict("ENVIRONMENT_EXISTS", "An environment with this name already exists")
    e = Environment(**data.model_dump())
    db.add(e)
    db.flush()
    audit.record(db, action="ENVIRONMENT_CREATED", resource_type="environment", resource_id=e.id, actor=actor,
                 after=data.model_dump())
    db.commit()
    return _env_out(db, e)


def update_environment(db: Session, actor: User, env_id: uuid.UUID, data: EnvironmentUpdate) -> EnvironmentOut:
    e = _env(db, env_id)
    before = {"name": e.name, "is_production": e.is_production, "requires_approval": e.requires_approval,
              "description": e.description}
    if "name" in data.model_fields_set and data.name and data.name != e.name:
        if repo.get_environment_by_name(db, data.name):
            raise conflict("ENVIRONMENT_EXISTS", "An environment with this name already exists")
        e.name = data.name
    for field in ("description", "is_production", "requires_approval"):
        if field in data.model_fields_set and (field == "description" or getattr(data, field) is not None):
            setattr(e, field, getattr(data, field))
    audit.record(db, action="ENVIRONMENT_UPDATED", resource_type="environment", resource_id=e.id, actor=actor,
                 before=before, after={"name": e.name, "is_production": e.is_production,
                                       "requires_approval": e.requires_approval, "description": e.description})
    db.commit()
    return _env_out(db, e)


def delete_environment(db: Session, actor: User, env_id: uuid.UUID) -> None:
    e = _env(db, env_id)
    n = db.scalar(select(func.count()).select_from(Server).where(Server.environment == e.name)) or 0
    if n:
        raise conflict("ENVIRONMENT_IN_USE", f"Environment is used by {n} server(s)", {"server_count": n})
    name = e.name
    db.delete(e)
    audit.record(db, action="ENVIRONMENT_DELETED", resource_type="environment", resource_id=env_id, actor=actor,
                 before={"name": name})
    db.commit()

from __future__ import annotations

import uuid

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models import (
    Backup,
    CertificateInstallation,
    Credential,
    DeploymentTarget,
    Environment,
    Server,
)


def get(db: Session, server_id: uuid.UUID) -> Server | None:
    return db.get(Server, server_id)


def by_name(db: Session, name: str) -> Server | None:
    return db.scalar(select(Server).where(func.lower(Server.name) == name.lower()))


def list_page(
    db: Session, *, q: str | None, environment: str | None, status: str | None, enabled: bool | None,
    tag: str | None, offset: int, limit: int,
) -> tuple[list[Server], int]:
    stmt = select(Server)
    if q:
        like = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(Server.name).like(like), func.lower(Server.hostname).like(like),
                              func.lower(func.coalesce(Server.address, "")).like(like)))
    if environment:
        stmt = stmt.where(Server.environment == environment)
    if status:
        stmt = stmt.where(Server.connection_status == status)
    if enabled is not None:
        stmt = stmt.where(Server.enabled.is_(enabled))
    if tag:
        stmt = stmt.where(Server.tags.any(tag))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(Server.name).offset(offset).limit(limit)).unique().all()
    return list(rows), total


def installation_counts(db: Session, server_ids: list[uuid.UUID]) -> dict[uuid.UUID, tuple[int, int]]:
    if not server_ids:
        return {}
    rows = db.execute(
        select(
            CertificateInstallation.server_id,
            func.count(CertificateInstallation.id),
            func.count(func.distinct(CertificateInstallation.certificate_id)),
        )
        .where(CertificateInstallation.server_id.in_(server_ids), CertificateInstallation.missing_since.is_(None))
        .group_by(CertificateInstallation.server_id)
    ).all()
    return {r[0]: (r[1], r[2]) for r in rows}


def usage(db: Session, server_id: uuid.UUID) -> dict[str, int]:
    return {
        "deployments": db.scalar(select(func.count()).select_from(DeploymentTarget).where(DeploymentTarget.server_id == server_id)) or 0,
        "backups": db.scalar(select(func.count()).select_from(Backup).where(Backup.server_id == server_id)) or 0,
        "bastion_for": db.scalar(select(func.count()).select_from(Server).where(Server.bastion_server_id == server_id)) or 0,
    }


def get_credential(db: Session, credential_id: uuid.UUID) -> Credential | None:
    return db.get(Credential, credential_id)


def get_environment_by_name(db: Session, name: str) -> Environment | None:
    return db.scalar(select(Environment).where(Environment.name == name))

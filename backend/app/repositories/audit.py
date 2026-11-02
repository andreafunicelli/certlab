from __future__ import annotations

from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AuditEvent


def list_page(
    db: Session, *, actor: str | None, action: str | None, resource_type: str | None, resource_id: str | None,
    outcome: str | None, ts_from: datetime | None, ts_to: datetime | None, offset: int, limit: int,
) -> tuple[list[AuditEvent], int]:
    stmt = select(AuditEvent)
    if actor:
        stmt = stmt.where(func.lower(AuditEvent.actor_name).like(f"%{actor.lower()}%"))
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if resource_type:
        stmt = stmt.where(AuditEvent.resource_type == resource_type)
    if resource_id:
        stmt = stmt.where(AuditEvent.resource_id == resource_id)
    if outcome:
        stmt = stmt.where(AuditEvent.outcome == outcome)
    if ts_from:
        stmt = stmt.where(AuditEvent.ts >= ts_from)
    if ts_to:
        stmt = stmt.where(AuditEvent.ts <= ts_to)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.scalars(stmt.order_by(AuditEvent.ts.desc(), AuditEvent.id).offset(offset).limit(limit)).all()
    return list(rows), total

"""Audit trail. ``record`` joins the caller's transaction; ``record_independent`` commits on its own."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.context import client_ip_var, correlation_id_var, user_agent_var
from app.core.logging import get_logger, redact
from app.models import AuditEvent, User
from app.repositories import audit as repo

log = get_logger(__name__)


def _build(
    *, action: str, resource_type: str | None, resource_id: Any, actor: User | None, actor_name: str | None,
    before: Any, after: Any, outcome: str, error: str | None,
) -> AuditEvent:
    return AuditEvent(
        actor_user_id=actor.id if actor is not None else None,
        actor_name=(actor.username if actor is not None else actor_name),
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id is not None else None,
        before=redact(before) if before is not None else None,
        after=redact(after) if after is not None else None,
        ip=client_ip_var.get(),
        user_agent=user_agent_var.get(),
        correlation_id=correlation_id_var.get(),
        outcome=outcome,
        error=(error or None) and redact(error)[:2000],
    )


def record(
    db: Session, *, action: str, resource_type: str | None = None, resource_id: Any = None,
    actor: User | None = None, actor_name: str | None = None, before: Any = None, after: Any = None,
    outcome: str = "success", error: str | None = None,
) -> AuditEvent:
    ev = _build(action=action, resource_type=resource_type, resource_id=resource_id, actor=actor,
                actor_name=actor_name, before=before, after=after, outcome=outcome, error=error)
    db.add(ev)
    return ev


def record_independent(**kwargs: Any) -> None:
    """Write an audit event in its own transaction (for failures/denials where the caller rolls back)."""
    from app.core.db import SessionLocal

    db = SessionLocal()
    try:
        record(db, **kwargs)
        db.commit()
    except Exception as exc:  # noqa: BLE001 - audit must never break the request path
        db.rollback()
        log.error("audit_write_failed", error=type(exc).__name__)
    finally:
        db.close()


def list_events(db: Session, **filters: Any):
    return repo.list_page(db, **filters)

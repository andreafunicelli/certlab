"""Notification channels, rules and deliveries.

``notify(db, event_type, severity, payload, dedupe_key)`` is the single entry point for the rest of the platform
(monitoring, discovery, deployments). It creates one pending delivery per matching rule and enqueues
``notifications.deliver(delivery_id)`` once the caller's transaction commits (or immediately with ``commit=True``).
"""
from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import event as sa_event
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.crypto import VaultError, get_vault
from app.core.errors import AppError, conflict, not_found
from app.core.logging import get_logger, redact
from app.integrations.notify import (
    ChannelError,
    Message,
    send_smtp,
    send_webhook,
    validate_smtp_config,
    validate_webhook_config,
)
from app.models import NotificationChannel, NotificationDelivery, NotificationRule, User
from app.models.base import utcnow
from app.services import audit

log = get_logger(__name__)

EVENT_TYPES = (
    "cert.expiring", "cert.expired", "server.unreachable", "discovery.failed", "deployment.completed",
    "deployment.failed", "rollback.triggered", "rollback.failed", "drift.detected", "hostkey.changed",
)
SEVERITY_ORDER = {"info": 0, "warning": 1, "high": 2, "critical": 3}
MAX_ATTEMPTS = 6


# ------------------------------------------------------------------------------------------------ rendering
def render(event_type: str, severity: str, payload: dict[str, Any]) -> tuple[str, str]:
    p = payload
    subject_by_event = {
        "cert.expiring": lambda: f"Certificate {p.get('common_name') or p.get('certificate_id')} expires in "
                                 f"{p.get('days_remaining')} day(s)",
        "cert.expired": lambda: f"Certificate {p.get('common_name') or p.get('certificate_id')} has expired",
        "server.unreachable": lambda: f"Server {p.get('server_name')} is unreachable",
        "discovery.failed": lambda: f"Discovery failed on {p.get('server_name')}",
        "deployment.completed": lambda: f"Deployment {p.get('deployment_id')} completed",
        "deployment.failed": lambda: f"Deployment {p.get('deployment_id')} failed",
        "rollback.triggered": lambda: f"Rollback triggered for deployment {p.get('deployment_id')}",
        "rollback.failed": lambda: f"Rollback FAILED for deployment {p.get('deployment_id')}",
        "drift.detected": lambda: f"Configuration drift detected on {p.get('server_name')}",
        "hostkey.changed": lambda: f"SSH host key changed on {p.get('server_name')}",
    }
    try:
        subject = subject_by_event.get(event_type, lambda: event_type)()
    except Exception:  # noqa: BLE001
        subject = event_type
    lines = [subject, "", f"Event: {event_type}", f"Severity: {severity}"]
    for k in sorted(p):
        v = p[k]
        if isinstance(v, (str, int, float, bool)) or v is None:
            lines.append(f"{k}: {v}")
    return f"[Cert Deploy Pro] [{severity.upper()}] {subject}", "\n".join(lines)


# ------------------------------------------------------------------------------------------------ routing
def _filters_match(filters: dict[str, Any], payload: dict[str, Any]) -> bool:
    env_filter = (filters or {}).get("environment")
    if env_filter:
        wanted = {env_filter} if isinstance(env_filter, str) else set(env_filter)
        have = set(payload.get("environments") or [])
        if payload.get("environment"):
            have.add(payload["environment"])
        if not (wanted & have):
            return False
    return True


def _flush_pending(db: Session) -> None:
    from app.workers.celery_app import enqueue

    ids = db.info.pop("cdp_pending_deliveries", [])
    for did in ids:
        try:
            enqueue("notifications.deliver", str(did))
        except Exception as exc:  # noqa: BLE001 - delivery stays pending; the periodic sweep re-enqueues it
            log.warning("notification_enqueue_failed", error=type(exc).__name__)


def _enqueue_after_commit(db: Session, delivery_ids: list[uuid.UUID], *, commit: bool) -> None:
    """Enqueue only once the deliveries are durable; a rollback discards them (nothing is enqueued)."""
    db.info.setdefault("cdp_pending_deliveries", []).extend(delivery_ids)
    if commit:
        db.commit()
        _flush_pending(db)
        return
    if not db.info.get("cdp_delivery_hooks"):
        db.info["cdp_delivery_hooks"] = True
        sa_event.listen(db, "after_commit", _flush_pending)
        sa_event.listen(db, "after_rollback", lambda session: session.info.pop("cdp_pending_deliveries", None))


def notify(db: Session, event_type: str, severity: str, payload: dict[str, Any], dedupe_key: str, *,
           commit: bool = False) -> list[NotificationDelivery]:
    """Create deliveries for every enabled rule matching ``event_type``/``severity``/filters.

    Dedupe: a rule does not receive the same ``dedupe_key`` again unless its ``reminder_interval_hours`` elapsed
    since the last delivery created for that key. Failed deliveries do not suppress later attempts.
    """
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown notification event type {event_type!r}")
    if severity not in SEVERITY_ORDER:
        raise ValueError(f"unknown severity {severity!r}")
    safe_payload = redact(payload)
    now = utcnow()
    rules = db.execute(
        select(NotificationRule, NotificationChannel)
        .join(NotificationChannel, NotificationChannel.id == NotificationRule.channel_id)
        .where(NotificationRule.event_type == event_type, NotificationRule.enabled.is_(True),
               NotificationChannel.enabled.is_(True))
        .order_by(NotificationRule.created_at)
    ).all()
    created: list[NotificationDelivery] = []
    subject, text = render(event_type, severity, safe_payload)
    for rule, channel in rules:
        if SEVERITY_ORDER[severity] < SEVERITY_ORDER.get(rule.min_severity, 0):
            continue
        if not _filters_match(rule.filters or {}, safe_payload):
            continue
        last = db.scalar(
            select(NotificationDelivery.created_at)
            .where(NotificationDelivery.rule_id == rule.id, NotificationDelivery.dedupe_key == dedupe_key,
                   NotificationDelivery.status.in_(("pending", "sent")))
            .order_by(NotificationDelivery.created_at.desc()).limit(1)
        )
        if last is not None and (
            not rule.reminder_interval_hours or now - last < timedelta(hours=rule.reminder_interval_hours)
        ):
            continue
        d = NotificationDelivery(
            rule_id=rule.id, channel_id=channel.id, event_type=event_type, dedupe_key=dedupe_key[:255],
            payload={"severity": severity, "subject": subject, "text": text, "data": safe_payload},
            status="pending",
        )
        db.add(d)
        created.append(d)
    if created:
        db.flush()
        _enqueue_after_commit(db, [d.id for d in created], commit=commit)
    elif commit:
        db.commit()
    return created


# ------------------------------------------------------------------------------------------------ delivery
def _secret(channel: NotificationChannel) -> str | None:
    if not channel.secret_encrypted:
        return None
    try:
        return get_vault().decrypt_value(channel.secret_encrypted)
    except VaultError as exc:
        raise ChannelError("channel secret cannot be decrypted (master key changed?)", retryable=False) from exc


def send_via_channel(channel: NotificationChannel, msg: Message) -> None:
    secret = _secret(channel)
    if channel.type == "smtp":
        send_smtp(channel.config, secret, msg)
    elif channel.type == "webhook":
        send_webhook(channel.config, secret, msg)
    else:  # pragma: no cover - guarded by a CHECK constraint
        raise ChannelError(f"unsupported channel type {channel.type}", retryable=False)


def attempt_delivery(db: Session, delivery_id: uuid.UUID) -> str:
    """One delivery attempt. Returns "sent" | "retry" | "failed" | "skipped"."""
    d = db.get(NotificationDelivery, delivery_id, with_for_update=True)
    if d is None or d.status in ("sent", "failed", "skipped"):
        return "skipped"
    channel = db.get(NotificationChannel, d.channel_id) if d.channel_id else None
    if channel is None or not channel.enabled:
        d.status, d.last_error = "skipped", "channel deleted or disabled"
        db.commit()
        return "skipped"
    d.attempts += 1
    data = d.payload or {}
    msg = Message(event_type=d.event_type, severity=data.get("severity", "info"), subject=data.get("subject", d.event_type),
                  text=data.get("text", ""), payload=data.get("data", {}), event_id=str(d.id),
                  created_at=d.created_at.isoformat() if d.created_at else "")
    try:
        send_via_channel(channel, msg)
    except ChannelError as exc:
        d.last_error = exc.message[:500]
        final = (not exc.retryable) or d.attempts >= MAX_ATTEMPTS
        d.status = "failed" if final else "pending"
        db.commit()
        log.warning("notification_delivery_failed", delivery_id=str(d.id), channel=channel.name, attempts=d.attempts,
                    final=final, reason=d.last_error)
        return "failed" if final else "retry"
    d.status, d.sent_at, d.last_error = "sent", utcnow(), None
    db.commit()
    return "sent"


def retry_pending(db: Session, older_than_minutes: int = 10) -> list[uuid.UUID]:
    """Deliveries stuck in 'pending' (lost broker message / worker crash) — to be re-enqueued by a sweep."""
    cutoff = utcnow() - timedelta(minutes=older_than_minutes)
    return list(db.scalars(select(NotificationDelivery.id).where(
        NotificationDelivery.status == "pending", NotificationDelivery.updated_at < cutoff).limit(200)))


# ------------------------------------------------------------------------------------------------ channels CRUD
def _validate_config(type_: str, config: dict[str, Any]) -> dict[str, Any]:
    try:
        if type_ == "smtp":
            return validate_smtp_config(config)
        if type_ == "webhook":
            return validate_webhook_config(config)
    except (ValueError, TypeError) as exc:
        raise AppError("INVALID_CHANNEL_CONFIG", str(exc), 422) from exc
    raise AppError("INVALID_CHANNEL_TYPE", "type must be smtp or webhook", 422)


def channel_out(c: NotificationChannel) -> dict[str, Any]:
    return {"id": c.id, "name": c.name, "type": c.type, "config": c.config, "has_secret": bool(c.secret_encrypted),
            "enabled": c.enabled, "created_at": c.created_at, "updated_at": c.updated_at}


def _channel(db: Session, channel_id: uuid.UUID) -> NotificationChannel:
    c = db.get(NotificationChannel, channel_id)
    if c is None:
        raise not_found("CHANNEL_NOT_FOUND", "Notification channel not found")
    return c


def list_channels(db: Session) -> list[dict[str, Any]]:
    return [channel_out(c) for c in db.scalars(select(NotificationChannel).order_by(NotificationChannel.name))]


def get_channel(db: Session, channel_id: uuid.UUID) -> dict[str, Any]:
    return channel_out(_channel(db, channel_id))


def create_channel(db: Session, actor: User, *, name: str, type: str, config: dict[str, Any],
                   secret: str | None, enabled: bool) -> dict[str, Any]:
    if db.scalar(select(NotificationChannel.id).where(func.lower(NotificationChannel.name) == name.lower())):
        raise conflict("CHANNEL_EXISTS", "A channel with this name already exists")
    c = NotificationChannel(name=name, type=type, config=_validate_config(type, config), enabled=enabled,
                            secret_encrypted=get_vault().encrypt_value(secret) if secret else None)
    db.add(c)
    db.flush()
    audit.record(db, action="NOTIFICATION_CHANNEL_CREATED", resource_type="notification_channel", resource_id=c.id,
                 actor=actor, after={"name": name, "type": type, "config": c.config, "has_secret": bool(secret)})
    db.commit()
    return channel_out(c)


def update_channel(db: Session, actor: User, channel_id: uuid.UUID, *, fields: set[str], name: str | None,
                   config: dict[str, Any] | None, secret: str | None, clear_secret: bool,
                   enabled: bool | None) -> dict[str, Any]:
    c = _channel(db, channel_id)
    before = {"name": c.name, "config": c.config, "enabled": c.enabled, "has_secret": bool(c.secret_encrypted)}
    if "name" in fields and name:
        if name.lower() != c.name.lower() and db.scalar(
                select(NotificationChannel.id).where(func.lower(NotificationChannel.name) == name.lower())):
            raise conflict("CHANNEL_EXISTS", "A channel with this name already exists")
        c.name = name
    if "config" in fields and config is not None:
        c.config = _validate_config(c.type, config)
    if secret:
        c.secret_encrypted = get_vault().encrypt_value(secret)
    elif clear_secret:
        c.secret_encrypted = None
    if "enabled" in fields and enabled is not None:
        c.enabled = enabled
    audit.record(db, action="NOTIFICATION_CHANNEL_UPDATED", resource_type="notification_channel", resource_id=c.id,
                 actor=actor, before=before,
                 after={"name": c.name, "config": c.config, "enabled": c.enabled, "has_secret": bool(c.secret_encrypted),
                        "secret_changed": bool(secret) or clear_secret})
    db.commit()
    return channel_out(c)


def delete_channel(db: Session, actor: User, channel_id: uuid.UUID) -> None:
    c = _channel(db, channel_id)
    snap = {"name": c.name, "type": c.type}
    db.delete(c)
    audit.record(db, action="NOTIFICATION_CHANNEL_DELETED", resource_type="notification_channel", resource_id=channel_id,
                 actor=actor, before=snap)
    db.commit()


def test_channel(db: Session, actor: User, channel_id: uuid.UUID) -> dict[str, Any]:
    c = _channel(db, channel_id)
    now = utcnow()
    subject = "[Cert Deploy Pro] Test notification"
    msg = Message("test", "info", subject, "This is a test notification from Cert Deploy Pro.",
                  {"channel": c.name}, event_id=str(uuid.uuid4()), created_at=now.isoformat())
    err: str | None = None
    try:
        send_via_channel(c, msg)
    except ChannelError as exc:
        err = exc.message
    db.add(NotificationDelivery(
        rule_id=None, channel_id=c.id, event_type="test", dedupe_key=f"test:{msg.event_id}",
        payload={"severity": "info", "subject": subject, "text": msg.text, "data": msg.payload},
        status="failed" if err else "sent", attempts=1, last_error=err, sent_at=None if err else now))
    audit.record(db, action="NOTIFICATION_CHANNEL_TESTED", resource_type="notification_channel", resource_id=c.id,
                 actor=actor, outcome="failure" if err else "success", error=err)
    db.commit()
    return {"ok": err is None, "error": err}


# ------------------------------------------------------------------------------------------------ rules CRUD
def rule_out(r: NotificationRule) -> dict[str, Any]:
    return {"id": r.id, "event_type": r.event_type, "channel_id": r.channel_id, "min_severity": r.min_severity,
            "filters": r.filters or {}, "reminder_interval_hours": r.reminder_interval_hours, "enabled": r.enabled,
            "created_at": r.created_at, "updated_at": r.updated_at}


def _check_rule(event_type: str | None, filters: dict[str, Any] | None) -> None:
    if event_type is not None and event_type not in EVENT_TYPES:
        raise AppError("INVALID_EVENT_TYPE", f"event_type must be one of {', '.join(EVENT_TYPES)}", 422)
    if filters:
        extra = set(filters) - {"environment"}
        if extra:
            raise AppError("INVALID_FILTER", f"unsupported filter(s): {', '.join(sorted(extra))}", 422)


def list_rules(db: Session) -> list[dict[str, Any]]:
    return [rule_out(r) for r in db.scalars(select(NotificationRule).order_by(NotificationRule.event_type,
                                                                              NotificationRule.created_at))]


def create_rule(db: Session, actor: User, **data: Any) -> dict[str, Any]:
    _check_rule(data["event_type"], data.get("filters"))
    _channel(db, data["channel_id"])
    r = NotificationRule(**data)
    db.add(r)
    db.flush()
    audit.record(db, action="NOTIFICATION_RULE_CREATED", resource_type="notification_rule", resource_id=r.id,
                 actor=actor, after=rule_out(r))
    db.commit()
    return rule_out(r)


def update_rule(db: Session, actor: User, rule_id: uuid.UUID, data: dict[str, Any]) -> dict[str, Any]:
    r = db.get(NotificationRule, rule_id)
    if r is None:
        raise not_found("RULE_NOT_FOUND", "Notification rule not found")
    _check_rule(data.get("event_type"), data.get("filters"))
    if "channel_id" in data:
        _channel(db, data["channel_id"])
    before = rule_out(r)
    for k, v in data.items():
        setattr(r, k, v)
    audit.record(db, action="NOTIFICATION_RULE_UPDATED", resource_type="notification_rule", resource_id=r.id,
                 actor=actor, before=before, after=rule_out(r))
    db.commit()
    return rule_out(r)


def delete_rule(db: Session, actor: User, rule_id: uuid.UUID) -> None:
    r = db.get(NotificationRule, rule_id)
    if r is None:
        raise not_found("RULE_NOT_FOUND", "Notification rule not found")
    snap = rule_out(r)
    db.delete(r)
    audit.record(db, action="NOTIFICATION_RULE_DELETED", resource_type="notification_rule", resource_id=rule_id,
                 actor=actor, before=snap)
    db.commit()


# ------------------------------------------------------------------------------------------------ deliveries
def list_deliveries(db: Session, *, offset: int, limit: int, status: str | None = None, event_type: str | None = None,
                    channel_id: uuid.UUID | None = None) -> tuple[list[dict[str, Any]], int]:
    stmt = select(NotificationDelivery, NotificationChannel.name).outerjoin(
        NotificationChannel, NotificationChannel.id == NotificationDelivery.channel_id)
    if status:
        stmt = stmt.where(NotificationDelivery.status == status)
    if event_type:
        stmt = stmt.where(NotificationDelivery.event_type == event_type)
    if channel_id:
        stmt = stmt.where(NotificationDelivery.channel_id == channel_id)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    rows = db.execute(stmt.order_by(NotificationDelivery.created_at.desc()).offset(offset).limit(limit)).all()
    items = [{
        "id": d.id, "rule_id": d.rule_id, "channel_id": d.channel_id, "channel_name": name,
        "event_type": d.event_type, "severity": (d.payload or {}).get("severity"),
        "subject": (d.payload or {}).get("subject"), "dedupe_key": d.dedupe_key, "status": d.status,
        "attempts": d.attempts, "last_error": d.last_error, "sent_at": d.sent_at, "created_at": d.created_at,
    } for d, name in rows]
    return items, total

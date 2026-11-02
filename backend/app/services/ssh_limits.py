"""Apply the ``ssh`` settings section to the SSH layer's process-wide limits (known issue K10).

``connection.set_host_concurrency_limit`` is process-local, so it must run in every worker process: at worker start, at
the start of every deployment / restore task (picks up changes made through the API since), and in the API process when the
section is saved.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.services import settings as settings_service

log = get_logger(__name__)


def apply(db: Session) -> int:
    """Set the per-host SSH session limit from ``ssh.host_concurrency``; returns the effective limit."""
    from app.integrations.ssh import connection

    limit = int(settings_service.get_section_data(db, "ssh").get("host_concurrency", 4))
    if limit != connection._default_limit:        # the setter clears the semaphores: only touch them on a real change
        connection.set_host_concurrency_limit(limit)
        log.info("ssh_host_concurrency_applied", limit=limit)
    return limit


def apply_from_db() -> int | None:
    """Best effort for worker start / task start: a settings problem must never prevent the work itself."""
    from app.core.db import SessionLocal

    try:
        with SessionLocal() as db:
            return apply(db)
    except Exception as exc:  # noqa: BLE001
        log.warning("ssh_host_concurrency_apply_failed", error=type(exc).__name__)
        return None


def on_settings_changed(section: str, data: dict[str, Any]) -> None:
    if section != "ssh":
        return
    from app.integrations.ssh import connection

    limit = int(data.get("host_concurrency", 4))
    if limit != connection._default_limit:
        connection.set_host_concurrency_limit(limit)

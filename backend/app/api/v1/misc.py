from __future__ import annotations

from datetime import datetime
from typing import Any

import redis as redis_lib
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.config import get_settings
from app.core.db import get_db
from app.schemas.common import Page, PageParams
from app.schemas.misc import AuditEventOut
from app.schemas.settings import SettingsPatch, SettingsSectionOut
from app.services import audit as audit_service
from app.services import dashboard as dashboard_service
from app.services import settings as settings_service
from app.services.auth import AuthContext

router = APIRouter()


# ---------------------------------------------------------------- health
@router.get("/healthz", tags=["health"])
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", tags=["health"])
def readyz(db: Session = Depends(get_db)):
    checks: dict[str, str] = {}
    try:
        db.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:  # noqa: BLE001 - health probe must never raise
        checks["database"] = "unavailable"
    try:
        redis_lib.Redis.from_url(get_settings().redis_url, socket_connect_timeout=1, socket_timeout=1).ping()
        checks["redis"] = "ok"
    except Exception:  # noqa: BLE001 - health probe must never raise
        checks["redis"] = "unavailable"
    ready = all(v == "ok" for v in checks.values())
    return JSONResponse({"status": "ready" if ready else "not_ready", "checks": checks}, status_code=200 if ready else 503)


# ---------------------------------------------------------------- settings
@router.get("/settings", response_model=dict[str, SettingsSectionOut], tags=["settings"])
def get_settings_all(_: AuthContext = Depends(require_permission("settings:read")), db: Session = Depends(get_db)):
    return settings_service.get_all(db)


@router.patch("/settings/{section}", response_model=SettingsSectionOut, tags=["settings"])
def patch_settings(section: str, body: SettingsPatch, ctx: AuthContext = Depends(require_permission("settings:write")),
                   db: Session = Depends(get_db)):
    return settings_service.update_section(db, ctx.user, section, body.version, body.data)


# ---------------------------------------------------------------- audit

@router.get("/audit-events", response_model=Page[AuditEventOut], tags=["audit"])
def list_audit_events(
    actor: str | None = Query(None, max_length=128), action: str | None = Query(None, max_length=64),
    resource_type: str | None = Query(None, max_length=48), resource_id: str | None = Query(None, max_length=64),
    outcome: str | None = Query(None, pattern="^(success|failure|denied)$"),
    from_: datetime | None = Query(None, alias="from"), to: datetime | None = None,
    p: PageParams = Depends(), _: AuthContext = Depends(require_permission("audit:read")),
    db: Session = Depends(get_db),
):
    rows, total = audit_service.list_events(
        db, actor=actor, action=action, resource_type=resource_type, resource_id=resource_id, outcome=outcome,
        ts_from=from_, ts_to=to, offset=p.offset, limit=p.page_size)
    return Page(items=[AuditEventOut.model_validate(r) for r in rows], total=total, page=p.page, page_size=p.page_size)


# ---------------------------------------------------------------- dashboard
@router.get("/dashboard/summary", tags=["dashboard"])
def dashboard_summary(_: AuthContext = Depends(require_permission("dashboard:read")),
                      db: Session = Depends(get_db)) -> dict[str, Any]:
    return dashboard_service.summary(db)


@router.get("/dashboard/expiry-trend", tags=["dashboard"])
def dashboard_expiry_trend(_: AuthContext = Depends(require_permission("dashboard:read")),
                           db: Session = Depends(get_db)) -> dict[str, Any]:
    return dashboard_service.expiry_trend(db)

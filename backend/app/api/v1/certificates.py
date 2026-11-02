from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.db import get_db
from app.schemas.common import Page, PageParams
from app.services import inventory
from app.services.auth import AuthContext

router = APIRouter(prefix="/certificates", tags=["certificates"])


@router.get("", response_model=Page[dict[str, Any]])
def list_certificates(
    q: str | None = Query(None, max_length=200),
    status: str | None = Query(None, description="valid|info|warning|high|critical|expired|expiring"),
    expiring_within: int | None = Query(None, ge=0, le=3650, description="days"),
    server_id: uuid.UUID | None = None, environment: str | None = None,
    include_ca: bool = False, sort: str = "not_after", p: PageParams = Depends(),
    _: AuthContext = Depends(require_permission("certificates:read")), db: Session = Depends(get_db),
):
    items, total = inventory.list_certificates(
        db, q=q, status=status, expiring_within=expiring_within, server_id=server_id, environment=environment,
        include_ca=include_ca, sort=sort, offset=p.offset, limit=p.page_size)
    return Page(items=items, total=total, page=p.page, page_size=p.page_size)


@router.get("/{certificate_id}")
def get_certificate(certificate_id: uuid.UUID, _: AuthContext = Depends(require_permission("certificates:read")),
                    db: Session = Depends(get_db)) -> dict[str, Any]:
    return inventory.certificate_detail(db, certificate_id)


@router.post("/{certificate_id}/verify")
def verify_certificate(certificate_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("certificates:verify")),
                       db: Session = Depends(get_db)) -> dict[str, Any]:
    return inventory.verify_certificate(db, ctx.user, certificate_id)

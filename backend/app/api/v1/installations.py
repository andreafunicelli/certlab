from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.db import get_db
from app.schemas.common import Page, PageParams
from app.schemas.inventory import InstallationPatch
from app.services import inventory
from app.services import servers as servers_service
from app.services.auth import AuthContext

router = APIRouter(tags=["installations"])


@router.get("/installations", response_model=Page[dict[str, Any]])
def list_installations(
    server_id: uuid.UUID | None = None, certificate_id: uuid.UUID | None = None, classification: str | None = None,
    drift_status: str | None = None, service_type: str | None = None, environment: str | None = None,
    q: str | None = Query(None, max_length=200), include_missing: bool = True, p: PageParams = Depends(),
    _: AuthContext = Depends(require_permission("installations:read")), db: Session = Depends(get_db),
):
    items, total = inventory.list_installations(
        db, offset=p.offset, limit=p.page_size, server_id=server_id, certificate_id=certificate_id,
        classification=classification, drift_status=drift_status, service_type=service_type, environment=environment,
        q=q, include_missing=include_missing)
    return Page(items=items, total=total, page=p.page, page_size=p.page_size)


@router.get("/servers/{server_id}/installations", response_model=Page[dict[str, Any]])
def server_installations(server_id: uuid.UUID, p: PageParams = Depends(), include_missing: bool = True,
                         _: AuthContext = Depends(require_permission("installations:read")),
                         db: Session = Depends(get_db)):
    servers_service.get(db, server_id)
    items, total = inventory.list_installations(db, offset=p.offset, limit=p.page_size, server_id=server_id,
                                                include_missing=include_missing)
    return Page(items=items, total=total, page=p.page, page_size=p.page_size)


@router.get("/installations/{installation_id}")
def get_installation(installation_id: uuid.UUID, _: AuthContext = Depends(require_permission("installations:read")),
                     db: Session = Depends(get_db)) -> dict[str, Any]:
    return inventory.installation_view(db, inventory.get_installation(db, installation_id))


@router.patch("/installations/{installation_id}")
def patch_installation(installation_id: uuid.UUID, body: InstallationPatch,
                       ctx: AuthContext = Depends(require_permission("installations:write")),
                       db: Session = Depends(get_db)) -> dict[str, Any]:
    data = {k: getattr(body, k) for k in body.model_fields_set}
    return inventory.update_installation(db, ctx.user, installation_id, data)


@router.post("/installations/{installation_id}/verify")
def verify_installation(installation_id: uuid.UUID,
                        ctx: AuthContext = Depends(require_permission("installations:verify")),
                        db: Session = Depends(get_db)) -> dict[str, Any]:
    return inventory.verify_installation(db, ctx.user, installation_id)

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.db import get_db
from app.schemas.common import Page, PageParams
from app.schemas.inventory import BulkDiscovery
from app.services import discovery, events
from app.services import servers as servers_service
from app.services.auth import AuthContext

router = APIRouter(tags=["discovery"])


@router.post("/discovery-jobs/bulk", status_code=202)
def bulk(body: BulkDiscovery, ctx: AuthContext = Depends(require_permission("discovery:run")),
         db: Session = Depends(get_db)) -> dict[str, Any]:
    return discovery.start_bulk(db, ctx.user, body.server_ids)


@router.get("/discovery-jobs", response_model=Page[dict[str, Any]])
def list_jobs(server_id: uuid.UUID | None = None, status: str | None = None, p: PageParams = Depends(),
              _: AuthContext = Depends(require_permission("discovery:read")), db: Session = Depends(get_db)):
    items, total = discovery.list_jobs(db, offset=p.offset, limit=p.page_size, server_id=server_id, status=status)
    return Page(items=items, total=total, page=p.page, page_size=p.page_size)


@router.get("/discovery-jobs/{job_id}")
def get_job(job_id: uuid.UUID, _: AuthContext = Depends(require_permission("discovery:read")),
            db: Session = Depends(get_db)) -> dict[str, Any]:
    return discovery.get_job(db, job_id)


@router.get("/discovery-jobs/{job_id}/events")
def job_events(job_id: uuid.UUID, _: AuthContext = Depends(require_permission("discovery:read")),
               db: Session = Depends(get_db)):
    discovery.get_job(db, job_id)             # 404 if unknown
    db.rollback()
    return StreamingResponse(events.sse_stream("discovery", job_id), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/servers/{server_id}/discovery-jobs", response_model=Page[dict[str, Any]])
def server_jobs(server_id: uuid.UUID, p: PageParams = Depends(),
                _: AuthContext = Depends(require_permission("discovery:read")), db: Session = Depends(get_db)):
    servers_service.get(db, server_id)
    items, total = discovery.list_jobs(db, offset=p.offset, limit=p.page_size, server_id=server_id)
    return Page(items=items, total=total, page=p.page, page_size=p.page_size)

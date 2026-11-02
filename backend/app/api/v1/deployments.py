from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.db import get_db
from app.schemas.common import Page, PageParams
from app.services import deployments as service
from app.services import events
from app.services.auth import AuthContext

router = APIRouter(tags=["deployments"])


class StrategyIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: str | None = Field(None, pattern="^(canary|batch|all)$")
    concurrency: int | None = Field(None, ge=1, le=50)
    failure_threshold: int | None = Field(None, ge=0, le=100)
    continue_on_failure: bool = False
    allow_restart: bool = False
    allow_file_only_verification: bool = False
    verify_retries: int | None = Field(None, ge=1, le=30)
    verify_delay_seconds: float | None = Field(None, ge=0, le=60)


class ExceptionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(max_length=64)
    justification: str = Field(min_length=10, max_length=1000)
    installation_id: uuid.UUID | None = None


class DeploymentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version_id: uuid.UUID
    installation_ids: list[uuid.UUID] = Field(min_length=1, max_length=200)
    strategy: StrategyIn | None = None
    acknowledged_warnings: list[str] = Field(default_factory=list, max_length=100)
    exception_approvals: list[ExceptionIn] = Field(default_factory=list, max_length=50)

    def as_body(self) -> dict[str, Any]:
        d = self.model_dump(mode="python")
        if d["strategy"] is not None:
            d["strategy"] = {k: v for k, v in d["strategy"].items() if v is not None}
        return d


@router.post("/deployments/plan")
def plan(body: DeploymentRequest, ctx: AuthContext = Depends(require_permission("deployments:plan")),
         db: Session = Depends(get_db)) -> dict[str, Any]:
    return service.plan(db, ctx.user, body.as_body())


@router.post("/deployments", status_code=201)
def create(body: DeploymentRequest, idempotency_key: str | None = Header(None, alias="Idempotency-Key"),
           ctx: AuthContext = Depends(require_permission("deployments:create")), db: Session = Depends(get_db)):
    job, created = service.create(db, ctx.user, idempotency_key, body.as_body())
    out = service.job_out(db, job, detail=True)
    out["idempotent_replay"] = not created
    return out


@router.get("/deployments", response_model=Page[dict[str, Any]])
def list_deployments(status: str | None = None, version_id: uuid.UUID | None = None, server_id: uuid.UUID | None = None,
                     initiated_by: uuid.UUID | None = None, since: datetime | None = None, until: datetime | None = None,
                     q: str | None = Query(None, max_length=40), p: PageParams = Depends(),
                     _: AuthContext = Depends(require_permission("deployments:read")), db: Session = Depends(get_db)):
    rows, total = service.list_jobs(db, offset=p.offset, limit=p.page_size, status=status, version_id=version_id,
                                    server_id=server_id, initiated_by=initiated_by, since=since, until=until, q=q)
    return Page(items=[service.job_out(db, j) for j in rows], total=total, page=p.page, page_size=p.page_size)


@router.get("/servers/{server_id}/deployments", response_model=Page[dict[str, Any]])
def server_deployments(server_id: uuid.UUID, p: PageParams = Depends(),
                       _: AuthContext = Depends(require_permission("deployments:read")), db: Session = Depends(get_db)):
    rows, total = service.list_jobs(db, offset=p.offset, limit=p.page_size, server_id=server_id)
    return Page(items=[service.job_out(db, j) for j in rows], total=total, page=p.page, page_size=p.page_size)


@router.get("/deployments/{deployment_id}")
def get_deployment(deployment_id: uuid.UUID, _: AuthContext = Depends(require_permission("deployments:read")),
                   db: Session = Depends(get_db)) -> dict[str, Any]:
    return service.job_out(db, service.get_job(db, deployment_id), detail=True)


@router.get("/deployments/{deployment_id}/events")
def deployment_events(deployment_id: uuid.UUID, _: AuthContext = Depends(require_permission("deployments:read")),
                      db: Session = Depends(get_db)):
    service.get_job(db, deployment_id)        # 404 if unknown
    db.rollback()
    # the stream starts with a full ``snapshot`` frame (so reconnects work), then ``progress`` frames, then ``end``
    return StreamingResponse(events.sse_stream("deployment", deployment_id), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.post("/deployments/{deployment_id}/approve")
def approve(deployment_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("deployments:approve", reauth=True)),
            db: Session = Depends(get_db)) -> dict[str, Any]:
    return service.job_out(db, service.approve(db, ctx.user, deployment_id), detail=True)


@router.post("/deployments/{deployment_id}/cancel")
def cancel(deployment_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("deployments:cancel")),
           db: Session = Depends(get_db)) -> dict[str, Any]:
    return service.job_out(db, service.cancel(db, ctx.user, deployment_id), detail=True)


@router.post("/deployments/{deployment_id}/retry", status_code=201)
def retry(deployment_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("deployments:retry")),
          db: Session = Depends(get_db)) -> dict[str, Any]:
    return service.job_out(db, service.retry(db, ctx.user, deployment_id), detail=True)


@router.post("/deployments/{deployment_id}/targets/{target_id}/rollback")
def rollback_target(deployment_id: uuid.UUID, target_id: uuid.UUID,
                    ctx: AuthContext = Depends(require_permission("deployments:rollback", reauth=True)),
                    db: Session = Depends(get_db)) -> dict[str, Any]:
    return service.rollback_target(db, ctx.user, deployment_id, target_id)

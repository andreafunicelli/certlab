from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, Form, Query, Response, UploadFile
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.db import get_db
from app.schemas.common import Page, PageParams
from app.schemas.server import (
    EnvironmentCreate,
    EnvironmentOut,
    EnvironmentUpdate,
    HostKeyBulkEnroll,
    HostKeyBulkEnrollOut,
    HostKeyBulkScan,
    HostKeyBulkScanOut,
    HostKeyEnroll,
    HostKeyScanOut,
    ImportResultOut,
    ServerCreate,
    ServerOut,
    ServerUpdate,
)
from app.services import connectivity, host_keys, server_import
from app.services import servers as service
from app.services.auth import AuthContext

router = APIRouter(tags=["servers"])


@router.get("/servers", response_model=Page[ServerOut])
def list_servers(
    q: str | None = Query(None, max_length=100), environment: str | None = None, status: str | None = None,
    enabled: bool | None = None, tag: str | None = None, p: PageParams = Depends(),
    _: AuthContext = Depends(require_permission("servers:read")), db: Session = Depends(get_db),
):
    items, total = service.list_servers(db, offset=p.offset, limit=p.page_size, q=q, environment=environment,
                                        status=status, enabled=enabled, tag=tag)
    return Page(items=items, total=total, page=p.page, page_size=p.page_size)


@router.post("/servers", response_model=ServerOut, status_code=201)
def create_server(body: ServerCreate, ctx: AuthContext = Depends(require_permission("servers:write")),
                  db: Session = Depends(get_db)):
    return service.create(db, ctx.user, body)


@router.get("/servers/import/template")
def import_template(_: AuthContext = Depends(require_permission("servers:write"))):
    return Response(server_import.template_csv(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{server_import.FILENAME}"'})


@router.post("/servers/import", response_model=ImportResultOut)
async def import_servers(
    file: UploadFile = File(...), dry_run: bool = Form(True), on_conflict: Literal["error", "skip"] = Form("error"),
    ctx: AuthContext = Depends(require_permission("servers:write")), db: Session = Depends(get_db),
):
    raw = await file.read(server_import.MAX_BYTES + 1)
    return await run_in_threadpool(server_import.run_import, db, ctx.user, raw, filename=file.filename,
                                   dry_run=dry_run, on_conflict=on_conflict)


@router.post("/servers/host-keys/scan", response_model=HostKeyBulkScanOut)
def bulk_scan_host_keys(body: HostKeyBulkScan, ctx: AuthContext = Depends(require_permission("servers:hostkey")),
                        db: Session = Depends(get_db)):
    return host_keys.scan(db, ctx.user, body.server_ids)


@router.post("/servers/host-keys/enroll", response_model=HostKeyBulkEnrollOut)
def bulk_enroll_host_keys(body: HostKeyBulkEnroll, ctx: AuthContext = Depends(require_permission("servers:hostkey")),
                          db: Session = Depends(get_db)):
    return host_keys.enroll(db, ctx.user, body)


@router.get("/servers/{server_id}", response_model=ServerOut)
def get_server(server_id: uuid.UUID, _: AuthContext = Depends(require_permission("servers:read")),
               db: Session = Depends(get_db)):
    return service.get_out(db, server_id)


@router.patch("/servers/{server_id}", response_model=ServerOut)
def update_server(server_id: uuid.UUID, body: ServerUpdate,
                  ctx: AuthContext = Depends(require_permission("servers:write")), db: Session = Depends(get_db)):
    return service.update(db, ctx.user, server_id, body)


@router.post("/servers/{server_id}/disable", response_model=ServerOut)
def disable_server(server_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("servers:write")),
                   db: Session = Depends(get_db)):
    return service.set_enabled(db, ctx.user, server_id, False)


@router.post("/servers/{server_id}/enable", response_model=ServerOut)
def enable_server(server_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("servers:write")),
                  db: Session = Depends(get_db)):
    return service.set_enabled(db, ctx.user, server_id, True)


@router.delete("/servers/{server_id}", status_code=204)
def delete_server(server_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("servers:write")),
                  db: Session = Depends(get_db)):
    service.delete(db, ctx.user, server_id)
    return Response(status_code=204)


@router.post("/servers/{server_id}/host-key/scan", response_model=HostKeyScanOut)
def scan_host_key(server_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("servers:hostkey")),
                  db: Session = Depends(get_db)):
    r = connectivity.scan_host_key(db, ctx.user, server_id)
    return HostKeyScanOut(key_type=r["key_type"], fingerprint_sha256=r["fingerprint_sha256"],
                          public_key=r["public_key"])


@router.post("/servers/{server_id}/host-key/enroll", response_model=ServerOut)
def enroll_host_key(server_id: uuid.UUID, body: HostKeyEnroll,
                    ctx: AuthContext = Depends(require_permission("servers:hostkey")), db: Session = Depends(get_db)):
    connectivity.enroll_host_key(db, ctx.user, server_id, body.public_key, body.fingerprint_sha256, body.replace)
    return service.get_out(db, server_id)


@router.post("/servers/{server_id}/test-connection")
def test_connection(server_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("servers:test")),
                    db: Session = Depends(get_db)) -> dict[str, Any]:
    return connectivity.test_connection(db, ctx.user, server_id)


def _job_dict(job: Any) -> Any:
    if hasattr(job, "model_dump"):
        return job.model_dump(mode="json")
    if hasattr(job, "__table__"):
        from fastapi.encoders import jsonable_encoder

        return jsonable_encoder({c.name: getattr(job, c.name) for c in job.__table__.columns})
    return job


@router.post("/servers/{server_id}/discover", status_code=202)
def discover(server_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("discovery:run")),
             db: Session = Depends(get_db)):
    service.get(db, server_id)
    from app.services.discovery import start_discovery

    return _job_dict(start_discovery(db, ctx.user, server_id))


# ------------------------------------------------------------------ environments
@router.get("/environments", response_model=list[EnvironmentOut])
def list_environments(_: AuthContext = Depends(require_permission("environments:read")), db: Session = Depends(get_db)):
    return service.list_environments(db)


@router.post("/environments", response_model=EnvironmentOut, status_code=201)
def create_environment(body: EnvironmentCreate, ctx: AuthContext = Depends(require_permission("environments:write")),
                       db: Session = Depends(get_db)):
    return service.create_environment(db, ctx.user, body)


@router.patch("/environments/{env_id}", response_model=EnvironmentOut)
def update_environment(env_id: uuid.UUID, body: EnvironmentUpdate,
                       ctx: AuthContext = Depends(require_permission("environments:write")),
                       db: Session = Depends(get_db)):
    return service.update_environment(db, ctx.user, env_id, body)


@router.delete("/environments/{env_id}", status_code=204)
def delete_environment(env_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("environments:write")),
                       db: Session = Depends(get_db)):
    service.delete_environment(db, ctx.user, env_id)
    return Response(status_code=204)

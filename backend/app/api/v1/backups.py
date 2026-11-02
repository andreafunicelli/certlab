from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.db import get_db
from app.schemas.common import Page, PageParams
from app.services import backups as service
from app.services import deployments as deployments_service
from app.services.auth import AuthContext

router = APIRouter(tags=["backups"])


@router.get("/backups", response_model=Page[dict[str, Any]])
def list_backups(server_id: uuid.UUID | None = None, installation_id: uuid.UUID | None = None,
                 deployment_id: uuid.UUID | None = None, p: PageParams = Depends(),
                 _: AuthContext = Depends(require_permission("backups:read")), db: Session = Depends(get_db)):
    rows, total = service.list_backups(db, offset=p.offset, limit=p.page_size, server_id=server_id,
                                       installation_id=installation_id, deployment_id=deployment_id)
    return Page(items=[service.backup_out(db, b) for b in rows], total=total, page=p.page, page_size=p.page_size)


@router.get("/backups/{backup_id}")
def get_backup(backup_id: uuid.UUID, _: AuthContext = Depends(require_permission("backups:read")),
               db: Session = Depends(get_db)) -> dict[str, Any]:
    """Manifest only: sha256, mode, owner, symlink info ... never file content."""
    return service.backup_out(db, service.get_backup(db, backup_id))


@router.post("/backups/{backup_id}/restore", status_code=202)
def restore_backup(backup_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("backups:restore", reauth=True)),
                   db: Session = Depends(get_db)) -> dict[str, Any]:
    """Queue the restore for a worker (202). Follow ``backup.restore_status`` (``in_progress`` -> ``restored``/``failed``)
    and, when the backup belongs to a completed/failed target, that target's status."""
    backup = service.get_backup(db, backup_id)
    target = None
    if backup.deployment_target_id:
        from app.models import DeploymentTarget

        target = db.get(DeploymentTarget, backup.deployment_target_id)
        if target is not None and target.status not in ("completed", "manual_intervention_required", "failed"):
            target = None
    out = deployments_service.queue_restore(db, ctx.user, backup, target)
    return {**out, "backup": service.backup_out(db, service.get_backup(db, backup_id))}


@router.get("/backups/{backup_id}/download")
def download_backup(backup_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("backups:download", reauth=True)),
                    db: Session = Depends(get_db)):
    data, filename = service.download(db, ctx.user, backup_id)
    return Response(content=data, media_type="application/gzip",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"', "Cache-Control": "no-store"})

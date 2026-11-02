from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, File, Form, UploadFile
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.db import get_db
from app.core.errors import AppError
from app.schemas.inventory import ValidateVersion
from app.services import uploads
from app.services.auth import AuthContext

router = APIRouter(tags=["certificate-versions"])


async def _read(f: UploadFile | None, name: str) -> bytes | None:
    if f is None:
        return None
    data = await f.read(uploads.MAX_UPLOAD_BYTES + 1)
    if len(data) > uploads.MAX_UPLOAD_BYTES:
        raise AppError("PAYLOAD_TOO_LARGE", f"{name} exceeds the {uploads.MAX_UPLOAD_BYTES // 1024} KiB limit", 413)
    return data or None


@router.post("/certificate-versions", status_code=201)
async def upload_version(
    certificate: UploadFile | None = File(None), private_key: UploadFile | None = File(None),
    chain: UploadFile | None = File(None), pkcs12: UploadFile | None = File(None),
    password: str | None = Form(None, max_length=1024), certificate_id: uuid.UUID | None = Form(None),
    ctx: AuthContext = Depends(require_permission("versions:upload")), db: Session = Depends(get_db),
) -> dict[str, Any]:
    cert_b, key_b = await _read(certificate, "certificate"), await _read(private_key, "private_key")
    chain_b, p12_b = await _read(chain, "chain"), await _read(pkcs12, "pkcs12")
    return await run_in_threadpool(
        uploads.create_version, db, ctx.user, certificate=cert_b, private_key=key_b, chain=chain_b, pkcs12=p12_b,
        password=password or None, certificate_id=certificate_id)


@router.get("/certificate-versions/{version_id}")
def get_version(version_id: uuid.UUID, _: AuthContext = Depends(require_permission("versions:read")),
                db: Session = Depends(get_db)) -> dict[str, Any]:
    return uploads.version_out(uploads.get_version(db, version_id))


@router.post("/certificate-versions/{version_id}/validate")
def validate_version(version_id: uuid.UUID, body: ValidateVersion,
                     ctx: AuthContext = Depends(require_permission("versions:upload")),
                     db: Session = Depends(get_db)) -> dict[str, Any]:
    return uploads.revalidate(db, ctx.user, version_id, body.installation_ids)

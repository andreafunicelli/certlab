from __future__ import annotations

import json
import uuid
from collections.abc import Callable

from fastapi import APIRouter, Depends, Request, Response
from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.db import get_db
from app.core.errors import AppError
from app.schemas.credential import CredentialCreate, CredentialOut, CredentialRotate
from app.services import credentials as service
from app.services.auth import AuthContext

router = APIRouter(prefix="/credentials", tags=["credentials"])
MAX_BODY = 128 * 1024


def body_parser(model: type[BaseModel]) -> Callable:
    """Accepts application/json or multipart/form-data (private_key as text field or private_key_file upload)."""

    async def parse(request: Request):
        ctype = request.headers.get("content-type", "")
        if ctype.startswith("application/json"):
            raw = await request.body()
            if len(raw) > MAX_BODY:
                raise AppError("PAYLOAD_TOO_LARGE", "Request body too large", 413)
            try:
                data = json.loads(raw)
            except ValueError as exc:
                raise AppError("VALIDATION_ERROR", "Body is not valid JSON", 422) from exc
        elif ctype.startswith(("multipart/form-data", "application/x-www-form-urlencoded")):
            form = await request.form(max_files=1, max_fields=10)
            data = {k: v for k, v in form.items() if isinstance(v, str)}
            upload = form.get("private_key_file")
            if upload is not None and not isinstance(upload, str):
                content = await upload.read(MAX_BODY + 1)
                if len(content) > MAX_BODY:
                    raise AppError("PAYLOAD_TOO_LARGE", "Key file too large", 413)
                data["private_key"] = content.decode("utf-8", errors="strict")
            if not data.get("passphrase"):
                data.pop("passphrase", None)
        else:
            raise AppError("UNSUPPORTED_MEDIA_TYPE", "Use application/json or multipart/form-data", 415)
        try:
            return model.model_validate(data)
        except ValidationError as exc:
            errs = [{"loc": [str(p) for p in e["loc"]], "msg": e["msg"]} for e in exc.errors()]
            raise AppError("VALIDATION_ERROR", "Request validation failed", 422, {"errors": errs}) from exc
        except UnicodeDecodeError as exc:
            raise AppError("VALIDATION_ERROR", "Key file must be UTF-8 text", 422) from exc

    return parse


@router.get("", response_model=list[CredentialOut])
def list_credentials(_: AuthContext = Depends(require_permission("credentials:read")), db: Session = Depends(get_db)):
    return service.list_all(db)


@router.post("", response_model=CredentialOut, status_code=201)
def create_credential(
    ctx: AuthContext = Depends(require_permission("credentials:write", reauth=True)),
    body: CredentialCreate = Depends(body_parser(CredentialCreate)),
    db: Session = Depends(get_db),
):
    return service.create(db, ctx.user, body)


@router.post("/{credential_id}/rotate", response_model=CredentialOut)
def rotate_credential(
    credential_id: uuid.UUID,
    ctx: AuthContext = Depends(require_permission("credentials:write", reauth=True)),
    body: CredentialRotate = Depends(body_parser(CredentialRotate)),
    db: Session = Depends(get_db),
):
    return service.rotate(db, ctx.user, credential_id, body)


@router.delete("/{credential_id}", status_code=204)
def delete_credential(credential_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("credentials:write")),
                      db: Session = Depends(get_db)):
    service.delete(db, ctx.user, credential_id)
    return Response(status_code=204)

from __future__ import annotations

import httpx
import pytest
from starlette.requests import Request

from app.api.v1.credentials import body_parser
from app.core.errors import AppError
from app.schemas.credential import CredentialCreate, CredentialRotate


@pytest.mark.parametrize("model", [CredentialCreate, CredentialRotate])
async def test_credential_multipart_rejects_non_utf8_key_files(model):
    upload = httpx.Request("POST", "https://certlab.example/credentials", data={"name": "key"},
                           files={"private_key_file": ("invalid.key", b"\xff" * 40)})
    body = upload.read()

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    request = Request({"type": "http", "method": "POST", "path": "/credentials",
                       "headers": [(name.lower(), value) for name, value in upload.headers.raw]}, receive)
    with pytest.raises(AppError) as exc:
        await body_parser(model)(request)

    assert exc.value.code == "VALIDATION_ERROR"
    assert exc.value.status == 422

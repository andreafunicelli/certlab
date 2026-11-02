from __future__ import annotations

import base64
import os
import stat
import uuid

import pytest
from sqlalchemy import select

from app.core import security
from app.core.config import ConfigError, Settings
from app.core.crypto import ArtifactIntegrityError, ArtifactNotFound, Vault, get_vault
from app.core.logging import MASK, PEM_MASK, redact, redaction_processor
from app.core.permissions import ROLE_PERMISSIONS, authorize, has_permission
from app.models import EncryptedArtifact

PEM = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----"


def test_password_hash_argon2id_and_verify():
    h = security.hash_password("s3cret-Passphrase!")
    assert h.startswith("$argon2id$")
    assert security.verify_password(h, "s3cret-Passphrase!")
    assert not security.verify_password(h, "wrong")
    assert not security.verify_password(None, "anything")  # unknown user path


def test_session_token_stored_hashed():
    t = security.new_session_token()
    assert len(t) >= 40 and security.hash_token(t) != t and len(security.hash_token(t)) == 64


def test_csrf_double_submit_requires_cookie_header_and_binding():
    tok = security.new_session_token()
    csrf = security.csrf_token_for(tok)
    assert security.csrf_valid(tok, csrf, csrf)
    assert not security.csrf_valid(tok, csrf, None)
    assert not security.csrf_valid(tok, None, csrf)
    assert not security.csrf_valid(tok, csrf, "x" * len(csrf))
    other = security.csrf_token_for(security.new_session_token())
    assert not security.csrf_valid(tok, other, other)  # not bound to this session


def test_totp_roundtrip():
    import pyotp

    secret = security.new_totp_secret()
    assert security.verify_totp(secret, pyotp.TOTP(secret).now())
    assert not security.verify_totp(secret, "000000") or pyotp.TOTP(secret).now() == "000000"
    assert not security.verify_totp(secret, "abc")


# ----------------------------------------------------------------------------- vault
def test_vault_roundtrip_and_file_permissions(db):
    v = get_vault()
    ref = v.store(b"top secret key material", "test", db=db)
    db.commit()
    path = v.artifact_dir / f"{ref.id}.bin"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert b"top secret" not in path.read_bytes()
    assert v.load(ref.id, db=db) == b"top secret key material"
    assert ref.size == 23 and ref.key_id == v.key_id and len(ref.sha256_plain) == 64


def test_vault_detects_ciphertext_tamper(db):
    v = get_vault()
    ref = v.store(b"hello world", "test", db=db)
    db.commit()
    p = v.artifact_dir / f"{ref.id}.bin"
    data = bytearray(p.read_bytes())
    data[0] ^= 0xFF
    p.write_bytes(bytes(data))
    with pytest.raises(ArtifactIntegrityError):
        v.load(ref.id, db=db)


def test_vault_detects_wrapped_dek_tamper_and_wrong_kek(db):
    v = get_vault()
    ref = v.store(b"payload", "test", db=db)
    db.commit()
    other = Vault(os.urandom(32), v.artifact_dir)
    with pytest.raises(ArtifactIntegrityError):
        other.load(ref.id, db=db)
    row = db.scalar(select(EncryptedArtifact).where(EncryptedArtifact.id == ref.id))
    row.wrapped_dek = bytes(row.wrapped_dek)[:-1] + bytes([row.wrapped_dek[-1] ^ 1])
    db.commit()
    with pytest.raises(ArtifactIntegrityError):
        v.load(ref.id, db=db)


def test_vault_aad_binds_purpose(db):
    v = get_vault()
    ref = v.store(b"payload", "purpose-a", db=db)
    row = db.get(EncryptedArtifact, ref.id)
    row.purpose = "purpose-b"
    db.commit()
    with pytest.raises(ArtifactIntegrityError):
        v.load(ref.id, db=db)


def test_vault_delete_removes_file(db):
    v = get_vault()
    ref = v.store(b"bye", "test", db=db)
    db.commit()
    v.delete(ref.id, db=db)
    db.commit()
    assert not (v.artifact_dir / f"{ref.id}.bin").exists()
    with pytest.raises(ArtifactNotFound):
        v.load(ref.id, db=db)


def test_inline_value_encryption_and_tamper():
    v = get_vault()
    tok = v.encrypt_value("smtp-password")
    assert "smtp-password" not in tok and v.decrypt_value(tok) == "smtp-password"
    assert v.encrypt_value("smtp-password") != tok  # random nonce
    bad = tok[:-4] + ("AAAA" if not tok.endswith("AAAA") else "BBBB")
    with pytest.raises(ArtifactIntegrityError):
        v.decrypt_value(bad)


def test_vault_refuses_to_start_without_kek(tmp_path):
    with pytest.raises(ConfigError):
        Settings(master_key=None, master_key_file=None, _env_file=None).resolve_master_key()  # type: ignore[call-arg]


def test_kek_from_file_and_length_validation(tmp_path):
    f = tmp_path / "kek"
    f.write_text(base64.b64encode(os.urandom(32)).decode())
    assert len(Settings(master_key=None, master_key_file=f).resolve_master_key()) == 32  # type: ignore[call-arg]
    f.write_text(base64.b64encode(os.urandom(16)).decode())
    with pytest.raises(ConfigError):
        Settings(master_key=None, master_key_file=f).resolve_master_key()  # type: ignore[call-arg]


# ----------------------------------------------------------------------------- redaction
def test_redaction_masks_keys_and_pem():
    out = redact({"password": "x", "nested": {"private_key": PEM, "api_token": "t", "ok": "fine"},
                  "msg": f"failed with {PEM} blah", "has_passphrase": True, "list": [{"secret": "s"}]})
    assert out["password"] == MASK and out["nested"]["private_key"] == MASK and out["nested"]["api_token"] == MASK
    assert out["nested"]["ok"] == "fine" and out["has_passphrase"] is True
    assert PEM_MASK in out["msg"] and "BEGIN" not in out["msg"]
    assert out["list"][0]["secret"] == MASK


def test_redaction_processor_for_structlog_event():
    ev = redaction_processor(None, "info", {"event": f"key={PEM}", "passphrase": "p"})
    assert "BEGIN" not in ev["event"] and ev["passphrase"] == MASK


# ----------------------------------------------------------------------------- permissions
class _U:
    enabled = True

    def __init__(self, *roles):
        self.role_names = list(roles)


def test_permission_matrix():
    assert has_permission(["admin"], "settings:write") and has_permission(["admin"], "credentials:write")
    assert has_permission(["operator"], "deployments:create") and has_permission(["operator"], "discovery:run")
    for p in ("users:write", "credentials:write", "settings:write", "servers:write", "deployments:approve"):
        assert not has_permission(["operator"], p)
    for p in ("servers:read", "certificates:read", "deployments:read", "logs:read"):
        assert has_permission(["viewer"], p)
    for p in ROLE_PERMISSIONS["viewer"]:
        assert p.endswith(":read")
    with pytest.raises(Exception) as ei:
        authorize(_U("viewer"), "servers:write")
    assert ei.value.status == 403  # type: ignore[attr-defined]
    authorize(_U("operator"), "deployments:create")
    assert uuid  # silence unused

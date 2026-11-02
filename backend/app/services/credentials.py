from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.crypto import ArtifactNotFound, get_vault
from app.core.errors import AppError, conflict, not_found
from app.models import Credential, Server, User
from app.models.base import utcnow
from app.schemas.credential import CredentialCreate, CredentialOut, CredentialRotate
from app.services import audit


def parse_private_key(pem: str, passphrase: str | None) -> dict[str, str]:
    """Validate an SSH private key and derive public key + SHA256 fingerprint (no secret leaves)."""
    import asyncssh

    try:
        key = asyncssh.import_private_key(pem.encode(), passphrase or None)
    except (asyncssh.KeyImportError, asyncssh.KeyEncryptionError, ValueError) as exc:
        raise AppError("INVALID_PRIVATE_KEY", "The private key could not be parsed or the passphrase is wrong",
                       422) from exc
    except Exception as exc:
        raise AppError("INVALID_PRIVATE_KEY", "The private key could not be parsed", 422) from exc
    alg = key.get_algorithm()
    if alg.startswith("ssh-dss"):
        raise AppError("UNSUPPORTED_KEY_TYPE", "DSA keys are not supported", 422)
    public = key.export_public_key("openssh").decode().strip()
    return {"public_key": public, "fingerprint": key.get_fingerprint("sha256"), "algorithm": alg}


def _server_count(db: Session, credential_id: uuid.UUID) -> int:
    return db.scalar(select(func.count()).select_from(Server).where(Server.credential_id == credential_id)) or 0


def to_out(db: Session, c: Credential) -> CredentialOut:
    return CredentialOut(
        id=c.id, name=c.name, type=c.type, fingerprint=c.fingerprint_sha256, public_key=c.public_key,
        key_algorithm=c.key_algorithm, has_passphrase=bool(c.passphrase_encrypted), created_at=c.created_at,
        rotated_at=c.rotated_at, server_count=_server_count(db, c.id),
    )


def _snapshot(c: Credential) -> dict[str, Any]:
    return {"name": c.name, "type": c.type, "fingerprint": c.fingerprint_sha256, "algorithm": c.key_algorithm}


def get(db: Session, credential_id: uuid.UUID) -> Credential:
    c = db.get(Credential, credential_id)
    if c is None:
        raise not_found("CREDENTIAL_NOT_FOUND", "Credential not found")
    return c


def list_all(db: Session) -> list[CredentialOut]:
    return [to_out(db, c) for c in db.scalars(select(Credential).order_by(Credential.name))]


def create(db: Session, actor: User, data: CredentialCreate) -> CredentialOut:
    if db.scalar(select(Credential.id).where(func.lower(Credential.name) == data.name.lower())):
        raise conflict("CREDENTIAL_EXISTS", "A credential with this name already exists")
    info = parse_private_key(data.private_key, data.passphrase)
    vault = get_vault()
    ref = vault.store(data.private_key.encode(), "ssh_private_key", db=db)
    c = Credential(
        name=data.name, type="ssh_private_key", encrypted_artifact_id=ref.id,
        passphrase_encrypted=vault.encrypt_value(data.passphrase) if data.passphrase else None,
        public_key=info["public_key"], fingerprint_sha256=info["fingerprint"], key_algorithm=info["algorithm"],
        created_by=actor.id,
    )
    db.add(c)
    db.flush()
    audit.record(db, action="CREDENTIAL_CREATED", resource_type="credential", resource_id=c.id, actor=actor,
                 after=_snapshot(c))
    db.commit()
    return to_out(db, c)


def rotate(db: Session, actor: User, credential_id: uuid.UUID, data: CredentialRotate) -> CredentialOut:
    c = get(db, credential_id)
    before = _snapshot(c)
    info = parse_private_key(data.private_key, data.passphrase)
    vault = get_vault()
    old_artifact = c.encrypted_artifact_id
    ref = vault.store(data.private_key.encode(), "ssh_private_key", db=db)
    c.encrypted_artifact_id = ref.id
    c.passphrase_encrypted = vault.encrypt_value(data.passphrase) if data.passphrase else None
    c.public_key, c.fingerprint_sha256, c.key_algorithm = info["public_key"], info["fingerprint"], info["algorithm"]
    c.rotated_at = utcnow()
    audit.record(db, action="CREDENTIAL_ROTATED", resource_type="credential", resource_id=c.id, actor=actor,
                 before=before, after=_snapshot(c))
    db.commit()
    vault.delete(old_artifact, db=db)
    db.commit()
    return to_out(db, c)


def delete(db: Session, actor: User, credential_id: uuid.UUID) -> None:
    c = get(db, credential_id)
    n = _server_count(db, c.id)
    if n:
        raise conflict("CREDENTIAL_IN_USE", f"Credential is used by {n} server(s)", {"server_count": n})
    snap, artifact = _snapshot(c), c.encrypted_artifact_id
    db.delete(c)
    audit.record(db, action="CREDENTIAL_DELETED", resource_type="credential", resource_id=credential_id,
                 actor=actor, before=snap)
    db.commit()
    try:
        get_vault().delete(artifact, db=db)
        db.commit()
    except ArtifactNotFound:
        pass

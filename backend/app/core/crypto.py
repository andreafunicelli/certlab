"""Envelope encryption: KEK (master key) -> per-artifact DEK (AES-256-GCM)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import uuid
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session

from app.core.config import ConfigError, Settings, get_settings
from app.models.artifact import EncryptedArtifact


class VaultError(Exception):
    """Base class: never carries plaintext in its message."""


class ArtifactNotFound(VaultError):
    pass


class ArtifactIntegrityError(VaultError):
    """Ciphertext/tag/hash verification failed (tampering or wrong KEK)."""


@dataclass(frozen=True)
class ArtifactRef:
    id: uuid.UUID
    wrapped_dek: bytes
    nonce: bytes
    sha256_plain: str
    size: int
    key_id: str


class Vault:
    def __init__(self, kek: bytes, artifact_dir: Path):
        if len(kek) != 32:
            raise ConfigError("KEK must be 32 bytes")
        self._kek = kek
        self._aes = AESGCM(kek)
        self.key_id = hashlib.sha256(kek).hexdigest()[:16]
        self.artifact_dir = Path(artifact_dir)
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.artifact_dir, 0o700)
        except OSError:
            pass

    @classmethod
    def from_settings(cls, settings: Settings) -> Vault:
        return cls(settings.resolve_master_key(), settings.artifact_dir)

    # ------------------------------------------------------------------ helpers
    def derive_key(self, label: str) -> bytes:
        """Domain-separated subkey (HMAC-SHA256 KDF) for non-encryption uses (CSRF, state cookies)."""
        return hmac.new(self._kek, b"cdp-derive:" + label.encode(), hashlib.sha256).digest()

    def _path(self, artifact_id: uuid.UUID) -> Path:
        return self.artifact_dir / f"{artifact_id}.bin"

    @staticmethod
    def _aad(artifact_id: uuid.UUID, purpose: str) -> bytes:
        return f"{artifact_id}|{purpose}".encode()

    def _with_session(self, db: Session | None):
        from app.core.db import SessionLocal

        return (db, False) if db is not None else (SessionLocal(), True)

    # ------------------------------------------------------------------ artifacts
    def store(self, plaintext: bytes, purpose: str, *, db: Session | None = None) -> ArtifactRef:
        artifact_id = uuid.uuid4()
        dek = AESGCM.generate_key(bit_length=256)
        nonce = os.urandom(12)
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext, self._aad(artifact_id, purpose))
        wrap_nonce = os.urandom(12)
        wrapped = wrap_nonce + self._aes.encrypt(wrap_nonce, dek, self._aad(artifact_id, "dek"))
        sha = hashlib.sha256(plaintext).hexdigest()

        path = self._path(artifact_id)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(ciphertext)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise

        session, owned = self._with_session(db)
        try:
            session.add(EncryptedArtifact(
                id=artifact_id, purpose=purpose, key_id=self.key_id, wrapped_dek=wrapped, nonce=nonce,
                sha256_plain=sha, size=len(plaintext), filename=path.name,
            ))
            if owned:
                session.commit()
            else:
                session.flush()
        except BaseException:
            if owned:
                session.rollback()
            path.unlink(missing_ok=True)
            raise
        finally:
            if owned:
                session.close()
        return ArtifactRef(artifact_id, wrapped, nonce, sha, len(plaintext), self.key_id)

    def load(self, artifact_id: uuid.UUID, *, db: Session | None = None) -> bytes:
        session, owned = self._with_session(db)
        try:
            row = session.get(EncryptedArtifact, artifact_id)
        finally:
            if owned:
                session.close()
        if row is None or row.deleted_at is not None:
            raise ArtifactNotFound(f"artifact {artifact_id} not found")
        try:
            data = self._path(artifact_id).read_bytes()
        except OSError as exc:
            raise ArtifactNotFound(f"artifact {artifact_id} ciphertext missing") from exc
        try:
            wrapped = bytes(row.wrapped_dek)
            dek = self._aes.decrypt(wrapped[:12], wrapped[12:], self._aad(artifact_id, "dek"))
            plain = AESGCM(dek).decrypt(bytes(row.nonce), data, self._aad(artifact_id, row.purpose))
        except InvalidTag as exc:
            raise ArtifactIntegrityError(f"artifact {artifact_id} failed authentication") from exc
        if not hmac.compare_digest(hashlib.sha256(plain).hexdigest(), row.sha256_plain):
            raise ArtifactIntegrityError(f"artifact {artifact_id} hash mismatch")
        return plain

    def delete(self, artifact_id: uuid.UUID, *, db: Session | None = None) -> None:
        path = self._path(artifact_id)
        if path.exists():
            try:
                size = path.stat().st_size
                with open(path, "r+b") as fh:
                    fh.write(os.urandom(size))
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                pass
            path.unlink(missing_ok=True)
        session, owned = self._with_session(db)
        try:
            row = session.get(EncryptedArtifact, artifact_id)
            if row is not None:
                from sqlalchemy import func

                row.deleted_at = func.now()
                row.wrapped_dek = b""
            if owned:
                session.commit()
            else:
                session.flush()
        finally:
            if owned:
                session.close()

    # ------------------------------------------------------------------ inline small secrets
    def encrypt_value(self, value: str) -> str:
        nonce = os.urandom(12)
        ct = self._aes.encrypt(nonce, value.encode(), b"cdp-inline-v1")
        return f"v1:{self.key_id}:{base64.b64encode(nonce + ct).decode()}"

    def decrypt_value(self, token: str) -> str:
        try:
            version, key_id, b64 = token.split(":", 2)
            if version != "v1" or key_id != self.key_id:
                raise ArtifactIntegrityError("unknown key id or version")
            raw = base64.b64decode(b64)
            return self._aes.decrypt(raw[:12], raw[12:], b"cdp-inline-v1").decode()
        except (InvalidTag, ValueError) as exc:
            raise ArtifactIntegrityError("encrypted value failed authentication") from exc


_vault: Vault | None = None


def get_vault() -> Vault:
    global _vault
    if _vault is None:
        _vault = Vault.from_settings(get_settings())
    return _vault


def reset_vault() -> None:
    global _vault
    _vault = None



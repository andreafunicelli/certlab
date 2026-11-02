"""Public-key helpers (no I/O)."""
from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import serialization

from app.integrations.contracts import CertInfo


def public_key_spki_sha256(public_key) -> str:
    """Lower-case hex SHA-256 of the DER SubjectPublicKeyInfo of ``public_key``."""
    der = public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return hashlib.sha256(der).hexdigest()


def key_matches_cert(key_pem: bytes, passphrase: str | bytes | None, cert_info: CertInfo) -> bool:
    """True when the private key's public half equals the certificate's public key.

    Raises ``CertificateError`` subclasses when the key cannot be loaded (wrong or missing
    passphrase, unsupported algorithm, malformed) so that callers can tell this apart from a mismatch.
    """
    from app.integrations.certificates.parse import load_private_key

    _, spki, _ = load_private_key(key_pem, passphrase)
    return spki == cert_info.public_key_sha256

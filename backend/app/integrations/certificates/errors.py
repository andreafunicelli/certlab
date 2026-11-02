"""Exceptions raised by the pure certificate helpers. Messages never include key material."""
from __future__ import annotations


class CertificateError(ValueError):
    """Base class. ``code`` is a stable machine code, ``details`` is safe to log."""

    code = "CERT_PARSE_ERROR"

    def __init__(self, message: str, *, code: str | None = None, details: dict | None = None):
        super().__init__(message)
        if code is not None:
            self.code = code
        self.details = details or {}


class KeyPassphraseRequired(CertificateError):
    code = "KEY_PASSPHRASE_REQUIRED"


class KeyPassphraseInvalid(CertificateError):
    code = "KEY_PASSPHRASE_INVALID"


class UnsupportedKeyError(CertificateError):
    code = "UNSUPPORTED_KEY_ALGORITHM"


class KeyParseError(CertificateError):
    code = "KEY_PARSE_ERROR"


class Pkcs12Error(CertificateError):
    code = "PKCS12_INVALID"

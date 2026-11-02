"""Trust anchors used for upload validation and endpoint probing: system store + optional configured extras."""
from __future__ import annotations

import ssl
from functools import lru_cache

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from sqlalchemy.orm import Session

from app.integrations.certificates import parse_pem_certificates
from app.integrations.certificates.parse import x509_from_info
from app.services import settings as settings_service


@lru_cache
def _system_anchors() -> tuple[x509.Certificate, ...]:
    ctx = ssl.create_default_context()
    out = []
    for der in ctx.get_ca_certs(binary_form=True):
        try:
            out.append(x509.load_der_x509_certificate(der))
        except ValueError:
            continue
    return tuple(out)


def extra_anchors_pem(db: Session) -> str:
    return settings_service.get_section_data(db, "security").get("trust_anchors_pem") or ""


def anchors(db: Session) -> list[x509.Certificate]:
    """System trust store + the optional ``security.trust_anchors_pem`` setting."""
    out = list(_system_anchors())
    extra = extra_anchors_pem(db)
    if extra.strip():
        out.extend(x509_from_info(i) for i in parse_pem_certificates(extra.encode()))
    return out


def anchors_pem_for_probe(db: Session) -> bytes | None:
    """PEM bytes for ``probe_endpoint`` — ``None`` (system default store) unless extras are configured."""
    extra = extra_anchors_pem(db)
    if not extra.strip():
        return None
    system = "".join(ssl.DER_cert_to_PEM_cert(c.public_bytes(Encoding.DER))
                     for c in _system_anchors())
    return (system + "\n" + extra).encode()

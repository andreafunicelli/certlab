"""Certificate version uploads: parsing, validation findings, encrypted storage. Key material is never returned."""
from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import ArtifactNotFound, VaultError, get_vault
from app.core.errors import AppError, not_found
from app.integrations.certificates import (
    ValidationPolicy,
    days_remaining,
    parse_pem_certificates,
    parse_upload,
    validate_bundle,
)
from app.integrations.certificates.parse import MAX_INPUT_BYTES
from app.integrations.contracts import CertInfo, Finding, ParsedBundle, Severity
from app.models import Certificate, CertificateInstallation, CertificateVersion, User
from app.models.base import utcnow
from app.services import audit, trust

MAX_UPLOAD_BYTES = MAX_INPUT_BYTES
IGNORED_SERVER_NAMES = ("_", "")


def _finding_dict(f: Finding) -> dict[str, Any]:
    return {"code": f.code, "severity": f.severity.value, "message": f.message, "details": dict(f.details)}


def validation_status(findings: list[dict[str, Any]]) -> str:
    sev = {f["severity"] for f in findings}
    if Severity.BLOCKING.value in sev:
        return "invalid"
    if Severity.WARNING.value in sev:
        return "warnings"
    return "valid"


def required_hostnames(installs: list[CertificateInstallation]) -> list[str]:
    names = {n for i in installs for n in (i.server_names or []) if n not in IGNORED_SERVER_NAMES and not n.startswith("~")}
    return sorted(names)


def _current_info(cert: Certificate | None) -> CertInfo | None:
    if cert is None:
        return None
    infos = parse_pem_certificates(cert.pem.encode())
    return infos[0] if infos else None


def evaluate(db: Session, bundle: ParsedBundle, *, cert: Certificate | None,
             installs: list[CertificateInstallation], now: datetime) -> list[dict[str, Any]]:
    """validate_bundle + key-reuse compatibility (public SPKI comparison against the currently installed certificates)."""
    findings = validate_bundle(
        bundle, now=now, trust_anchors=trust.anchors(db), required_hostnames=required_hostnames(installs),
        current_cert=_current_info(cert), policy=ValidationPolicy(),
    )
    out = [_finding_dict(f) for f in findings if not (f.code == "KEY_MISSING" and bundle.leaf is not None)]
    if bundle.leaf is None:
        return out
    if bundle.private_key_public_sha256 is None:
        out.append({"code": "KEY_REUSE_REQUIRED", "severity": "info", "details": {},
                    "message": "no private key supplied; the key already installed on each target will be reused "
                               "(compatibility is verified again at deployment preflight)"})
        spki = bundle.leaf.public_key_sha256
        current: dict[uuid.UUID, Certificate] = {}
        if cert is not None:
            current[cert.id] = cert
        unknown: list[str] = []
        for i in installs:
            if i.certificate_id is None:
                unknown.append(str(i.id))
            elif i.certificate_id not in current:
                c = db.get(Certificate, i.certificate_id)
                if c is not None:
                    current[c.id] = c
        bad = [c for c in current.values() if c.public_key_sha256 != spki]
        if bad:
            out.append({"code": "KEY_REUSE_INCOMPATIBLE", "severity": "blocking",
                        "message": "the new certificate does not use the same key pair as the currently installed "
                                   "certificate, so the existing private key cannot be reused; upload the new private key",
                        "details": {"current_certificate_ids": [str(c.id) for c in bad]}})
        if unknown:
            out.append({"code": "KEY_REUSE_UNVERIFIED", "severity": "warning",
                        "message": "some target installations have no identified certificate; key compatibility "
                                   "cannot be checked until deployment preflight",
                        "details": {"installation_ids": unknown}})
    return out


def _cert_dict(c: CertInfo, now: datetime) -> dict[str, Any]:
    return {
        "subject": c.subject, "issuer": c.issuer, "common_name": c.common_name, "sans": list(c.sans),
        "serial_number": c.serial_number, "fingerprint_sha256": c.fingerprint_sha256,
        "not_before": c.not_before.isoformat(), "not_after": c.not_after.isoformat(),
        "days_remaining": days_remaining(c.not_after, now), "public_key_algorithm": c.public_key_algorithm,
        "public_key_size": c.public_key_size, "public_key_sha256": c.public_key_sha256,
        "signature_algorithm": c.signature_algorithm, "is_ca": c.is_ca, "is_self_signed": c.is_self_signed,
    }


def version_out(v: CertificateVersion) -> dict[str, Any]:
    meta = v.leaf_metadata or {}
    leaf = {k: val for k, val in meta.items() if k not in ("chain", "key_spki_sha256")}
    return {
        "id": v.id, "certificate_id": v.certificate_id, "fingerprint_sha256": v.fingerprint_sha256, "leaf": leaf,
        "chain": meta.get("chain", []), "findings": v.findings or [], "validation_status": v.validation_status,
        "status": v.status, "reuses_existing_key": v.reuses_existing_key, "has_private_key": v.key_artifact_id is not None,
        "uploaded_by": v.uploaded_by, "created_at": v.created_at, "updated_at": v.updated_at,
    }


def _installs_for(db: Session, cert_id: uuid.UUID | None) -> list[CertificateInstallation]:
    if cert_id is None:
        return []
    return list(db.scalars(select(CertificateInstallation).where(
        CertificateInstallation.certificate_id == cert_id, CertificateInstallation.missing_since.is_(None))))


def create_version(db: Session, user: User, *, certificate: bytes | None, private_key: bytes | None,
                   chain: bytes | None, pkcs12: bytes | None, password: str | None,
                   certificate_id: uuid.UUID | None, now: datetime | None = None) -> dict[str, Any]:
    now = now or utcnow()
    for what, blob in (("certificate", certificate), ("private_key", private_key), ("chain", chain), ("pkcs12", pkcs12)):
        if blob is not None and len(blob) > MAX_UPLOAD_BYTES:
            raise AppError("PAYLOAD_TOO_LARGE", f"{what} exceeds the {MAX_UPLOAD_BYTES // 1024} KiB limit", 413)
    if not certificate and not pkcs12:
        raise AppError("VALIDATION_ERROR", "Provide a certificate (PEM/DER) or a PKCS#12 bundle", 422)
    target_cert = None
    if certificate_id is not None:
        target_cert = db.get(Certificate, certificate_id)
        if target_cert is None:
            raise not_found("CERTIFICATE_NOT_FOUND", "Certificate not found")
    bundle = parse_upload(cert_pem=certificate or None, key_pem=private_key or None, chain_pem=chain or None,
                          pkcs12=pkcs12 or None, password=password or None)
    if bundle.leaf is None:
        findings = [_finding_dict(f) for f in bundle.findings]
        audit.record(db, action="CERTIFICATE_VERSION_REJECTED", resource_type="certificate_version", actor=user,
                     outcome="failure", error="no usable certificate in upload",
                     after={"finding_codes": [f["code"] for f in findings]})
        db.commit()
        raise AppError("UPLOAD_INVALID", "No usable certificate was found in the upload", 422, {"findings": findings})
    installs = _installs_for(db, certificate_id)
    findings = evaluate(db, bundle, cert=target_cert, installs=installs, now=now)
    status = validation_status(findings)

    vault = get_vault()
    cert_ref = vault.store(bundle.leaf.pem.encode(), "certificate_pem", db=db)
    chain_ref = vault.store("".join(c.pem for c in bundle.chain).encode(), "certificate_chain", db=db) if bundle.chain else None
    key_ref = vault.store(bundle.private_key_pem, "certificate_private_key", db=db) if bundle.private_key_pem else None
    meta = _cert_dict(bundle.leaf, now)
    meta["chain"] = [_cert_dict(c, now) for c in bundle.chain]
    meta["key_spki_sha256"] = bundle.private_key_public_sha256
    v = CertificateVersion(
        certificate_id=certificate_id, fingerprint_sha256=bundle.leaf.fingerprint_sha256, leaf_metadata=meta,
        cert_artifact_id=cert_ref.id, chain_artifact_id=chain_ref.id if chain_ref else None,
        key_artifact_id=key_ref.id if key_ref else None, uploaded_by=user.id, validation_status=status,
        findings=findings, status="uploaded" if status == "invalid" else "validated",
        reuses_existing_key=bundle.private_key_pem is None,
    )
    db.add(v)
    db.flush()
    audit.record(db, action="CERTIFICATE_VERSION_UPLOADED", resource_type="certificate_version", resource_id=v.id,
                 actor=user, after={"fingerprint_sha256": v.fingerprint_sha256, "common_name": bundle.leaf.common_name,
                                    "certificate_id": certificate_id, "validation_status": status,
                                    "has_private_key": key_ref is not None, "has_chain": chain_ref is not None,
                                    "finding_codes": sorted({f["code"] for f in findings})})
    db.commit()
    return version_out(v)


def get_version(db: Session, version_id: uuid.UUID) -> CertificateVersion:
    v = db.get(CertificateVersion, version_id)
    if v is None:
        raise not_found("VERSION_NOT_FOUND", "Certificate version not found")
    return v


def load_bundle(db: Session, v: CertificateVersion) -> ParsedBundle:
    """Rebuild the public ParsedBundle of a stored version (the private key is deliberately not loaded)."""
    vault = get_vault()
    try:
        leaf_pem = vault.load(v.cert_artifact_id, db=db) if v.cert_artifact_id else b""
        chain_pem = vault.load(v.chain_artifact_id, db=db) if v.chain_artifact_id else None
    except (ArtifactNotFound, VaultError) as exc:
        raise AppError("ARTIFACT_UNAVAILABLE", "Stored certificate material is unavailable", 500) from exc
    b = parse_upload(cert_pem=leaf_pem, chain_pem=chain_pem)
    spki = (v.leaf_metadata or {}).get("key_spki_sha256")
    return dataclasses.replace(b, private_key_public_sha256=spki)


def revalidate(db: Session, user: User, version_id: uuid.UUID, installation_ids: list[uuid.UUID]) -> dict[str, Any]:
    v = get_version(db, version_id)
    installs = list(db.scalars(select(CertificateInstallation).where(CertificateInstallation.id.in_(installation_ids)))) \
        if installation_ids else _installs_for(db, v.certificate_id)
    if installation_ids and len(installs) != len(set(installation_ids)):
        raise AppError("INSTALLATION_NOT_FOUND", "One or more installations do not exist", 404)
    bundle = load_bundle(db, v)
    cert = db.get(Certificate, v.certificate_id) if v.certificate_id else None
    findings = evaluate(db, bundle, cert=cert, installs=installs, now=utcnow())
    status = validation_status(findings)
    v.findings, v.validation_status = findings, status
    if v.status in ("uploaded", "validated"):
        v.status = "uploaded" if status == "invalid" else "validated"
    audit.record(db, action="CERTIFICATE_VERSION_VALIDATED", resource_type="certificate_version", resource_id=v.id,
                 actor=user, after={"validation_status": status, "installation_ids": [str(i.id) for i in installs],
                                    "finding_codes": sorted({f["code"] for f in findings})})
    db.commit()
    return version_out(v)

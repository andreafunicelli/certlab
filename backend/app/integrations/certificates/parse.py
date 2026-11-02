"""Pure certificate / key parsing and classification built on ``cryptography``. No I/O."""
from __future__ import annotations

import re
from collections.abc import Iterable
from datetime import UTC

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtensionOID, NameOID

from app.integrations.certificates.errors import (
    CertificateError,
    KeyParseError,
    KeyPassphraseInvalid,
    KeyPassphraseRequired,
    Pkcs12Error,
    UnsupportedKeyError,
)
from app.integrations.certificates.keys import public_key_spki_sha256
from app.integrations.contracts import CertInfo, FileKind, Finding, ParsedBundle, Severity

MAX_INPUT_BYTES = 256 * 1024
MAX_CERTS = 10

_PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)
_CERT_LABELS = {b"CERTIFICATE", b"X509 CERTIFICATE", b"TRUSTED CERTIFICATE"}
_CSR_LABELS = {b"CERTIFICATE REQUEST", b"NEW CERTIFICATE REQUEST"}
_JKS_MAGIC = (b"\xfe\xed\xfe\xed", b"\xce\xce\xce\xce")  # JKS, JCEKS


def _is_key_label(label: bytes) -> bool:
    return label.endswith(b"PRIVATE KEY")


# --------------------------------------------------------------------------- x509 -> CertInfo
def _key_algorithm(public_key) -> tuple[str, int | None]:
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "EC", public_key.curve.key_size
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 456
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size
    return type(public_key).__name__, None


def _hex(data: bytes | None, upper: bool = True) -> str | None:
    if data is None:
        return None
    h = data.hex()
    return h.upper() if upper else h


def _name_str(name: x509.Name) -> str:
    return name.rfc4514_string()


def _common_name(name: x509.Name) -> str | None:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attrs:
        return None
    v = attrs[0].value
    return v if isinstance(v, str) else v.decode("utf-8", "replace")


def _sans(cert: x509.Certificate) -> tuple[str, ...]:
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return ()
    except ValueError:  # malformed extension
        return ()
    out: list[str] = []
    for gn in ext.value:
        if isinstance(gn, x509.DNSName):
            out.append(gn.value.lower())
        elif isinstance(gn, x509.IPAddress):
            out.append(str(gn.value))
    return tuple(out)


def _ext_value(cert: x509.Certificate, cls):
    try:
        return cert.extensions.get_extension_for_class(cls).value
    except (x509.ExtensionNotFound, ValueError):
        return None


def _signature_algorithm_name(cert: x509.Certificate) -> str:
    oid = cert.signature_algorithm_oid
    name = getattr(oid, "_name", None)
    return name if name and name != "Unknown OID" else oid.dotted_string


def _manual_verify(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """Signature check for algorithms ``verify_directly_issued_by`` refuses (e.g. SHA-1 RSA/ECDSA)."""
    if child.issuer != parent.subject:
        return False
    key, hash_alg = parent.public_key(), child.signature_hash_algorithm
    try:
        if isinstance(key, rsa.RSAPublicKey) and hash_alg is not None:
            key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(), hash_alg)
        elif isinstance(key, ec.EllipticCurvePublicKey) and hash_alg is not None:
            key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(hash_alg))
        else:
            return False
        return True
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm):
        return False


def is_directly_issued(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """Cryptographic check that ``child`` was signed by ``parent`` (also checks names)."""
    try:
        child.verify_directly_issued_by(parent)
        return True
    except InvalidSignature:
        return False
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return _manual_verify(child, parent)


def _is_self_signed(cert: x509.Certificate) -> bool:
    if cert.subject != cert.issuer:
        return False
    return is_directly_issued(cert, cert)


def cert_info_from_x509(cert: x509.Certificate) -> CertInfo:
    algo, size = _key_algorithm(cert.public_key())
    bc = _ext_value(cert, x509.BasicConstraints)
    aki = _ext_value(cert, x509.AuthorityKeyIdentifier)
    ski = _ext_value(cert, x509.SubjectKeyIdentifier)
    return CertInfo(
        subject=_name_str(cert.subject),
        issuer=_name_str(cert.issuer),
        common_name=_common_name(cert.subject),
        sans=_sans(cert),
        serial_number=format(cert.serial_number, "X"),
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
        public_key_algorithm=algo,
        public_key_size=size,
        public_key_sha256=public_key_spki_sha256(cert.public_key()),
        signature_algorithm=_signature_algorithm_name(cert),
        not_before=cert.not_valid_before_utc.astimezone(UTC),
        not_after=cert.not_valid_after_utc.astimezone(UTC),
        is_ca=bool(bc.ca) if bc is not None else False,
        is_self_signed=_is_self_signed(cert),
        authority_key_id=_hex(aki.key_identifier) if aki is not None else None,
        subject_key_id=_hex(ski.digest) if ski is not None else None,
        pem=cert.public_bytes(serialization.Encoding.PEM).decode("ascii"),
    )


def x509_from_info(info: CertInfo) -> x509.Certificate:
    return x509.load_pem_x509_certificate(info.pem.encode("ascii"))


# --------------------------------------------------------------------------- PEM helpers
def _load_pem_x509(data: bytes) -> list[x509.Certificate]:
    certs: list[x509.Certificate] = []
    for m in _PEM_BLOCK.finditer(data):
        if m.group(1) in _CERT_LABELS:
            block = b"-----BEGIN CERTIFICATE-----" + m.group(2) + b"-----END CERTIFICATE-----"
            try:
                certs.append(x509.load_pem_x509_certificate(block))
            except Exception as exc:
                raise CertificateError(
                    f"certificate #{len(certs) + 1} is not a valid X.509 certificate",
                    details={"index": len(certs)},
                ) from exc
    return certs


def parse_pem_certificates(data: bytes) -> list[CertInfo]:
    """All CERTIFICATE blocks in ``data`` (surrounding text and other PEM blocks are ignored)."""
    return [cert_info_from_x509(c) for c in _load_pem_x509(data)]


def _pem_labels(data: bytes) -> list[bytes]:
    return [m.group(1) for m in _PEM_BLOCK.finditer(data)]


def has_private_key(data: bytes) -> bool:
    return any(_is_key_label(label) for label in _pem_labels(data))


def private_key_is_encrypted(data: bytes) -> bool:
    for m in _PEM_BLOCK.finditer(data):
        if _is_key_label(m.group(1)) and (
            m.group(1) == b"ENCRYPTED PRIVATE KEY" or b"ENCRYPTED" in m.group(2)[:200]
        ):
            return True
    return False


def _sniff_pkcs12(data: bytes) -> bool:
    if len(data) < 8 or data[0] != 0x30:
        return False
    b = data[1]
    hdr = 2 if b < 0x80 else 2 + (b & 0x7F)
    # PFX ::= SEQUENCE { version INTEGER (3), authSafe ContentInfo (SEQUENCE) ... }
    return data[hdr : hdr + 4] == b"\x02\x01\x03\x30"


def classify_pem(data: bytes) -> FileKind:
    """Classify a file purely from its content; never decodes private keys."""
    if not data or not data.strip():
        return FileKind.UNKNOWN
    if data[:4] in _JKS_MAGIC:
        return FileKind.JKS
    if data[0] == 0x30 and b"-----BEGIN" not in data[:4096]:
        try:
            x509.load_der_x509_certificate(data)
            return FileKind.CERTIFICATE
        except Exception:  # noqa: BLE001, S110 - not a DER certificate
            pass
        if _sniff_pkcs12(data):
            return FileKind.PKCS12
        return FileKind.UNKNOWN
    labels = _pem_labels(data)
    if not labels:
        return FileKind.UNKNOWN
    n_cert = sum(1 for label in labels if label in _CERT_LABELS)
    has_key = any(_is_key_label(label) for label in labels)
    has_csr = any(label in _CSR_LABELS for label in labels)
    if n_cert and has_key:
        return FileKind.COMBINED_PEM
    if has_key:
        return FileKind.PRIVATE_KEY
    if n_cert > 1:
        return FileKind.CERT_BUNDLE
    if n_cert == 1:
        return FileKind.CERTIFICATE
    if has_csr:
        return FileKind.CSR
    return FileKind.UNRELATED_PEM


# --------------------------------------------------------------------------- private keys
def _pw(passphrase: str | bytes | None) -> bytes | None:
    if passphrase is None or passphrase == "" or passphrase == b"":
        return None
    return passphrase.encode("utf-8") if isinstance(passphrase, str) else passphrase


def load_private_key_object(data: bytes, passphrase: str | bytes | None):
    """Return ``(private_key_object, was_encrypted)`` for the first private key block in ``data``."""
    block = None
    for m in _PEM_BLOCK.finditer(data):
        if _is_key_label(m.group(1)):
            block = m.group(0)
            label = m.group(1)
            break
    if block is None:
        raise KeyParseError("no PEM private key found")
    if label == b"OPENSSH PRIVATE KEY":
        raise UnsupportedKeyError("OpenSSH-format private keys are not supported; use PKCS#8 or PEM")
    encrypted = private_key_is_encrypted(block)
    pw = _pw(passphrase)
    try:
        key = serialization.load_pem_private_key(block, password=pw)
        return key, encrypted
    except TypeError as exc:
        msg = str(exc).lower()
        if "not encrypted" in msg and pw is not None:
            try:
                return serialization.load_pem_private_key(block, password=None), False
            except Exception as exc2:
                raise KeyParseError("private key could not be parsed") from exc2
        raise KeyPassphraseRequired("private key is encrypted and no passphrase was supplied") from exc
    except UnsupportedAlgorithm as exc:
        raise UnsupportedKeyError("private key algorithm is not supported") from exc
    except ValueError as exc:
        if encrypted and pw is not None:
            raise KeyPassphraseInvalid("wrong passphrase for the private key") from exc
        if encrypted:
            raise KeyPassphraseRequired("private key is encrypted and no passphrase was supplied") from exc
        raise KeyParseError("private key could not be parsed") from exc


def _supported_private_key(key) -> None:
    if not isinstance(
        key,
        (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey,
         ed448.Ed448PrivateKey, dsa.DSAPrivateKey),
    ):
        raise UnsupportedKeyError("private key type is not supported")


def load_private_key(data: bytes, passphrase: str | bytes | None = None) -> tuple[bytes, str, bool]:
    """Returns ``(unencrypted_pkcs8_pem, spki_sha256_hex, was_encrypted)``."""
    key, encrypted = load_private_key_object(data, passphrase)
    _supported_private_key(key)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return pem, public_key_spki_sha256(key.public_key()), encrypted


# --------------------------------------------------------------------------- ordering
def _issued_by_name(child: x509.Certificate, parent: x509.Certificate, *, strict: bool = True) -> bool:
    """Name (+ key-identifier when ``strict``) based link; signatures are verified in validate."""
    if child.issuer != parent.subject:
        return False
    if not strict:
        return True
    aki = _ext_value(child, x509.AuthorityKeyIdentifier)
    ski = _ext_value(parent, x509.SubjectKeyIdentifier)
    if aki is not None and aki.key_identifier and ski is not None:
        return aki.key_identifier == ski.digest
    return True


def order_certificates(
    certs: Iterable[x509.Certificate], *, prefer_key_sha256: str | None = None,
    leaf_hint: x509.Certificate | None = None,
) -> tuple[x509.Certificate | None, list[x509.Certificate], list[Finding]]:
    """Pick the leaf and order the remaining relevant certs leaf->root."""
    findings: list[Finding] = []
    uniq: dict[bytes, x509.Certificate] = {}
    for c in certs:
        uniq.setdefault(c.fingerprint(hashes.SHA256()), c)
    items = list(uniq.values())
    if not items:
        return None, [], findings

    def issues_someone(c: x509.Certificate) -> bool:
        return any(o is not c and o.subject != o.issuer and _issued_by_name(o, c, strict=False) for o in items)

    leaf: x509.Certificate | None = None
    if leaf_hint is not None:
        leaf = uniq.get(leaf_hint.fingerprint(hashes.SHA256()))
    if leaf is None:
        candidates = [c for c in items if not issues_someone(c)] or list(items)
        if prefer_key_sha256:
            for c in candidates + items:
                if public_key_spki_sha256(c.public_key()) == prefer_key_sha256:
                    leaf = c
                    break
        if leaf is None:
            non_ca = [c for c in candidates if not (_ext_value(c, x509.BasicConstraints) or _NO_CA).ca]
            pool = non_ca or candidates
            leaf = pool[0]
            if len(pool) > 1:
                findings.append(Finding(
                    "AMBIGUOUS_LEAF", Severity.WARNING,
                    f"{len(pool)} certificates look like end-entity certificates; using the first one",
                    {"candidates": [c.subject.rfc4514_string() for c in pool]},
                ))
    chain: list[x509.Certificate] = []
    seen = {leaf.fingerprint(hashes.SHA256())}
    current = leaf
    while not _is_self_signed(current):
        remaining = [o for o in items if o.fingerprint(hashes.SHA256()) not in seen]
        # prefer an exact key-id match; fall back to name only so validate can report CHAIN_INVALID
        parent = next((o for o in remaining if _issued_by_name(current, o)), None) or next(
            (o for o in remaining if _issued_by_name(current, o, strict=False)), None
        )
        if parent is None:
            break
        chain.append(parent)
        seen.add(parent.fingerprint(hashes.SHA256()))
        current = parent
    extra = [o for o in items if o.fingerprint(hashes.SHA256()) not in seen]
    if extra:
        findings.append(Finding(
            "UNRELATED_CERTS", Severity.WARNING,
            f"{len(extra)} certificate(s) are not part of the leaf's chain and were ignored",
            {"subjects": [c.subject.rfc4514_string() for c in extra]},
        ))
    return leaf, chain, findings


class _NoCA:
    ca = False


_NO_CA = _NoCA()


# --------------------------------------------------------------------------- bundles
def _bundle(
    certs: list[x509.Certificate], key_pem: bytes | None, key_sha: str | None, key_encrypted: bool,
    findings: list[Finding], leaf_hint: x509.Certificate | None = None,
) -> ParsedBundle:
    leaf, chain, f2 = order_certificates(certs, prefer_key_sha256=key_sha, leaf_hint=leaf_hint)
    return ParsedBundle(
        leaf=cert_info_from_x509(leaf) if leaf is not None else None,
        chain=tuple(cert_info_from_x509(c) for c in chain),
        private_key_pem=key_pem,
        private_key_public_sha256=key_sha,
        private_key_encrypted=key_encrypted,
        findings=tuple(findings) + tuple(f2),
    )


def _p12_parts(data: bytes, password: str | bytes | None):
    pw = _pw(password)
    try:
        return pkcs12.load_pkcs12(data, pw)
    except UnsupportedAlgorithm as exc:
        raise Pkcs12Error("PKCS#12 uses an unsupported algorithm", code="UNSUPPORTED_KEY_ALGORITHM") from exc
    except ValueError as exc:
        raise Pkcs12Error(
            "PKCS#12 could not be opened: wrong password or corrupt file",
            code="PKCS12_PASSWORD_OR_DATA_INVALID",
        ) from exc


def _p12_key_pem(p12) -> tuple[bytes | None, str | None]:
    if p12.key is None:
        return None, None
    _supported_private_key(p12.key)
    pem = p12.key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return pem, public_key_spki_sha256(p12.key.public_key())


def parse_pkcs12(data: bytes, password: str | bytes | None = None) -> ParsedBundle:
    """Open a PKCS#12 container; raises ``Pkcs12Error`` on wrong password / corrupt data."""
    p12 = _p12_parts(data, password)
    certs = ([p12.cert.certificate] if p12.cert else []) + [c.certificate for c in p12.additional_certs]
    key_pem, key_sha = _p12_key_pem(p12)
    findings: list[Finding] = []
    if len(certs) > MAX_CERTS:
        raise CertificateError(f"too many certificates (max {MAX_CERTS})", code="TOO_MANY_CERTS")
    return _bundle(certs, key_pem, key_sha, _pw(password) is not None, findings,
                   leaf_hint=p12.cert.certificate if p12.cert else None)


def _err_finding(exc: CertificateError, what: str) -> Finding:
    code = exc.code
    return Finding(code, Severity.BLOCKING, f"{what}: {exc}", dict(exc.details))


def _decode_certs(data: bytes, what: str, findings: list[Finding]) -> list[x509.Certificate]:
    if len(data) > MAX_INPUT_BYTES:
        findings.append(Finding("INPUT_TOO_LARGE", Severity.BLOCKING,
                                f"{what} exceeds the {MAX_INPUT_BYTES // 1024} KiB limit",
                                {"input": what, "size": len(data)}))
        return []
    if not data.strip():
        return []
    if b"-----BEGIN" not in data and data[:1] == b"\x30":
        try:
            return [x509.load_der_x509_certificate(data)]
        except Exception:  # noqa: BLE001
            findings.append(Finding("CERT_PARSE_ERROR", Severity.BLOCKING,
                                    f"{what} is not a valid DER certificate", {"input": what}))
            return []
    try:
        return _load_pem_x509(data)
    except CertificateError as exc:
        findings.append(_err_finding(exc, what))
        return []


def parse_upload(
    cert_pem: bytes | None = None,
    key_pem: bytes | None = None,
    chain_pem: bytes | None = None,
    pkcs12: bytes | None = None,
    password: str | None = None,
) -> ParsedBundle:
    """Build a ``ParsedBundle`` from the upload fields. Problems become blocking Findings."""
    findings: list[Finding] = []
    certs: list[x509.Certificate] = []
    leaf_hint = None
    key_pem_out: bytes | None = None
    key_sha: str | None = None
    key_encrypted = False

    # PKCS#12 may arrive in the pkcs12 field or (mis-)placed in the cert field.
    p12_data = pkcs12
    if p12_data is None and cert_pem is not None and classify_pem(cert_pem) == FileKind.PKCS12:
        p12_data, cert_pem = cert_pem, None
    if cert_pem is not None and classify_pem(cert_pem) == FileKind.JKS:
        findings.append(Finding("CERT_PARSE_ERROR", Severity.BLOCKING,
                                "Java keystores (JKS) are not supported; convert to PKCS#12 or PEM"))
        cert_pem = None

    if p12_data is not None:
        if len(p12_data) > MAX_INPUT_BYTES:
            findings.append(Finding("INPUT_TOO_LARGE", Severity.BLOCKING,
                                    f"PKCS#12 exceeds the {MAX_INPUT_BYTES // 1024} KiB limit"))
        else:
            try:
                p12 = _p12_parts(p12_data, password)
                if p12.cert is not None:
                    leaf_hint = p12.cert.certificate
                    certs.append(leaf_hint)
                certs.extend(c.certificate for c in p12.additional_certs)
                key_pem_out, key_sha = _p12_key_pem(p12)
                key_encrypted = _pw(password) is not None
            except CertificateError as exc:
                findings.append(_err_finding(exc, "PKCS#12"))

    for data, what in ((cert_pem, "certificate"), (chain_pem, "chain")):
        if data is not None:
            certs.extend(_decode_certs(data, what, findings))

    # key: dedicated field first, else a private key embedded in the cert/chain field (combined PEM)
    if key_pem is not None and len(key_pem) > MAX_INPUT_BYTES:
        findings.append(Finding("INPUT_TOO_LARGE", Severity.BLOCKING,
                                f"private key exceeds the {MAX_INPUT_BYTES // 1024} KiB limit"))
        key_pem = None
    if key_pem_out is None:
        for data, what in ((key_pem, "private key"), (cert_pem, "embedded private key"),
                           (chain_pem, "embedded private key")):
            if data is None or len(data) > MAX_INPUT_BYTES or not has_private_key(data):
                continue
            try:
                key_pem_out, key_sha, key_encrypted = load_private_key(data, password)
            except CertificateError as exc:
                findings.append(_err_finding(exc, what))
            break
    if key_pem is not None and key_pem.strip():
        if has_private_key(key_pem):
            if cert_pem is None and chain_pem is None and p12_data is None:
                certs.extend(_decode_certs(key_pem, "private key field", findings))  # combined PEM
        else:
            findings.append(Finding("KEY_PARSE_ERROR", Severity.BLOCKING,
                                    "the private key field does not contain a PEM private key"))

    # de-duplicate before limit check
    uniq = {c.fingerprint(hashes.SHA256()): c for c in certs}
    n_blocks = len(uniq)
    if n_blocks > MAX_CERTS:
        findings.append(Finding("TOO_MANY_CERTS", Severity.BLOCKING,
                                f"{n_blocks} certificates supplied; at most {MAX_CERTS} are accepted",
                                {"count": n_blocks}))
        return ParsedBundle(None, (), None, None, False, tuple(findings))
    if not uniq:
        if not any(f.severity == Severity.BLOCKING for f in findings):
            findings.append(Finding("CERT_PARSE_ERROR", Severity.BLOCKING,
                                    "no certificate found in the supplied input"))
        return ParsedBundle(None, (), key_pem_out, key_sha, key_encrypted, tuple(findings))
    return _bundle(list(uniq.values()), key_pem_out, key_sha, key_encrypted, findings, leaf_hint)

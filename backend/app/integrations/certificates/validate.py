"""Pure validation of a ``ParsedBundle`` against policy. No I/O, deterministic given ``now``."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography import x509

from app.integrations.certificates.parse import (
    cert_info_from_x509,
    is_directly_issued,
    x509_from_info,
)
from app.integrations.contracts import CertInfo, Finding, ParsedBundle, Severity

DEFAULT_THRESHOLDS: dict[str, int] = {"info": 60, "warning": 30, "high": 14, "critical": 7}
_SUPPORTED_KEY_ALGOS = {"RSA", "EC", "Ed25519"}
_WEAK_HASHES = {"md2", "md4", "md5", "sha1"}


@dataclass(frozen=True)
class ValidationPolicy:
    min_rsa_bits: int = 2048
    min_ec_bits: int = 256
    allowed_signature_hashes: frozenset[str] = field(
        default_factory=lambda: frozenset({"sha256", "sha384", "sha512"})
    )
    allow_self_signed: bool = False
    warn_if_expires_within_days: int = 30
    require_key: bool = False


# --------------------------------------------------------------------------- time helpers
def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def days_remaining(not_after: datetime, now: datetime) -> int:
    """Whole days until expiry, floored (negative once expired). Naive datetimes are taken as UTC."""
    return (_utc(not_after) - _utc(now)).days


def expiry_status(days: int, thresholds: dict[str, int] | None = None) -> str:
    """"valid" | "info" | "warning" | "high" | "critical" | "expired"."""
    t = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    if days < 0:
        return "expired"
    if days <= t["critical"]:
        return "critical"
    if days <= t["high"]:
        return "high"
    if days <= t["warning"]:
        return "warning"
    if days <= t["info"]:
        return "info"
    return "valid"


# --------------------------------------------------------------------------- hostnames
def _norm_host(h: str) -> str:
    h = h.strip().lower().rstrip(".")
    if h and not h.isascii():
        try:
            h = h.encode("idna").decode("ascii")
        except UnicodeError:
            pass
    return h


def _as_ip(s: str):
    try:
        return ipaddress.ip_address(s.strip("[]"))
    except ValueError:
        return None


def hostname_matches(pattern: str, hostname: str) -> bool:
    """RFC 6125 style: only a whole left-most ``*`` label; wildcard matches exactly one label;
    IP addresses are matched exactly (never through wildcards)."""
    ip_h = _as_ip(hostname)
    ip_p = _as_ip(pattern)
    if ip_h is not None or ip_p is not None:
        return ip_h is not None and ip_p is not None and ip_h == ip_p
    p, h = _norm_host(pattern), _norm_host(hostname)
    if not p or not h:
        return False
    if h.startswith("*."):  # a wildcard requirement is only covered by the identical wildcard SAN
        return p == h
    if "*" not in p:
        return p == h
    if not p.startswith("*.") or "*" in p[2:]:
        return False
    rest = p[2:]
    if rest.count(".") < 1 or not rest.strip("."):  # refuse "*.com"
        return False
    label, _, tail = h.partition(".")
    return bool(label) and tail == rest and "*" not in h


# --------------------------------------------------------------------------- signature helpers
_HASH_RE = re.compile(r"(md2|md4|md5|sha1|sha224|sha256|sha384|sha512|sha3[-_]?\d+)", re.IGNORECASE)


def signature_hash_name(signature_algorithm: str) -> str | None:
    m = _HASH_RE.search(signature_algorithm)
    return m.group(1).lower().replace("-", "").replace("_", "") if m else None


def _subject_label(c: CertInfo) -> str:
    return c.subject


# --------------------------------------------------------------------------- main
def _to_infos(anchors: Iterable) -> list[tuple[CertInfo, x509.Certificate]]:
    out = []
    for a in anchors or ():
        if isinstance(a, CertInfo):
            out.append((a, x509_from_info(a)))
        else:
            out.append((cert_info_from_x509(a), a))
    return out


def validate_bundle(
    bundle: ParsedBundle,
    *,
    now: datetime,
    trust_anchors: Sequence = (),
    required_hostnames: Sequence[str] = (),
    current_cert: CertInfo | None = None,
    policy: ValidationPolicy | None = None,
) -> list[Finding]:
    """Run all checks. The result also contains ``bundle.findings`` (parse-time findings)."""
    policy = policy or ValidationPolicy()
    now = _utc(now)
    out: list[Finding] = list(bundle.findings)

    def add(code: str, sev: Severity, msg: str, **details) -> None:
        out.append(Finding(code, sev, msg, details))

    leaf = bundle.leaf
    if leaf is None:
        add("NO_LEAF", Severity.BLOCKING, "no leaf certificate could be identified in the upload")
        return out

    if bundle.private_key_encrypted:
        add("KEY_ENCRYPTED_INPUT", Severity.INFO,
            "the supplied private key was passphrase protected; it will be stored and deployed unencrypted")

    # --- leaf type
    if leaf.is_ca:
        add("IS_CA_CERT", Severity.BLOCKING,
            "the end-entity certificate has CA=true; this looks like a CA certificate, not a server certificate",
            subject=leaf.subject)

    # --- validity
    _check_dates(add, leaf, now, policy, "leaf")
    for c in bundle.chain:
        if now > c.not_after:
            add("CERT_EXPIRED", Severity.BLOCKING, f"chain certificate '{c.subject}' has expired",
                subject=c.subject, not_after=c.not_after.isoformat(), position="chain")
        elif now < c.not_before:
            add("CERT_NOT_YET_VALID", Severity.BLOCKING,
                f"chain certificate '{c.subject}' is not yet valid",
                subject=c.subject, not_before=c.not_before.isoformat(), position="chain")

    # --- key
    if bundle.private_key_public_sha256 is None:
        if policy.require_key:
            add("KEY_MISSING", Severity.BLOCKING, "a private key is required but none was supplied")
        else:
            add("KEY_MISSING", Severity.INFO,
                "no private key supplied; the key already deployed on the target will be reused")
    elif bundle.private_key_public_sha256 != leaf.public_key_sha256:
        add("KEY_MISMATCH", Severity.BLOCKING,
            "the private key does not match the certificate's public key")

    # --- key strength / algorithms
    for c, pos in [(leaf, "leaf")] + [(c, "chain") for c in bundle.chain if not c.is_self_signed]:
        _check_strength(add, c, policy, pos)

    # --- SANs
    _check_hostnames(add, leaf, required_hostnames)

    # --- chain
    _check_chain(add, bundle, leaf, now, trust_anchors, required_hostnames, policy)

    # --- relative to current certificate
    if current_cert is not None:
        if leaf.not_after < current_cert.not_after:
            add("SHORTER_VALIDITY_THAN_CURRENT", Severity.WARNING,
                "the new certificate expires earlier than the certificate currently deployed",
                new_not_after=leaf.not_after.isoformat(), current_not_after=current_cert.not_after.isoformat())
        if leaf.fingerprint_sha256 == current_cert.fingerprint_sha256:
            add("SAME_AS_CURRENT", Severity.INFO, "the new certificate is identical to the current one")
        if (leaf.public_key_algorithm, leaf.public_key_size) != (
            current_cert.public_key_algorithm, current_cert.public_key_size
        ):
            add("REPLACES_DIFFERENT_KEY_TYPE", Severity.INFO,
                "the new certificate uses a different key type or size than the current one",
                new=f"{leaf.public_key_algorithm}-{leaf.public_key_size}",
                current=f"{current_cert.public_key_algorithm}-{current_cert.public_key_size}")
    return out


def _check_dates(add, leaf: CertInfo, now: datetime, policy: ValidationPolicy, position: str) -> None:
    if now > leaf.not_after:
        add("CERT_EXPIRED", Severity.BLOCKING, "the certificate has expired",
            not_after=leaf.not_after.isoformat(), position=position)
    elif now < leaf.not_before:
        add("CERT_NOT_YET_VALID", Severity.BLOCKING, "the certificate is not yet valid",
            not_before=leaf.not_before.isoformat(), position=position)
    else:
        days = days_remaining(leaf.not_after, now)
        if days <= policy.warn_if_expires_within_days:
            add("EXPIRES_SOON", Severity.WARNING, f"the certificate expires in {days} day(s)",
                days_remaining=days, not_after=leaf.not_after.isoformat())


def _check_strength(add, c: CertInfo, policy: ValidationPolicy, position: str) -> None:
    algo = c.public_key_algorithm
    if algo not in _SUPPORTED_KEY_ALGOS:
        add("UNSUPPORTED_KEY_ALGORITHM", Severity.BLOCKING,
            f"public key algorithm {algo} is not supported", algorithm=algo, position=position)
    elif algo == "RSA" and (c.public_key_size or 0) < policy.min_rsa_bits:
        add("WEAK_KEY", Severity.BLOCKING,
            f"RSA key of {c.public_key_size} bits is below the minimum of {policy.min_rsa_bits}",
            algorithm=algo, bits=c.public_key_size, position=position)
    elif algo == "EC" and (c.public_key_size or 0) < policy.min_ec_bits:
        add("WEAK_KEY", Severity.BLOCKING,
            f"EC key of {c.public_key_size} bits is below the minimum of {policy.min_ec_bits}",
            algorithm=algo, bits=c.public_key_size, position=position)
    h = signature_hash_name(c.signature_algorithm)
    if h is not None and (h in _WEAK_HASHES or h not in policy.allowed_signature_hashes):
        add("WEAK_SIGNATURE", Severity.BLOCKING,
            f"signature algorithm {c.signature_algorithm} is not allowed",
            signature_algorithm=c.signature_algorithm, position=position, subject=c.subject)


def _check_hostnames(add, leaf: CertInfo, required: Sequence[str]) -> None:
    if not required:
        return
    has_san = bool(leaf.sans)
    for host in required:
        if has_san:
            if not any(hostname_matches(s, host) for s in leaf.sans):
                add("SAN_MISMATCH", Severity.BLOCKING,
                    f"'{host}' is not covered by the certificate's subject alternative names",
                    hostname=host, sans=list(leaf.sans))
        elif leaf.common_name and hostname_matches(leaf.common_name, host):
            add("SAN_MISSING_CN_FALLBACK", Severity.WARNING,
                f"certificate has no subject alternative names; '{host}' only matches the common name, "
                "which modern clients ignore", hostname=host, common_name=leaf.common_name)
        else:
            add("SAN_MISMATCH", Severity.BLOCKING,
                f"'{host}' is not covered by the certificate (no SAN extension)",
                hostname=host, sans=[], common_name=leaf.common_name)


def _check_chain(add, bundle: ParsedBundle, leaf: CertInfo, now: datetime, anchors_in: Sequence,
                 required: Sequence[str], policy: ValidationPolicy) -> None:
    anchors = _to_infos(anchors_in)
    anchor_fps = {a.fingerprint_sha256 for a, _ in anchors}
    if leaf.is_self_signed and not bundle.chain:
        if leaf.fingerprint_sha256 in anchor_fps:
            return
        if policy.allow_self_signed:
            return
        add("CHAIN_UNTRUSTED", Severity.BLOCKING,
            "the certificate is self-signed and self-signed certificates are not allowed by policy",
            self_signed=True)
        return

    links = [leaf, *bundle.chain]
    objs = [x509_from_info(c) for c in links]
    links_ok = True
    for i in range(len(links) - 1):
        child, parent = objs[i], objs[i + 1]
        if not links[i + 1].is_ca:
            add("CHAIN_INVALID", Severity.BLOCKING,
                f"issuer '{links[i + 1].subject}' is not marked as a CA", subject=links[i + 1].subject)
            links_ok = False
        if not is_directly_issued(child, parent):
            add("CHAIN_INVALID", Severity.BLOCKING,
                f"'{links[i].subject}' is not signed by '{links[i + 1].subject}'",
                subject=links[i].subject, issuer=links[i + 1].subject)
            links_ok = False

    last, last_obj = links[-1], objs[-1]
    trusted = False
    if last.is_self_signed:
        if anchors:
            trusted = last.fingerprint_sha256 in anchor_fps
            if not trusted:
                add("CHAIN_UNTRUSTED", Severity.WARNING,
                    "the chain ends in a root that is not among the configured trust anchors",
                    root=last.subject)
    else:
        issuer_anchor = next((a for a, ao in anchors if is_directly_issued(last_obj, ao)), None)
        if issuer_anchor is not None:
            trusted = True
        else:
            if anchors:
                spoofed = next((a for a, _ in anchors if a.subject_key_id and a.subject_key_id == last.authority_key_id
                                and a.subject == last.issuer), None)
                if spoofed is not None:
                    add("CHAIN_INVALID", Severity.BLOCKING,
                        f"'{last.subject}' claims to be issued by trust anchor '{spoofed.subject}' "
                        "but the signature does not verify", subject=last.subject)
                    links_ok = False
                else:
                    add("CHAIN_UNTRUSTED", Severity.WARNING,
                        "the chain does not terminate at a configured trust anchor", issuer=last.issuer)
            if len(links) == 1:
                add("CHAIN_INCOMPLETE", Severity.WARNING,
                    "no intermediate/issuer certificate was supplied; clients may fail to build a path",
                    missing_issuer=last.issuer)

    if trusted and links_ok:
        _policy_builder_check(add, leaf, objs, anchors, now, required)


def _policy_builder_check(add, leaf: CertInfo, objs, anchors, now: datetime, required: Sequence[str]) -> None:
    """Full RFC 5280 / CABF-style path validation via cryptography, when available.
    Failures are warnings: private CAs often deviate from the web PKI profile."""
    if now > leaf.not_after or now < leaf.not_before:
        return
    try:
        from cryptography.x509.verification import PolicyBuilder, Store
    except ImportError:
        return
    try:
        subject = None
        names = [s for s in leaf.sans if _as_ip(s) is None]
        if names:
            n = names[0]
            subject = x509.DNSName("www" + n[1:] if n.startswith("*") else n)
        elif leaf.sans:
            subject = x509.IPAddress(ipaddress.ip_address(leaf.sans[0]))
        if subject is None:
            return
        store = Store([ao for _, ao in anchors])
        verifier = PolicyBuilder().store(store).time(now).build_server_verifier(subject)
        verifier.verify(objs[0], list(objs[1:]))
    except AttributeError:
        return  # old cryptography without the verification API
    except Exception as exc:  # noqa: BLE001
        if exc.__class__.__name__ not in ("VerificationError", "UnsupportedGeneralNameType") and not isinstance(
            exc, ValueError
        ):
            return
        add("CHAIN_POLICY_VIOLATION", Severity.WARNING,
            f"path validation against the trust anchors reported a problem: {exc}", reason=str(exc))

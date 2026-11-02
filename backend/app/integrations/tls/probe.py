"""Live TLS endpoint probe (SNI aware).

Two handshakes: (1) unverified, to learn exactly what the server presents; (2) verifying, against
the supplied trust anchors (or the system store) to answer "does this chain validate".
Hostname matching is done on the retrieved leaf (SAN only, RFC 6125), independent of chain validity.
"""
from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import ssl

from cryptography import x509

from app.integrations.certificates.parse import cert_info_from_x509
from app.integrations.contracts import CertInfo, EndpointCertResult


def hostname_matches(cert: CertInfo, hostname: str) -> bool:
    """RFC 6125 style: SAN dNSName (single left-most wildcard label) or iPAddress. CN only if no SAN."""
    name = hostname.strip().rstrip(".").lower()
    if not name:
        return False
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        ip = None
    sans = cert.sans
    if not sans and cert.common_name:
        sans = (cert.common_name.lower(),)
    for san in sans:
        s = san.strip().rstrip(".").lower()
        if ip is not None:
            try:
                if ipaddress.ip_address(s) == ip:
                    return True
            except ValueError:
                pass
            continue
        if s == name:
            return True
        if s.startswith("*.") and s.count("*") == 1:
            suffix = s[1:]                      # ".example.com"
            if name.endswith(suffix) and "." not in name[: -len(suffix)] and name[: -len(suffix)]:
                return True
    return False


def _unverified_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _verifying_context(trust_anchors_pem: bytes | None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False              # hostname handled separately (we may probe by IP with an SNI)
    ctx.verify_mode = ssl.CERT_REQUIRED
    if trust_anchors_pem:
        ctx.load_verify_locations(cadata=trust_anchors_pem.decode("ascii", errors="ignore"))
    else:
        ctx.load_default_certs()
    return ctx


async def _handshake(host: str, port: int, sni: str | None, ctx: ssl.SSLContext, timeout: float):
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni, ssl_handshake_timeout=timeout),
        timeout=timeout,
    )
    return reader, writer


def _chain_der(ssl_obj: ssl.SSLObject) -> list[bytes]:
    der_chain: list[bytes] = []
    getter = getattr(ssl_obj, "get_unverified_chain", None)
    if getter is not None:
        try:
            for c in getter() or []:
                der_chain.append(c if isinstance(c, bytes) else ssl.PEM_cert_to_DER_cert(c.public_bytes()))
        except Exception:  # noqa: BLE001 - fall back to leaf only
            der_chain = []
    if not der_chain:
        leaf = ssl_obj.getpeercert(binary_form=True)
        if leaf:
            der_chain = [leaf]
    return der_chain


async def probe_endpoint(host: str, port: int, sni: str | None, timeout: float,
                         trust_anchors_pem: bytes | None = None,
                         expected_hostname: str | None = None) -> EndpointCertResult:
    """Return the certificate chain a TLS endpoint actually serves, plus validity/hostname verdicts."""
    leaf: CertInfo | None = None
    chain: tuple[CertInfo, ...] = ()
    tls_version: str | None = None
    try:
        _, writer = await _handshake(host, port, sni, _unverified_context(), timeout)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        return EndpointCertResult(host, port, sni, False, None, (), None, None,
                                  f"{type(exc).__name__}: {exc}"[:300], None)
    try:
        ssl_obj: ssl.SSLObject = writer.get_extra_info("ssl_object")
        tls_version = ssl_obj.version()
        ders = _chain_der(ssl_obj)
        parsed = [cert_info_from_x509(x509.load_der_x509_certificate(d)) for d in ders]
    except Exception as exc:  # noqa: BLE001
        return EndpointCertResult(host, port, sni, False, None, (), None, None,
                                  f"could not parse served certificate: {type(exc).__name__}", tls_version)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), timeout=2)
    if not parsed:
        return EndpointCertResult(host, port, sni, False, None, (), None, None, "server presented no certificate",
                                  tls_version)
    leaf, chain = parsed[0], tuple(parsed[1:])

    expected = expected_hostname or sni or host
    hostname_ok = hostname_matches(leaf, expected)

    chain_valid: bool | None
    try:
        _, vwriter = await _handshake(host, port, sni, _verifying_context(trust_anchors_pem), timeout)
        vwriter.close()
        chain_valid = True
    except ssl.SSLCertVerificationError:
        chain_valid = False
    except (OSError, ssl.SSLError, TimeoutError):
        chain_valid = None
    return EndpointCertResult(host, port, sni, True, leaf, chain, chain_valid, hostname_ok, None, tls_version)

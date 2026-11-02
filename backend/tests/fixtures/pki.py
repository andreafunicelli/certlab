"""Throwaway PKI builders for tests. Never use outside tests: keys are generated in-process.

All ``*_pem`` attributes are ``bytes``. Private keys are unencrypted PKCS#8 unless stated.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

UTC = dt.UTC
_HASHES = {"sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}


def now_utc() -> dt.datetime:
    return dt.datetime.now(UTC).replace(microsecond=0)


def make_key(kind: str = "rsa2048"):
    """kind: rsa1024 | rsa2048 | rsa3072 | rsa4096 | ec256 | ec384"""
    if kind.startswith("rsa"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(kind[3:]))
    if kind == "ec256":
        return ec.generate_private_key(ec.SECP256R1())
    if kind == "ec384":
        return ec.generate_private_key(ec.SECP384R1())
    raise ValueError(f"unknown key kind {kind}")


def key_to_pem(key, passphrase: bytes | None = None) -> bytes:
    enc = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


@dataclass
class Issued:
    cert: x509.Certificate
    key: object

    @property
    def cert_pem(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def key_pem(self) -> bytes:
        return key_to_pem(self.key)

    def encrypted_key_pem(self, passphrase: bytes) -> bytes:
        return key_to_pem(self.key, passphrase)

    @property
    def cert_der(self) -> bytes:
        return self.cert.public_bytes(serialization.Encoding.DER)


def _name(cn: str, org: str = "CertLab Test") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def _san_list(sans: list[str]) -> list[x509.GeneralName]:
    out: list[x509.GeneralName] = []
    for s in sans:
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(s)))
        except ValueError:
            out.append(x509.DNSName(s))
    return out


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _sha1_resign(cert: x509.Certificate, signing_key) -> x509.Certificate:
    """cryptography refuses to *build* SHA-1 certificates, so patch the AlgorithmIdentifier of a
    sha256WithRSA cert (same DER length) and re-sign the TBS with PKCS#1 v1.5 + SHA-1 (RSA issuers only)."""
    if not isinstance(signing_key, rsa.RSAPrivateKey):
        raise TypeError("sha1 test certificates need an RSA issuer key")
    alg256 = bytes.fromhex("300d06092a864886f70d01010b0500")
    alg1 = bytes.fromhex("300d06092a864886f70d0101050500")
    tbs = cert.tbs_certificate_bytes
    assert alg256 in tbs
    tbs = tbs.replace(alg256, alg1, 1)
    sig = signing_key.sign(tbs, padding.PKCS1v15(), hashes.SHA1())
    bitstring = b"\x03" + _der_len(len(sig) + 1) + b"\x00" + sig
    body = tbs + alg1 + bitstring
    return x509.load_der_x509_certificate(b"\x30" + _der_len(len(body)) + body)


def _issue(
    *, subject_cn: str, key, issuer: Issued | None, is_ca: bool, sans: list[str] | None = None,
    not_before: dt.datetime | None = None, not_after: dt.datetime | None = None,
    sig_hash: str = "sha256", path_length: int | None = None, with_san_ext: bool = True,
    org: str = "CertLab Test",
) -> Issued:
    now = now_utc()
    not_before = not_before or now - dt.timedelta(days=1)
    not_after = not_after or now + dt.timedelta(days=90)
    subject = _name(subject_cn, org)
    signing_key = issuer.key if issuer else key
    issuer_name = issuer.cert.subject if issuer else subject
    b = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=path_length if is_ca else None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if issuer:
        b = b.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.cert.public_key()), critical=False
        )
    if is_ca:
        b = b.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True
        )
    else:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        if with_san_ext and sans:
            b = b.add_extension(x509.SubjectAlternativeName(_san_list(sans)), critical=False)
    if sig_hash == "sha1":
        cert = _sha1_resign(b.sign(signing_key, hashes.SHA256()), signing_key)
    else:
        cert = b.sign(signing_key, _HASHES[sig_hash]())
    return Issued(cert, key)


def make_root_ca(cn: str = "CertLab Test Root CA", key_kind: str = "rsa2048", days: int = 3650,
                 sig_hash: str = "sha256") -> Issued:
    now = now_utc()
    return _issue(subject_cn=cn, key=make_key(key_kind), issuer=None, is_ca=True, path_length=2,
                  not_before=now - dt.timedelta(days=2), not_after=now + dt.timedelta(days=days),
                  sig_hash=sig_hash)


def make_intermediate_ca(root: Issued, cn: str = "CertLab Test Intermediate CA", key_kind: str = "rsa2048",
                         days: int = 1825) -> Issued:
    now = now_utc()
    return _issue(subject_cn=cn, key=make_key(key_kind), issuer=root, is_ca=True, path_length=0,
                  not_before=now - dt.timedelta(days=1), not_after=now + dt.timedelta(days=days))


def make_leaf(
    issuer: Issued, sans: list[str] | None = None, cn: str | None = None, key_kind: str = "rsa2048",
    not_before: dt.datetime | None = None, not_after: dt.datetime | None = None,
    sig_hash: str = "sha256", key=None, is_ca: bool = False, with_san_ext: bool = True,
) -> Issued:
    sans = sans if sans is not None else ["www.example.com", "example.com"]
    cn = cn or (sans[0] if sans else "leaf.example.com")
    return _issue(subject_cn=cn, key=key or make_key(key_kind), issuer=issuer, is_ca=is_ca, sans=sans,
                  not_before=not_before, not_after=not_after, sig_hash=sig_hash, with_san_ext=with_san_ext)


def make_self_signed(sans: list[str] | None = None, cn: str | None = None, key_kind: str = "rsa2048",
                     days: int = 90) -> Issued:
    sans = sans if sans is not None else ["self.example.com"]
    now = now_utc()
    return _issue(subject_cn=cn or sans[0], key=make_key(key_kind), issuer=None, is_ca=False, sans=sans,
                  not_before=now - dt.timedelta(days=1), not_after=now + dt.timedelta(days=days))


def make_expired_leaf(issuer: Issued, sans: list[str] | None = None) -> Issued:
    now = now_utc()
    return make_leaf(issuer, sans, not_before=now - dt.timedelta(days=400), not_after=now - dt.timedelta(days=10))


def make_not_yet_valid_leaf(issuer: Issued, sans: list[str] | None = None) -> Issued:
    now = now_utc()
    return make_leaf(issuer, sans, not_before=now + dt.timedelta(days=5), not_after=now + dt.timedelta(days=95))


def make_sha1_leaf(issuer: Issued, sans: list[str] | None = None) -> Issued:
    return make_leaf(issuer, sans, sig_hash="sha1")


def to_pkcs12(leaf: Issued, chain: list[Issued] | None = None, password: bytes | None = b"changeit",
              name: bytes = b"test") -> bytes:
    enc = serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
    return pkcs12.serialize_key_and_certificates(
        name, leaf.key, leaf.cert, [c.cert for c in (chain or [])], enc
    )


@dataclass
class TestPki:
    __test__ = False  # not a pytest class

    root: Issued
    intermediate: Issued
    leaf: Issued

    @property
    def fullchain_pem(self) -> bytes:
        """leaf + intermediate (root omitted, like a normal fullchain)."""
        return self.leaf.cert_pem + self.intermediate.cert_pem

    @property
    def chain_pem(self) -> bytes:
        return self.intermediate.cert_pem

    @property
    def root_pem(self) -> bytes:
        return self.root.cert_pem


def make_pki(sans: list[str] | None = None, leaf_key_kind: str = "rsa2048", **leaf_kwargs) -> TestPki:
    """Root -> Intermediate -> leaf (valid 90 days)."""
    root = make_root_ca()
    inter = make_intermediate_ca(root)
    leaf = make_leaf(inter, sans, key_kind=leaf_key_kind, **leaf_kwargs)
    return TestPki(root, inter, leaf)

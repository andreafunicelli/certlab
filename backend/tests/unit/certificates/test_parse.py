from __future__ import annotations

import datetime as dt
import random

import pytest

from app.integrations.certificates.errors import (
    CertificateError,
    KeyParseError,
    KeyPassphraseInvalid,
    KeyPassphraseRequired,
    Pkcs12Error,
    UnsupportedKeyError,
)
from app.integrations.certificates.keys import key_matches_cert, public_key_spki_sha256
from app.integrations.certificates.parse import (
    MAX_CERTS,
    MAX_INPUT_BYTES,
    cert_info_from_x509,
    classify_pem,
    load_private_key,
    parse_pem_certificates,
    parse_pkcs12,
    parse_upload,
)
from app.integrations.contracts import FileKind, Severity
from tests.fixtures import pki


@pytest.fixture(scope="module")
def chain():
    return pki.make_pki(["www.example.com", "example.com", "10.1.2.3", "*.wild.example.com"])


def codes(findings):
    return {f.code for f in findings}


class TestCertInfo:
    def test_fields(self, chain):
        info = parse_pem_certificates(chain.leaf.cert_pem)[0]
        assert info.sans == ("www.example.com", "example.com", "10.1.2.3", "*.wild.example.com")
        assert info.common_name == "www.example.com"
        assert info.public_key_algorithm == "RSA" and info.public_key_size == 2048
        assert info.fingerprint_sha256 == info.fingerprint_sha256.lower() and len(info.fingerprint_sha256) == 64
        assert info.serial_number == info.serial_number.upper() and ":" not in info.serial_number
        assert info.not_after.tzinfo is not None and info.not_after.utcoffset() == dt.timedelta(0)
        assert not info.is_ca and not info.is_self_signed
        assert info.authority_key_id and info.subject_key_id
        assert info.signature_algorithm == "sha256WithRSAEncryption"
        assert info.public_key_sha256 == public_key_spki_sha256(chain.leaf.key.public_key())
        assert info.pem.startswith("-----BEGIN CERTIFICATE-----")

    def test_ca_and_self_signed(self, chain):
        root = cert_info_from_x509(chain.root.cert)
        assert root.is_ca and root.is_self_signed
        inter = cert_info_from_x509(chain.intermediate.cert)
        assert inter.is_ca and not inter.is_self_signed

    def test_ec_key(self):
        root = pki.make_root_ca()
        leaf = pki.make_leaf(root, ["ec.example.com"], key_kind="ec384")
        info = cert_info_from_x509(leaf.cert)
        assert (info.public_key_algorithm, info.public_key_size) == ("EC", 384)

    def test_dns_lowercased(self):
        root = pki.make_root_ca()
        leaf = pki.make_leaf(root, ["WWW.Example.COM"])
        assert cert_info_from_x509(leaf.cert).sans == ("www.example.com",)

    def test_bundle_text_and_noise_ignored(self, chain):
        data = b"some text\n" + chain.leaf.cert_pem + b"\nnoise\n" + chain.intermediate.cert_pem
        assert len(parse_pem_certificates(data)) == 2

    def test_invalid_block_raises(self):
        with pytest.raises(CertificateError):
            parse_pem_certificates(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")


class TestClassify:
    def test_kinds(self, chain):
        leaf, key = chain.leaf.cert_pem, chain.leaf.key_pem
        assert classify_pem(leaf) == FileKind.CERTIFICATE
        assert classify_pem(chain.fullchain_pem) == FileKind.CERT_BUNDLE
        assert classify_pem(key) == FileKind.PRIVATE_KEY
        assert classify_pem(leaf + key) == FileKind.COMBINED_PEM
        assert classify_pem(chain.leaf.encrypted_key_pem(b"pw")) == FileKind.PRIVATE_KEY
        assert classify_pem(chain.leaf.cert_der) == FileKind.CERTIFICATE
        assert classify_pem(b"") == FileKind.UNKNOWN
        assert classify_pem(b"hello world") == FileKind.UNKNOWN

    def test_legacy_key_labels(self):
        for label in ("RSA PRIVATE KEY", "EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"):
            pem = f"-----BEGIN {label}-----\nAAAA\n-----END {label}-----\n".encode()
            assert classify_pem(pem) == FileKind.PRIVATE_KEY

    def test_csr_and_other(self):
        csr = b"-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----\n"
        assert classify_pem(csr) == FileKind.CSR
        pub = b"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"
        assert classify_pem(pub) == FileKind.UNRELATED_PEM
        dh = b"-----BEGIN DH PARAMETERS-----\nAAAA\n-----END DH PARAMETERS-----\n"
        assert classify_pem(dh) == FileKind.UNRELATED_PEM

    def test_pkcs12_and_jks(self, chain):
        assert classify_pem(pki.to_pkcs12(chain.leaf, [chain.intermediate])) == FileKind.PKCS12
        assert classify_pem(b"\xfe\xed\xfe\xed\x00\x00\x00\x02" + b"\x00" * 16) == FileKind.JKS

    def test_classification_does_not_decode_keys(self):
        # garbage body but valid armour -> still PRIVATE_KEY
        pem = b"-----BEGIN PRIVATE KEY-----\n!!!notbase64!!!\n-----END PRIVATE KEY-----\n"
        assert classify_pem(pem) == FileKind.PRIVATE_KEY


class TestPrivateKey:
    def test_plain(self, chain):
        pem, sha, enc = load_private_key(chain.leaf.key_pem, None)
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----") and not enc
        assert sha == cert_info_from_x509(chain.leaf.cert).public_key_sha256

    def test_encrypted(self, chain):
        pem, _sha, enc = load_private_key(chain.leaf.encrypted_key_pem(b"s3cret"), "s3cret")
        assert enc and b"ENCRYPTED" not in pem

    def test_wrong_and_missing_passphrase(self, chain):
        data = chain.leaf.encrypted_key_pem(b"s3cret")
        with pytest.raises(KeyPassphraseInvalid):
            load_private_key(data, "nope")
        with pytest.raises(KeyPassphraseRequired):
            load_private_key(data, None)

    def test_passphrase_given_for_plain_key(self, chain):
        _, _, enc = load_private_key(chain.leaf.key_pem, "unneeded")
        assert enc is False

    def test_garbage_and_unsupported(self):
        with pytest.raises(KeyParseError):
            load_private_key(b"nothing", None)
        with pytest.raises(KeyParseError):
            load_private_key(b"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", None)
        with pytest.raises(UnsupportedKeyError):
            load_private_key(b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")

    def test_error_messages_have_no_key_material(self, chain):
        with pytest.raises(KeyPassphraseInvalid) as ei:
            load_private_key(chain.leaf.encrypted_key_pem(b"x"), "y")
        assert "BEGIN" not in str(ei.value)

    def test_combined_input(self, chain):
        _, sha, _ = load_private_key(chain.leaf.cert_pem + chain.leaf.key_pem, None)
        assert sha == cert_info_from_x509(chain.leaf.cert).public_key_sha256

    def test_ec_key(self):
        root = pki.make_root_ca()
        leaf = pki.make_leaf(root, ["e.example.com"], key_kind="ec256")
        info = cert_info_from_x509(leaf.cert)
        assert key_matches_cert(leaf.key_pem, None, info)


class TestKeyMatch:
    def test_match_and_mismatch(self, chain):
        info = cert_info_from_x509(chain.leaf.cert)
        assert key_matches_cert(chain.leaf.key_pem, None, info)
        other = pki.make_key("rsa2048")
        assert not key_matches_cert(pki.key_to_pem(other), None, info)

    def test_encrypted(self, chain):
        info = cert_info_from_x509(chain.leaf.cert)
        assert key_matches_cert(chain.leaf.encrypted_key_pem(b"pw"), "pw", info)
        with pytest.raises(KeyPassphraseInvalid):
            key_matches_cert(chain.leaf.encrypted_key_pem(b"pw"), "bad", info)


class TestPkcs12:
    def test_round_trip(self, chain):
        data = pki.to_pkcs12(chain.leaf, [chain.intermediate, chain.root], b"changeit")
        b = parse_pkcs12(data, "changeit")
        assert b.leaf.fingerprint_sha256 == cert_info_from_x509(chain.leaf.cert).fingerprint_sha256
        assert [c.subject for c in b.chain] == [
            cert_info_from_x509(chain.intermediate.cert).subject,
            cert_info_from_x509(chain.root.cert).subject,
        ]
        assert b.private_key_pem.startswith(b"-----BEGIN PRIVATE KEY-----")
        assert b.private_key_public_sha256 == b.leaf.public_key_sha256
        assert b.private_key_encrypted

    def test_wrong_password(self, chain):
        data = pki.to_pkcs12(chain.leaf, [], b"changeit")
        with pytest.raises(Pkcs12Error):
            parse_pkcs12(data, "wrong")
        with pytest.raises(Pkcs12Error):
            parse_pkcs12(data, None)

    def test_garbage(self):
        with pytest.raises(Pkcs12Error):
            parse_pkcs12(b"\x30\x03\x02\x01\x03", "x")

    def test_upload_wrong_password_finding(self, chain):
        data = pki.to_pkcs12(chain.leaf, [], b"changeit")
        b = parse_upload(pkcs12=data, password="nope")
        assert b.leaf is None
        assert any(f.severity == Severity.BLOCKING and f.code.startswith("PKCS12") for f in b.findings)

    def test_upload_via_pkcs12_field(self, chain):
        data = pki.to_pkcs12(chain.leaf, [chain.intermediate], b"changeit")
        b = parse_upload(pkcs12=data, password="changeit")
        assert b.leaf and len(b.chain) == 1 and b.private_key_pem

    def test_upload_p12_in_cert_field(self, chain):
        data = pki.to_pkcs12(chain.leaf, [chain.intermediate], b"changeit")
        b = parse_upload(cert_pem=data, password="changeit")
        assert b.leaf and b.private_key_pem

    def test_no_password_container(self, chain):
        data = pki.to_pkcs12(chain.leaf, [], None)
        b = parse_pkcs12(data, None)
        assert b.leaf and not b.private_key_encrypted


class TestParseUpload:
    def test_simple(self, chain):
        b = parse_upload(chain.leaf.cert_pem, chain.leaf.key_pem, chain.chain_pem)
        assert b.leaf.subject == cert_info_from_x509(chain.leaf.cert).subject
        assert len(b.chain) == 1
        assert b.private_key_public_sha256 == b.leaf.public_key_sha256
        assert not b.findings

    def test_fullchain_in_cert_field(self, chain):
        b = parse_upload(chain.fullchain_pem, chain.leaf.key_pem)
        assert b.leaf.subject.startswith("CN=www.example.com")
        assert len(b.chain) == 1 and b.chain[0].is_ca

    def test_shuffled_fullchain_with_root(self, chain):
        certs = [chain.root.cert_pem, chain.intermediate.cert_pem, chain.leaf.cert_pem]
        for seed in range(6):
            random.Random(seed).shuffle(certs)
            b = parse_upload(b"".join(certs), None)
            assert b.leaf.subject == cert_info_from_x509(chain.leaf.cert).subject
            assert [c.is_self_signed for c in b.chain] == [False, True]
            assert b.chain[0].subject == cert_info_from_x509(chain.intermediate.cert).subject

    def test_chain_in_separate_field_shuffled_and_dupes(self, chain):
        b = parse_upload(chain.leaf.cert_pem, None, chain.root.cert_pem + chain.intermediate.cert_pem + chain.intermediate.cert_pem)
        assert len(b.chain) == 2 and not b.chain[0].is_self_signed and b.chain[1].is_self_signed

    def test_combined_pem_in_cert_field(self, chain):
        b = parse_upload(chain.leaf.cert_pem + chain.leaf.key_pem + chain.chain_pem)
        assert b.leaf and b.private_key_pem and len(b.chain) == 1

    def test_combined_pem_in_key_field(self, chain):
        b = parse_upload(None, chain.leaf.cert_pem + chain.leaf.key_pem)
        assert b.leaf and b.private_key_pem

    def test_encrypted_key(self, chain):
        enc = chain.leaf.encrypted_key_pem(b"pw")
        b = parse_upload(chain.leaf.cert_pem, enc, password="pw")
        assert b.private_key_encrypted and b.private_key_pem and not b.findings
        b = parse_upload(chain.leaf.cert_pem, enc, password="bad")
        assert "KEY_PASSPHRASE_INVALID" in codes(b.findings) and b.private_key_pem is None
        b = parse_upload(chain.leaf.cert_pem, enc)
        assert "KEY_PASSPHRASE_REQUIRED" in codes(b.findings)

    def test_leaf_chosen_by_key_when_ambiguous(self):
        root = pki.make_root_ca()
        a, b_ = pki.make_leaf(root, ["a.example.com"]), pki.make_leaf(root, ["b.example.com"])
        res = parse_upload(a.cert_pem + b_.cert_pem + root.cert_pem, b_.key_pem)
        assert res.leaf.common_name == "b.example.com"
        assert "UNRELATED_CERTS" in codes(res.findings)  # the other leaf is not in b's chain

    def test_ambiguous_without_key_warns(self):
        root = pki.make_root_ca()
        a, b_ = pki.make_leaf(root, ["a.example.com"]), pki.make_leaf(root, ["b.example.com"])
        res = parse_upload(a.cert_pem + b_.cert_pem)
        assert "AMBIGUOUS_LEAF" in codes(res.findings)

    def test_der_cert(self, chain):
        b = parse_upload(chain.leaf.cert_der)
        assert b.leaf and not b.chain

    def test_self_signed_single(self):
        ss = pki.make_self_signed()
        b = parse_upload(ss.cert_pem, ss.key_pem)
        assert b.leaf.is_self_signed and b.chain == ()

    def test_ca_only(self, chain):
        b = parse_upload(chain.root.cert_pem)
        assert b.leaf.is_ca

    def test_empty_and_garbage(self):
        assert parse_upload().leaf is None and "CERT_PARSE_ERROR" in codes(parse_upload().findings)
        b = parse_upload(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
        assert b.leaf is None and "CERT_PARSE_ERROR" in codes(b.findings)

    def test_key_field_without_key(self, chain):
        b = parse_upload(chain.leaf.cert_pem, chain.leaf.cert_pem)
        assert "KEY_PARSE_ERROR" in codes(b.findings)

    def test_jks_rejected(self):
        b = parse_upload(b"\xfe\xed\xfe\xed" + b"\x00" * 30)
        assert b.leaf is None and "CERT_PARSE_ERROR" in codes(b.findings)

    def test_size_limit(self, chain):
        big = chain.leaf.cert_pem + b"#" * (MAX_INPUT_BYTES + 1)
        b = parse_upload(big, chain.leaf.key_pem)
        assert "INPUT_TOO_LARGE" in codes(b.findings) and b.leaf is None
        b = parse_upload(chain.leaf.cert_pem, b"x" * (MAX_INPUT_BYTES + 1))
        assert "INPUT_TOO_LARGE" in codes(b.findings)

    def test_too_many_certs(self):
        root = pki.make_root_ca()
        pems = b"".join(pki.make_leaf(root, [f"h{i}.example.com"]).cert_pem for i in range(MAX_CERTS + 1))
        b = parse_upload(pems)
        assert "TOO_MANY_CERTS" in codes(b.findings) and b.leaf is None

    def test_exactly_max_certs_ok(self):
        root = pki.make_root_ca()
        pems = b"".join(pki.make_leaf(root, [f"h{i}.example.com"]).cert_pem for i in range(MAX_CERTS))
        assert "TOO_MANY_CERTS" not in codes(parse_upload(pems).findings)

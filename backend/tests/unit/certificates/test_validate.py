from __future__ import annotations

import datetime as dt

import pytest

from app.integrations.certificates.parse import cert_info_from_x509, parse_upload
from app.integrations.certificates.validate import (
    ValidationPolicy,
    days_remaining,
    expiry_status,
    hostname_matches,
    validate_bundle,
)
from app.integrations.contracts import Severity
from tests.fixtures import pki

NOW = pki.now_utc()
UTC = dt.UTC


def run(parsed, **kw):
    kw.setdefault("now", NOW)
    return validate_bundle(parsed, **kw)


def by_code(findings):
    return {f.code: f for f in findings}


@pytest.fixture(scope="module")
def p():
    return pki.make_pki(["www.example.com", "example.com", "*.wild.example.com", "10.0.0.5"])


def good(p):
    return parse_upload(p.fullchain_pem, p.leaf.key_pem)


class TestHappyPath:
    def test_clean(self, p):
        assert run(good(p), trust_anchors=[p.root.cert], required_hostnames=["www.example.com"]) == []

    def test_anchor_as_certinfo(self, p):
        assert run(good(p), trust_anchors=[cert_info_from_x509(p.root.cert)]) == []

    def test_with_root_in_bundle(self, p):
        b = parse_upload(p.fullchain_pem + p.root_pem, p.leaf.key_pem)
        assert run(b, trust_anchors=[p.root.cert]) == []


class TestDates:
    def test_expired(self, p):
        leaf = pki.make_expired_leaf(p.intermediate)
        f = by_code(run(parse_upload(leaf.cert_pem + p.chain_pem, leaf.key_pem)))
        assert f["CERT_EXPIRED"].severity == Severity.BLOCKING
        assert "EXPIRES_SOON" not in f

    def test_not_yet_valid(self, p):
        leaf = pki.make_not_yet_valid_leaf(p.intermediate)
        f = by_code(run(parse_upload(leaf.cert_pem + p.chain_pem, leaf.key_pem)))
        assert f["CERT_NOT_YET_VALID"].severity == Severity.BLOCKING

    def test_expires_soon(self, p):
        leaf = pki.make_leaf(p.intermediate, ["a.example.com"], not_after=NOW + dt.timedelta(days=10, hours=1))
        f = by_code(run(parse_upload(leaf.cert_pem + p.chain_pem, leaf.key_pem)))
        assert f["EXPIRES_SOON"].severity == Severity.WARNING and f["EXPIRES_SOON"].details["days_remaining"] == 10

    def test_policy_window(self, p):
        b = good(p)  # ~90 days
        assert "EXPIRES_SOON" not in by_code(run(b))
        assert "EXPIRES_SOON" in by_code(run(b, policy=ValidationPolicy(warn_if_expires_within_days=120)))

    def test_naive_now_treated_as_utc(self, p):
        assert run(good(p), now=NOW.replace(tzinfo=None)) == run(good(p), now=NOW)

    def test_expired_intermediate(self, p):
        root = pki.make_root_ca()
        inter = pki._issue(subject_cn="old inter", key=pki.make_key(), issuer=root, is_ca=True,
                           not_before=NOW - dt.timedelta(days=100), not_after=NOW - dt.timedelta(days=1))
        leaf = pki.make_leaf(inter, ["a.example.com"])
        f = run(parse_upload(leaf.cert_pem + inter.cert_pem, leaf.key_pem))
        assert any(x.code == "CERT_EXPIRED" and x.details["position"] == "chain" for x in f)


class TestKey:
    def test_mismatch(self, p):
        b = parse_upload(p.fullchain_pem, pki.key_to_pem(pki.make_key("rsa2048")))
        assert by_code(run(b))["KEY_MISMATCH"].severity == Severity.BLOCKING

    def test_missing_info_and_required(self, p):
        b = parse_upload(p.fullchain_pem)
        assert by_code(run(b))["KEY_MISSING"].severity == Severity.INFO
        f = by_code(run(b, policy=ValidationPolicy(require_key=True)))
        assert f["KEY_MISSING"].severity == Severity.BLOCKING

    def test_encrypted_info(self, p):
        b = parse_upload(p.fullchain_pem, p.leaf.encrypted_key_pem(b"pw"), password="pw")
        assert by_code(run(b))["KEY_ENCRYPTED_INPUT"].severity == Severity.INFO

    def test_weak_rsa(self, p):
        leaf = pki.make_leaf(p.intermediate, ["a.example.com"], key_kind="rsa1024")
        f = by_code(run(parse_upload(leaf.cert_pem + p.chain_pem, leaf.key_pem)))
        assert f["WEAK_KEY"].severity == Severity.BLOCKING and f["WEAK_KEY"].details["bits"] == 1024

    def test_weak_rsa_policy_relaxed(self, p):
        leaf = pki.make_leaf(p.intermediate, ["a.example.com"], key_kind="rsa1024")
        b = parse_upload(leaf.cert_pem + p.chain_pem, leaf.key_pem)
        assert "WEAK_KEY" not in by_code(run(b, policy=ValidationPolicy(min_rsa_bits=1024)))

    def test_ec_ok_and_below_policy(self, p):
        leaf = pki.make_leaf(p.intermediate, ["a.example.com"], key_kind="ec256")
        b = parse_upload(leaf.cert_pem + p.chain_pem, leaf.key_pem)
        assert "WEAK_KEY" not in by_code(run(b))
        assert "WEAK_KEY" in by_code(run(b, policy=ValidationPolicy(min_ec_bits=384)))

    def test_sha1_signature(self, p):
        leaf = pki.make_sha1_leaf(p.intermediate, ["a.example.com"])
        f = by_code(run(parse_upload(leaf.cert_pem + p.chain_pem, leaf.key_pem)))
        assert f["WEAK_SIGNATURE"].severity == Severity.BLOCKING

    def test_sha384_allowed(self, p):
        leaf = pki.make_leaf(p.intermediate, ["a.example.com"], sig_hash="sha384")
        assert "WEAK_SIGNATURE" not in by_code(run(parse_upload(leaf.cert_pem + p.chain_pem)))


class TestLeafType:
    def test_ca_leaf(self, p):
        b = parse_upload(p.root_pem)
        f = by_code(run(b))
        assert f["IS_CA_CERT"].severity == Severity.BLOCKING

    def test_no_leaf(self):
        b = parse_upload()
        assert by_code(run(b))["NO_LEAF"].severity == Severity.BLOCKING
        assert "CERT_PARSE_ERROR" in by_code(run(b))  # parse findings are passed through


class TestSan:
    def test_mismatch(self, p):
        f = run(good(p), required_hostnames=["www.example.com", "other.example.com"])
        mm = [x for x in f if x.code == "SAN_MISMATCH"]
        assert len(mm) == 1 and mm[0].details["hostname"] == "other.example.com"
        assert mm[0].severity == Severity.BLOCKING

    def test_wildcard_and_ip(self, p):
        f = run(good(p), required_hostnames=["a.wild.example.com", "10.0.0.5"])
        assert not [x for x in f if x.code == "SAN_MISMATCH"]
        f = run(good(p), required_hostnames=["a.b.wild.example.com", "wild.example.com", "10.0.0.6"])
        assert len([x for x in f if x.code == "SAN_MISMATCH"]) == 3

    def test_cn_fallback_only_without_san(self, p):
        leaf = pki.make_leaf(p.intermediate, [], cn="legacy.example.com", with_san_ext=False)
        b = parse_upload(leaf.cert_pem + p.chain_pem)
        f = by_code(run(b, required_hostnames=["legacy.example.com"]))
        assert f["SAN_MISSING_CN_FALLBACK"].severity == Severity.WARNING and "SAN_MISMATCH" not in f
        f = by_code(run(b, required_hostnames=["x.example.com"]))
        assert "SAN_MISMATCH" in f

    def test_cn_ignored_when_san_present(self, p):
        leaf = pki.make_leaf(p.intermediate, ["only.example.com"], cn="cn.example.com")
        b = parse_upload(leaf.cert_pem + p.chain_pem)
        assert "SAN_MISMATCH" in by_code(run(b, required_hostnames=["cn.example.com"]))


class TestHostnameMatches:
    @pytest.mark.parametrize(
        ("pattern", "host", "expected"),
        [
            ("*.example.com", "a.example.com", True),
            ("*.example.com", "A.Example.COM", True),
            ("*.example.com", "a.b.example.com", False),
            ("*.example.com", "example.com", False),
            ("*.example.com", ".example.com", False),
            ("*.com", "example.com", False),
            ("f*.example.com", "foo.example.com", False),
            ("*foo.example.com", "afoo.example.com", False),
            ("a.*.example.com", "a.b.example.com", False),
            ("www.example.com", "www.example.com.", True),
            ("www.example.com", "WWW.example.com", True),
            ("example.com", "www.example.com", False),
            ("10.0.0.1", "10.0.0.1", True),
            ("10.0.0.1", "10.0.0.2", False),
            ("*.0.0.1", "10.0.0.1", False),
            ("10.0.0.1", "a.example.com", False),
            ("a.example.com", "10.0.0.1", False),
            ("2001:db8::1", "2001:0db8:0:0:0:0:0:1", True),
            ("2001:db8::1", "[2001:db8::1]", True),
            ("*.example.com", "*.example.com", True),
            ("www.example.com", "*.example.com", False),
            ("", "a", False),
        ],
    )
    def test_cases(self, pattern, host, expected):
        assert hostname_matches(pattern, host) is expected

    def test_idn(self):
        assert hostname_matches("xn--bcher-kva.example", "bücher.example")


class TestChain:
    def test_leaf_not_signed_by_listed_issuer(self, p):
        other = pki.make_root_ca(cn="CertLab Test Intermediate CA")  # same name as p.intermediate, other key
        leaf = pki.make_leaf(other, ["a.example.com"])
        b = parse_upload(leaf.cert_pem + p.chain_pem, leaf.key_pem)
        assert "CHAIN_INVALID" in by_code(run(b))

    def test_untrusted_anchor(self, p):
        other_root = pki.make_root_ca(cn="Other Root")
        f = by_code(run(parse_upload(p.fullchain_pem + p.root_pem), trust_anchors=[other_root.cert]))
        assert f["CHAIN_UNTRUSTED"].severity == Severity.WARNING
        f = by_code(run(good(p), trust_anchors=[other_root.cert]))
        assert f["CHAIN_UNTRUSTED"].severity == Severity.WARNING

    def test_incomplete_leaf_only(self, p):
        f = by_code(run(parse_upload(p.leaf.cert_pem, p.leaf.key_pem)))
        assert f["CHAIN_INCOMPLETE"].severity == Severity.WARNING
        f = by_code(run(parse_upload(p.leaf.cert_pem), trust_anchors=[p.root.cert]))
        assert f["CHAIN_INCOMPLETE"].severity == Severity.WARNING and "CHAIN_UNTRUSTED" in f

    def test_leaf_directly_under_anchor(self):
        root = pki.make_root_ca()
        leaf = pki.make_leaf(root, ["a.example.com"])
        assert run(parse_upload(leaf.cert_pem, leaf.key_pem), trust_anchors=[root.cert]) == []

    def test_self_signed_blocking_unless_allowed(self):
        ss = pki.make_self_signed()
        b = parse_upload(ss.cert_pem, ss.key_pem)
        f = by_code(run(b))
        assert f["CHAIN_UNTRUSTED"].severity == Severity.BLOCKING
        assert run(b, policy=ValidationPolicy(allow_self_signed=True)) == []
        assert run(b, trust_anchors=[ss.cert]) == []

    def test_no_anchors_complete_chain_quiet(self, p):
        assert run(good(p)) == []


class TestCurrent:
    def test_shorter_validity(self, p):
        cur_leaf = pki.make_leaf(p.intermediate, ["a.example.com"], not_after=NOW + dt.timedelta(days=300))
        cur = cert_info_from_x509(cur_leaf.cert)
        f = by_code(run(good(p), current_cert=cur))
        assert f["SHORTER_VALIDITY_THAN_CURRENT"].severity == Severity.WARNING

    def test_longer_validity_no_warning(self, p):
        cur_leaf = pki.make_leaf(p.intermediate, ["a.example.com"], not_after=NOW + dt.timedelta(days=5))
        f = by_code(run(good(p), current_cert=cert_info_from_x509(cur_leaf.cert)))
        assert "SHORTER_VALIDITY_THAN_CURRENT" not in f

    def test_key_type_change(self, p):
        cur_leaf = pki.make_leaf(p.intermediate, ["a.example.com"], key_kind="ec256")
        f = by_code(run(good(p), current_cert=cert_info_from_x509(cur_leaf.cert)))
        assert f["REPLACES_DIFFERENT_KEY_TYPE"].severity == Severity.INFO

    def test_same_cert(self, p):
        cur = cert_info_from_x509(p.leaf.cert)
        f = by_code(run(good(p), current_cert=cur))
        assert "SAME_AS_CURRENT" in f and "REPLACES_DIFFERENT_KEY_TYPE" not in f


class TestExpiryHelpers:
    def test_days_remaining(self):
        na = NOW + dt.timedelta(days=10, hours=3)
        assert days_remaining(na, NOW) == 10
        assert days_remaining(NOW - dt.timedelta(hours=1), NOW) == -1
        assert days_remaining(NOW + dt.timedelta(hours=5), NOW) == 0

    def test_timezone_handling(self):
        tz = dt.timezone(dt.timedelta(hours=9))
        na = (NOW + dt.timedelta(days=5)).astimezone(tz)
        assert days_remaining(na, NOW) == 5
        assert days_remaining(na.replace(tzinfo=None) - dt.timedelta(hours=9), NOW.replace(tzinfo=None)) == 5

    @pytest.mark.parametrize(
        ("days", "status"),
        [(-1, "expired"), (0, "critical"), (7, "critical"), (8, "high"), (14, "high"), (15, "warning"),
         (30, "warning"), (31, "info"), (60, "info"), (61, "valid"), (500, "valid")],
    )
    def test_status_defaults(self, days, status):
        assert expiry_status(days) == status

    def test_custom_thresholds(self):
        t = {"info": 10, "warning": 5, "high": 3, "critical": 1}
        assert expiry_status(2, t) == "high"
        assert expiry_status(11, t) == "valid"
        assert expiry_status(40, {"info": 90}) == "info"


class TestPathValidation:
    def test_policy_builder_runs_when_anchors_given(self, p):
        leaf = pki.make_sha1_leaf(p.intermediate, ["a.example.com"])
        b = parse_upload(leaf.cert_pem + p.chain_pem, leaf.key_pem)
        f = by_code(run(b, trust_anchors=[p.root.cert]))
        assert f["CHAIN_POLICY_VIOLATION"].severity == Severity.WARNING
        assert "CHAIN_POLICY_VIOLATION" not in by_code(run(b))  # no anchors -> not attempted

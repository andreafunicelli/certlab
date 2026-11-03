from __future__ import annotations

import hashlib
import hmac
import json
import smtplib
from datetime import timedelta

import httpx
import pytest
from sqlalchemy import select

from app.core.errors import AppError
from app.integrations.notify import ChannelError, Message, build_webhook_request, send_webhook, sign_body
from app.models import Certificate, CertificateInstallation, NotificationDelivery, Server
from app.models.base import utcnow
from app.models.certificate import make_identity_key
from app.services import monitoring
from app.services import notifications as svc
from tests.conftest import make_user

WEBHOOK = {"url": "https://hooks.example.com/cdp"}


@pytest.mark.parametrize("value", [42, True, {"Production": True}, [{"name": "Production"}], ["Production", 42]])
def test_invalid_environment_filter_is_rejected_before_saving(value):
    with pytest.raises(AppError) as exc:
        svc._check_rule("cert.expiring", {"environment": value})
    assert exc.value.code == "INVALID_FILTER"


@pytest.fixture
def enq(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr("app.workers.celery_app.enqueue", lambda name, *a, **k: calls.append(f"{name}:{a[0]}"))
    return calls


def _chan(db, actor, name="hook", secret="s3cr3t"):
    return svc.create_channel(db, actor, name=name, type="webhook", config=dict(WEBHOOK), secret=secret, enabled=True)


def _rule(db, actor, channel_id, event="cert.expiring", **kw):
    return svc.create_rule(db, actor, event_type=event, channel_id=channel_id, min_severity=kw.pop("min_severity", "info"),
                           filters=kw.pop("filters", {}), reminder_interval_hours=kw.pop("reminder_interval_hours", None),
                           enabled=True)


# ----------------------------------------------------------------------------------- webhook transport
def test_webhook_signature_is_hmac_sha256_over_timestamp_and_body():
    msg = Message("cert.expiring", "high", "subj", "text", {"a": 1}, event_id="e1", created_at="2026-01-01T00:00:00Z")
    url, body, headers = build_webhook_request(WEBHOOK, "topsecret", msg, now=1_700_000_000)
    assert url == WEBHOOK["url"] and headers["X-CDP-Timestamp"] == "1700000000"
    expect = "sha256=" + hmac.new(b"topsecret", b"1700000000." + body, hashlib.sha256).hexdigest()
    assert headers["X-CDP-Signature"] == expect == sign_body("topsecret", "1700000000", body)
    assert json.loads(body)["event_type"] == "cert.expiring" and json.loads(body)["payload"] == {"a": 1}
    _, _, h2 = build_webhook_request(WEBHOOK, None, msg)
    assert "X-CDP-Signature" not in h2


def test_webhook_requires_https_unless_explicitly_allowed_and_no_redirects():
    msg = Message("t", "info", "s", "t")
    with pytest.raises(ValueError):
        build_webhook_request({"url": "http://x.example.com/h"}, None, msg)
    build_webhook_request({"url": "http://x.example.com/h", "allow_http": True}, None, msg)
    with pytest.raises(ValueError):
        build_webhook_request({"url": "https://user:pw@x.example.com/h"}, None, msg)
    with pytest.raises(ValueError):
        build_webhook_request({"url": "ftp://x.example.com/h"}, None, msg)

    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(302, headers={"location": "https://evil.example.com/"})

    with pytest.raises(ChannelError) as ei:
        send_webhook(WEBHOOK, "k", msg, transport=httpx.MockTransport(handler))
    assert "302" in ei.value.message and len(seen) == 1 and ei.value.retryable is False
    ok = send_webhook(WEBHOOK, "k", msg, transport=httpx.MockTransport(lambda r: httpx.Response(204)))
    assert ok == 204
    with pytest.raises(ChannelError) as e5:
        send_webhook(WEBHOOK, None, msg, transport=httpx.MockTransport(lambda r: httpx.Response(503)))
    assert e5.value.retryable is True


def test_smtp_starttls_login_and_send(monkeypatch):
    log: list = []

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            log.append(("connect", host, port))

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def ehlo(self):
            log.append("ehlo")

        def starttls(self, context=None):
            log.append("starttls")

        def login(self, u, p):
            log.append(("login", u, p))

        def send_message(self, m):
            log.append(("send", m["Subject"], m["To"]))

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    from app.integrations.notify import send_smtp

    cfg = {"host": "smtp.example.com", "security": "starttls", "to": ["ops@example.com"], "from_address": "cdp@example.com",
           "username": "u"}
    send_smtp(cfg, "pw", Message("cert.expired", "critical", "Line1\nInjected: x", "body"))
    assert ("connect", "smtp.example.com", 587) in log and "starttls" in log and ("login", "u", "pw") in log
    sent = next(x for x in log if isinstance(x, tuple) and x[0] == "send")
    assert "\n" not in sent[1] and sent[2] == "ops@example.com"
    with pytest.raises(ValueError):
        from app.integrations.notify import validate_smtp_config
        validate_smtp_config({"host": "h", "to": [], "from_address": "a@b"})


# ----------------------------------------------------------------------------------- routing / dedupe
def test_notify_dedupe_reminder_severity_and_environment_filter(db, enq):
    admin = make_user(db, "n1", "admin")
    ch = _chan(db, admin)
    r_all = _rule(db, admin, ch["id"], reminder_interval_hours=24)
    r_prod = _rule(db, admin, ch["id"], filters={"environment": "Production"}, min_severity="high")

    made = svc.notify(db, "cert.expiring", "warning", {"common_name": "a", "environment": "Staging", "days_remaining": 20}, "k1")
    db.commit()
    assert len(made) == 1 and made[0].rule_id == r_all["id"] and enq == [f"notifications.deliver:{made[0].id}"]
    assert svc.notify(db, "cert.expiring", "warning", {"environment": "Staging"}, "k1") == []      # deduped
    db.commit()
    # a new bucket (different dedupe key) notifies immediately
    assert len(svc.notify(db, "cert.expiring", "high", {"environment": "Staging"}, "k2")) == 1
    # production + high matches both rules; staging only the unfiltered one
    both = svc.notify(db, "cert.expiring", "high", {"environments": ["Production"]}, "k3")
    assert {d.rule_id for d in both} == {r_all["id"], r_prod["id"]}
    assert svc.notify(db, "cert.expiring", "info", {"environment": "Production"}, "k4")[0].rule_id == r_all["id"]
    # unrelated event type -> nothing
    assert svc.notify(db, "server.unreachable", "high", {}, "k5") == []
    db.commit()
    # reminder after the interval elapsed (rule without reminder never repeats)
    for d in db.scalars(select(NotificationDelivery).where(NotificationDelivery.dedupe_key == "k1")):
        d.created_at = utcnow() - timedelta(hours=25)
    db.commit()
    again = svc.notify(db, "cert.expiring", "warning", {"environment": "Staging"}, "k1")
    assert [d.rule_id for d in again] == [r_all["id"]]
    for d in db.scalars(select(NotificationDelivery).where(NotificationDelivery.dedupe_key == "k3")):
        d.created_at = utcnow() - timedelta(hours=100)
    db.commit()
    again3 = svc.notify(db, "cert.expiring", "high", {"environments": ["Production"]}, "k3")
    assert {d.rule_id for d in again3} == {r_all["id"]}          # r_prod has no reminder interval
    with pytest.raises(ValueError):
        svc.notify(db, "bogus.event", "high", {}, "x")


def test_no_enqueue_before_commit_and_payload_is_redacted(db, enq):
    admin = make_user(db, "n2", "admin")
    ch = _chan(db, admin)
    _rule(db, admin, ch["id"], event="deployment.failed")
    made = svc.notify(db, "deployment.failed", "high", {"deployment_id": "d1", "password": "hunter2",
                                                        "note": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"}, "dep:d1")
    assert enq == []
    db.rollback()
    assert enq == [] and db.query(NotificationDelivery).count() == 0
    svc.notify(db, "deployment.failed", "high", {"deployment_id": "d1", "password": "hunter2",
                                                 "note": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"}, "dep:d1")
    db.commit()
    assert len(enq) == 1
    d = db.scalars(select(NotificationDelivery)).one()
    assert "hunter2" not in str(d.payload) and "BEGIN PRIVATE" not in str(d.payload)
    assert made  # created in the rolled back transaction


def test_delivery_attempts_retry_then_fail_and_secret_is_used(db, monkeypatch):
    admin = make_user(db, "n3", "admin")
    ch = _chan(db, admin)
    _rule(db, admin, ch["id"], event="rollback.failed")
    monkeypatch.setattr("app.workers.celery_app.enqueue", lambda *a, **k: None)
    d = svc.notify(db, "rollback.failed", "critical", {"deployment_id": "x"}, "rb:x", commit=True)[0]
    state = {"status": 503, "sigs": []}

    def fake_send(cfg, secret, msg, **_):
        state["sigs"].append(secret)
        if state["status"] >= 400:
            raise ChannelError(f"webhook returned HTTP {state['status']}", retryable=state["status"] >= 500)

    monkeypatch.setattr(svc, "send_webhook", fake_send)
    assert svc.attempt_delivery(db, d.id) == "retry"
    db.refresh(d)
    assert d.status == "pending" and d.attempts == 1 and "503" in d.last_error
    state["status"] = 200
    assert svc.attempt_delivery(db, d.id) == "sent"
    db.refresh(d)
    assert d.status == "sent" and d.sent_at and state["sigs"] == ["s3cr3t", "s3cr3t"]
    assert svc.attempt_delivery(db, d.id) == "skipped"                 # idempotent after success
    d2 = svc.notify(db, "rollback.failed", "critical", {"deployment_id": "y"}, "rb:y", commit=True)[0]
    state["status"] = 400
    assert svc.attempt_delivery(db, d2.id) == "failed"                 # non-retryable
    d3 = svc.notify(db, "rollback.failed", "critical", {"deployment_id": "z"}, "rb:z", commit=True)[0]
    state["status"] = 500
    for _ in range(svc.MAX_ATTEMPTS - 1):
        assert svc.attempt_delivery(db, d3.id) == "retry"
    assert svc.attempt_delivery(db, d3.id) == "failed"


# ----------------------------------------------------------------------------------- API
def test_notification_api_crud_never_returns_secret(login, db):
    admin = login("admin")
    r = admin.post("/api/v1/notifications/channels", json={"name": "ops-hook", "type": "webhook", "config": WEBHOOK,
                                                           "secret": "TOPSECRET"})
    assert r.status_code == 201, r.text
    assert "TOPSECRET" not in r.text and r.json()["has_secret"] is True
    assert "TOPSECRET" not in admin.get("/api/v1/notifications/channels").text
    cid = r.json()["id"]
    from app.models import NotificationChannel
    assert "TOPSECRET" not in db.get(NotificationChannel, cid).secret_encrypted
    bad = admin.post("/api/v1/notifications/channels", json={"name": "bad", "type": "webhook", "config": {"url": "http://x.example.com"}})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "INVALID_CHANNEL_CONFIG"
    assert admin.post("/api/v1/notifications/channels", json={"name": "ops-hook", "type": "webhook", "config": WEBHOOK}).status_code == 409
    smtp = admin.post("/api/v1/notifications/channels", json={
        "name": "mail", "type": "smtp", "secret": "mailpw",
        "config": {"host": "smtp.example.com", "to": ["a@example.com"], "from_address": "cdp@example.com", "username": "u"}})
    assert smtp.status_code == 201 and "mailpw" not in smtp.text and smtp.json()["config"]["port"] == 587
    rule = admin.post("/api/v1/notifications/rules", json={"event_type": "cert.expired", "channel_id": cid,
                                                           "min_severity": "high", "reminder_interval_hours": 12})
    assert rule.status_code == 201
    assert admin.post("/api/v1/notifications/rules", json={"event_type": "nope", "channel_id": cid}).status_code == 422
    assert admin.patch(f"/api/v1/notifications/rules/{rule.json()['id']}", json={"enabled": False}).json()["enabled"] is False
    assert len(admin.get("/api/v1/notifications/rules").json()) == 1
    assert admin.patch(f"/api/v1/notifications/channels/{cid}", json={"clear_secret": True}).json()["has_secret"] is False
    assert admin.get("/api/v1/notifications/deliveries").json()["total"] == 0
    assert "cert.expiring" in admin.get("/api/v1/notifications/event-types").json()["event_types"]
    assert admin.delete(f"/api/v1/notifications/channels/{cid}").status_code == 204
    assert admin.get("/api/v1/notifications/rules").json() == []              # cascade
    assert login("operator").get("/api/v1/notifications/channels").status_code == 403
    assert login("viewer").post("/api/v1/notifications/channels", json={"name": "x", "type": "webhook", "config": WEBHOOK}).status_code == 403


def test_channel_test_endpoint_records_delivery(login, db, monkeypatch):
    admin = login("admin")
    cid = admin.post("/api/v1/notifications/channels", json={"name": "t", "type": "webhook", "config": WEBHOOK,
                                                             "secret": "k"}).json()["id"]
    monkeypatch.setattr(svc, "send_webhook", lambda *a, **k: 200)
    assert admin.post(f"/api/v1/notifications/channels/{cid}/test").json() == {"ok": True, "error": None}

    def boom(*a, **k):
        raise ChannelError("webhook request failed (ConnectError)")
    monkeypatch.setattr(svc, "send_webhook", boom)
    res = admin.post(f"/api/v1/notifications/channels/{cid}/test").json()
    assert res["ok"] is False and "ConnectError" in res["error"]
    items = admin.get("/api/v1/notifications/deliveries?event_type=test").json()["items"]
    assert [i["status"] for i in items] == ["failed", "sent"] and items[0]["channel_name"] == "t"


# ----------------------------------------------------------------------------------- monitoring: expiry buckets
@pytest.mark.parametrize("days,expected", [(90, None), (60, ("cert.expiring", "info")), (31, ("cert.expiring", "info")),
                                           (30, ("cert.expiring", "warning")), (15, ("cert.expiring", "warning")),
                                           (14, ("cert.expiring", "high")), (8, ("cert.expiring", "high")),
                                           (7, ("cert.expiring", "critical")), (0, ("cert.expiring", "critical")),
                                           (-1, ("cert.expired", "critical"))])
def test_expiry_buckets_use_configured_thresholds(days, expected):
    from app.integrations.certificates import expiry_status
    th = {"info": 60, "warning": 30, "high": 14, "critical": 7}
    assert monitoring.expiry_event(expiry_status(days, th)) == expected


def _seed(db, cn, days, env="Production", now=None):
    now = now or utcnow()
    srv = db.scalar(select(Server).where(Server.name == f"srv-{env}"))
    if srv is None:
        srv = Server(name=f"srv-{env}", hostname=f"{env}.example.com", ssh_username="u", environment=env)
        db.add(srv)
        db.flush()
    fp = hashlib.sha256(f"{cn}{days}".encode()).hexdigest()
    cert = Certificate(fingerprint_sha256=fp, common_name=cn, subject=f"CN={cn}", sans=[cn], issuer="CN=CA",
                       serial_number="01", public_key_algorithm="RSA", public_key_size=2048, public_key_sha256=fp,
                       signature_algorithm="sha256WithRSAEncryption", not_before=now - timedelta(days=100),
                       not_after=now + timedelta(days=days, hours=1), pem="x")
    db.add(cert)
    db.flush()
    db.add(CertificateInstallation(certificate_id=cert.id, server_id=srv.id, service_type="nginx", cert_path=f"/{cn}.pem",
                                   identity_key=make_identity_key(srv.id, "nginx", f"/{cn}.pem", None)))
    db.commit()
    return cert


def test_check_expiry_emits_once_per_bucket_and_updates_status(db, enq):
    admin = make_user(db, "m1", "admin")
    ch = _chan(db, admin)
    _rule(db, admin, ch["id"], event="cert.expiring", reminder_interval_hours=None)
    _rule(db, admin, ch["id"], event="cert.expired")
    c_ok, c_warn, c_crit, c_dead = (_seed(db, "ok.example.com", 200), _seed(db, "warn.example.com", 20),
                                    _seed(db, "crit.example.com", 3), _seed(db, "dead.example.com", -2))
    res = monitoring.check_expiry(db)
    assert res["checked"] == 4 and res["events"] == 3 and res["expired"] == 1 and res["expiring"] == 2
    keys = {d.dedupe_key: d for d in db.scalars(select(NotificationDelivery))}
    assert set(keys) == {f"cert.expiring:{c_warn.id}:warning", f"cert.expiring:{c_crit.id}:critical",
                         f"cert.expired:{c_dead.id}"}
    sev = {k: v.payload["severity"] for k, v in keys.items()}
    assert sev[f"cert.expiring:{c_crit.id}:critical"] == "critical" and sev[f"cert.expiring:{c_warn.id}:warning"] == "warning"
    db.refresh(c_warn), db.refresh(c_ok), db.refresh(c_dead), db.refresh(c_crit)
    assert (c_ok.status, c_warn.status, c_crit.status, c_dead.status) == ("valid", "expiring", "critical", "expired")
    assert len(enq) == 3
    # running again the same day: deduped (no reminder interval configured)
    assert monitoring.check_expiry(db)["events"] == 0
    # certificate moves to the next bucket -> new notification
    c_warn.not_after = utcnow() + timedelta(days=10)
    db.commit()
    assert monitoring.check_expiry(db)["events"] == 1
    assert db.scalar(select(NotificationDelivery).where(
        NotificationDelivery.dedupe_key == f"cert.expiring:{c_warn.id}:high")) is not None
    # payload carries environment for rule filters + no secrets
    p = keys[f"cert.expired:{c_dead.id}"].payload["data"]
    assert p["environments"] == ["Production"] and p["days_remaining"] in (-3, -2)

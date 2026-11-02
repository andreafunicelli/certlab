from __future__ import annotations

from sqlalchemy import select

from app.models import AuditEvent
from tests.conftest import PASSWORD, make_user


def test_login_logout_and_session_cookie_flags(anon, db):
    make_user(db, "alice", "admin")
    r = anon.post("/api/v1/auth/login", json={"username": "alice", "password": PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body["roles"] == ["admin"] and "servers:write" in body["permissions"] and body["csrf_token"]
    sc = r.headers.get_list("set-cookie")
    sess = next(c for c in sc if c.startswith("cdp_session="))
    assert "httponly" in sess.lower() and "samesite=lax" in sess.lower()
    assert not next(c for c in sc if c.startswith("cdp_csrf=")).lower().count("httponly")
    assert anon.get("/api/v1/auth/me").status_code == 200
    out = anon.post("/api/v1/auth/logout", headers={"X-CSRF-Token": body["csrf_token"]})
    assert out.status_code == 204
    assert anon.get("/api/v1/auth/me").status_code == 401


def test_login_failure_is_generic_and_audited(anon, db):
    make_user(db, "bob", "viewer")
    bad = anon.post("/api/v1/auth/login", json={"username": "bob", "password": "nope-nope-nope"})
    ghost = anon.post("/api/v1/auth/login", json={"username": "ghost", "password": "nope-nope-nope"})
    assert bad.status_code == ghost.status_code == 401
    assert bad.json()["error"]["message"] == ghost.json()["error"]["message"]
    ev = db.scalars(select(AuditEvent).where(AuditEvent.action == "LOGIN_FAILED")).all()
    assert len(ev) == 2 and all(e.outcome == "failure" for e in ev)


def test_account_lockout_after_repeated_failures(anon, db):
    make_user(db, "carol", "viewer")
    for _ in range(5):
        anon.post("/api/v1/auth/login", json={"username": "carol", "password": "wrong-wrong-wrong"})
    r = anon.post("/api/v1/auth/login", json={"username": "carol", "password": PASSWORD})
    assert r.status_code == 401


def test_unauthenticated_and_error_shape(anon):
    r = anon.get("/api/v1/servers", headers={"X-Correlation-ID": "test-correlation-1"})
    assert r.status_code == 401
    err = r.json()["error"]
    assert err["code"] == "UNAUTHENTICATED" and err["correlation_id"] == "test-correlation-1"
    assert r.headers["x-correlation-id"] == "test-correlation-1"
    assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_csrf_enforced_for_cookie_authenticated_writes(admin):
    body = {"name": "Test2", "description": "x"}
    r = admin.without_csrf().post("/api/v1/environments", json=body)
    assert r.status_code == 403 and r.json()["error"]["code"] == "CSRF_FAILED"
    r = admin.post("/api/v1/environments", json=body, headers={"X-CSRF-Token": "forged"})
    assert r.status_code == 403
    assert admin.post("/api/v1/environments", json=body).status_code == 201
    assert admin.get("/api/v1/environments").status_code == 200  # GET needs no csrf


def test_rbac_viewer_is_read_only(login):
    viewer = login("viewer")
    assert viewer.get("/api/v1/servers").status_code == 200
    assert viewer.get("/api/v1/dashboard/summary").status_code == 200
    assert viewer.post("/api/v1/environments", json={"name": "X1"}).status_code == 403
    assert viewer.post("/api/v1/servers", json={}).status_code in (403, 422)
    assert viewer.get("/api/v1/users").status_code == 403
    assert viewer.get("/api/v1/credentials").status_code == 403


def test_rbac_operator_cannot_manage_users_credentials_settings(login, db):
    op = login("operator")
    assert op.get("/api/v1/servers").status_code == 200
    assert op.get("/api/v1/users").status_code == 403
    assert op.post("/api/v1/users", json={"username": "zed", "email": "z@e.com", "display_name": "Z",
                                          "password": "x" * 14, "roles": ["viewer"]}).status_code == 403
    assert op.get("/api/v1/credentials").status_code == 403
    assert op.post("/api/v1/credentials", json={"name": "k", "private_key": "x" * 40}).status_code == 403
    assert op.patch("/api/v1/settings/general", json={"version": 1, "data": {}}).status_code == 403
    assert op.post("/api/v1/servers", json={}).status_code == 403
    denied = db.scalars(select(AuditEvent).where(AuditEvent.outcome == "denied")).all()
    assert len(denied) >= 4


def test_admin_user_management_and_role_change_audited(admin, db):
    r = admin.post("/api/v1/users", json={"username": "dave", "email": "dave@example.com", "display_name": "Dave",
                                          "password": "a-long-enough-password", "roles": ["viewer"]})
    assert r.status_code == 201 and "password" not in r.text
    uid = r.json()["id"]
    r = admin.patch(f"/api/v1/users/{uid}/roles", json={"roles": ["operator"]})
    assert r.status_code == 200 and r.json()["roles"] == ["operator"]
    ev = db.scalars(select(AuditEvent).where(AuditEvent.action == "USER_ROLES_CHANGED")).one()
    assert ev.before == {"roles": ["viewer"]} and ev.after == {"roles": ["operator"]}
    assert admin.patch(f"/api/v1/users/{uid}/roles", json={"roles": ["nope"]}).status_code == 422


def test_last_admin_protected(admin):
    me = admin.get("/api/v1/auth/me").json()["user"]["id"]
    r = admin.patch(f"/api/v1/users/{me}/roles", json={"roles": ["viewer"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "LAST_ADMIN"


def test_reauth_updates_session(admin, db):
    assert admin.post("/api/v1/auth/reauth", json={"password": "wrong"}).status_code == 401
    assert admin.post("/api/v1/auth/reauth", json={"password": PASSWORD}).status_code == 204


def test_totp_mfa_flow(anon, db):
    import pyotp

    make_user(db, "erin", "admin")
    r = anon.post("/api/v1/auth/login", json={"username": "erin", "password": PASSWORD})
    csrf = r.json()["csrf_token"]
    secret = anon.post("/api/v1/auth/mfa/setup", headers={"X-CSRF-Token": csrf}).json()["secret"]
    assert anon.post("/api/v1/auth/mfa/enable", json={"code": pyotp.TOTP(secret).now()},
                     headers={"X-CSRF-Token": csrf}).status_code == 204
    anon.cookies.clear()
    r = anon.post("/api/v1/auth/login", json={"username": "erin", "password": PASSWORD})
    assert r.status_code == 401 and r.json()["error"]["code"] == "MFA_REQUIRED"
    r = anon.post("/api/v1/auth/login", json={"username": "erin", "password": PASSWORD,
                                              "totp": pyotp.TOTP(secret).now()})
    assert r.status_code == 200


def test_health_endpoints_and_openapi(anon):
    assert anon.get("/api/v1/healthz").json() == {"status": "ok"}
    r = anon.get("/api/v1/readyz")
    assert r.status_code in (200, 503) and r.json()["checks"]["database"] == "ok"
    assert anon.get("/api/v1/openapi.json").status_code == 200
    assert anon.get("/api/docs").status_code == 200


def test_internal_errors_do_not_leak(app):
    from fastapi.testclient import TestClient

    @app.get("/api/v1/_boom_test")
    def boom():
        raise RuntimeError("secret internals /etc/passwd")

    with TestClient(app, raise_server_exceptions=False) as c:
        r = c.get("/api/v1/_boom_test")
    assert r.status_code == 500 and "passwd" not in r.text
    assert r.json()["error"]["code"] == "INTERNAL_ERROR" and r.headers["x-correlation-id"]

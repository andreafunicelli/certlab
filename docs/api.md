# API

How the Cert Deploy Pro (CDP) REST API authenticates callers, what its errors look like, and which endpoint needs which
permission.

Basis: source at commit `a353f1e`. The endpoint list was generated from the route decorators in
`backend/app/api/v1/*.py`, the router prefixes, and the `require_permission(...)` calls. Permission names come from
`backend/app/core/permissions.py`. Read for behaviour: `api/deps.py`, `core/errors.py`, `core/middleware.py`,
`core/ratelimit.py`, `schemas/common.py`, `main.py`, `services/auth.py`, `services/deployments.py`,
`services/events.py`, `infra/caddy/Caddyfile`. **No request was sent to a running API for this page.** Behaviour that
rests on reading alone is marked **(unverified)**.

Related: [security.md](security.md) (sessions, CSRF, RBAC and re-authentication, in depth),
[configuration.md](configuration.md) (`CDP_*` settings), [troubleshooting.md](troubleshooting.md) (error codes by area).

**Interactive documentation** is served by the API itself. The Swagger UI is at `/api/docs` and the OpenAPI document at
`/api/v1/openapi.json` (both set in `main.py`). The schemas for each request and response are there. This page covers
what the schemas do not: authentication, permissions, behaviour and error codes.

---

## 1. Routing and limits

- All endpoints are under `/api/v1`. Caddy sends `/api/*` to the `api` service (port 8000) and everything else to the
  frontend. Request bodies under `/api/*` are capped at 2 MB at the proxy (`infra/caddy/Caddyfile`).
- Per-part upload limit: 256 KiB for each certificate, key, chain or PKCS#12 part (`uploads.MAX_UPLOAD_BYTES`). Larger
  parts return 413 `PAYLOAD_TOO_LARGE`.
- Rate limit: 600 requests per minute per client IP on every `/api/*` path except `/api/v1/healthz`
  (`CDP_RATE_LIMIT_API_PER_MINUTE`). The limit answers 429 `RATE_LIMITED` with `Retry-After` and
  `details.retry_after`. Login has its own stricter limits (section 2.2).
- Client IP is the socket address. With `CDP_TRUST_PROXY_HEADERS=true` the first `X-Forwarded-For` value is used. Enable it
  only behind the bundled proxy.

---

## 2. Authentication

### 2.1 Sign-in

`POST /api/v1/auth/login` with a JSON body `{username, password, totp?}`.

- On success it sets two cookies and returns the current user, including `csrf_token`:
  - `cdp_session`: the session token. `HttpOnly`, `Secure` (unless `CDP_COOKIE_SECURE=false`), `SameSite=Lax`, `Path=/`.
  - `cdp_csrf`: the CSRF token. Readable by script, `Secure`, `SameSite=Lax`.
- Sessions expire after the shorter of `security.session_minutes` (default 480) and `CDP_SESSION_TTL` (default 8 h). The
  expiry is absolute and is not extended by activity (see [security.md](security.md) section 1.2).
- `GET /api/v1/auth/me` returns the same shape for the current session. It also refreshes the cookies.
- `POST /api/v1/auth/logout` revokes the session and clears both cookies.

Sign-in with OIDC: `GET /api/v1/auth/oidc/login` redirects to the identity provider and sets a short-lived signed state
cookie (`cdp_oidc`, `Path=/api/v1/auth/oidc`). `GET /api/v1/auth/oidc/callback` completes sign-in. Both return an error
when OIDC is not configured.

### 2.2 Login limits and errors

| Limit | Value | Source |
|---|---|---|
| Login attempts per client IP | 10 per minute | `rate_limit_login_per_minute` |
| Login attempts per username | 5 per minute | `security.md` section 1.1 |
| Failed passwords before lock | 5, then 15-minute lock | `services/auth.py` |

Unknown user, wrong password, disabled account and locked account all return the same 401 `INVALID_CREDENTIALS`, so the
response does not reveal which applies. A wrong TOTP code counts as a failed attempt.

---

## 3. CSRF

Every authenticated request that is not `GET` (`POST`, `PUT`, `PATCH`, `DELETE`) must send header `X-CSRF-Token`. The value
must equal the `cdp_csrf` cookie and must equal the token derived from the session (`security.md` section 1.4). The check
is done by `api/deps.py` (`get_auth_context`).

- Missing or invalid: 403 `CSRF_FAILED`.
- Not checked: `POST /api/v1/auth/login` and the OIDC routes, which do not depend on `get_auth_context`.
- Browser clients read `cdp_csrf` from the document. Scripts can read it from the cookie jar.

CORS: `Content-Type`, `X-CSRF-Token`, `X-Correlation-ID` and `Idempotency-Key` are allowed request headers, and
`X-Correlation-ID` is exposed. Allowed origins come from `CDP_CORS_ORIGINS`, which is empty by default. Cross-origin use
therefore needs explicit configuration.

---

## 4. Errors

Every error body has the same shape:

```json
{"error": {"code": "SERVER_NOT_FOUND", "message": "Server not found", "correlation_id": "3f9c...", "details": {}}}
```

- `code` is a stable machine code. Domain errors use specific codes (for example `PREFLIGHT_BLOCKED`, `REAUTH_REQUIRED`).
  Framework errors use these: `400 BAD_REQUEST`, `401 UNAUTHENTICATED`, `403 FORBIDDEN`, `404 NOT_FOUND`,
  `405 METHOD_NOT_ALLOWED`, `409 CONFLICT`, `413 PAYLOAD_TOO_LARGE`, `415 UNSUPPORTED_MEDIA_TYPE`, `429 RATE_LIMITED`,
  `500 INTERNAL_ERROR`. Any other HTTP status is `HTTP_ERROR`.
- `details` is passed through redaction (`core/logging.redact`), so keys that look like secrets and PEM blocks are removed.
- Validation errors (422) use `VALIDATION_ERROR`. `details.errors` lists `loc`, `msg` and `type` for each field. The submitted
  values are never echoed.
- Unexpected exceptions return 500 `INTERNAL_ERROR` with a generic message. The traceback goes to the logs.
- A 403 for a missing permission has `details.required_permission`.

Domain error codes by area are in [troubleshooting.md](troubleshooting.md).

---

## 5. Correlation IDs

- Send `X-Correlation-ID` to label a request. It is accepted when it is 8 to 64 characters from `A-Z a-z 0-9 . _ -`.
  Otherwise the server generates a 32-character hex ID.
- Every response has the header `X-Correlation-ID`. Error bodies carry the same value in `error.correlation_id`.
- The ID is written to the structured logs (`correlation_id` field) and to each audit event written during the request
  (`audit_events.correlation_id`).
- **The audit API cannot filter by correlation ID.** Its filters are `actor`, `action`, `resource_type`, `resource_id`,
  `outcome`, `from` and `to`. To find events for one request, search the logs, or query `audit_events` directly
  (see [troubleshooting.md](troubleshooting.md)).

---

## 6. Pagination

List endpoints marked *paged* in section 9 take:

- `page`: integer, 1 to 100000, default 1.
- `page_size`: integer, 1 to 200, default 25.

They return `{"items": [...], "total": <int>, "page": <int>, "page_size": <int>}`. Endpoints not marked paged return a
plain array.

---

## 7. Idempotency

`POST /api/v1/deployments` requires an `Idempotency-Key` header of 1 to 80 characters. Without it the request fails with
400 `IDEMPOTENCY_KEY_REQUIRED`.

- Keys are scoped to the calling user.
- The request body is hashed. The same key with the same body returns the original job with HTTP 201 and
  `"idempotent_replay": true`. The same key with a different body returns 409 `IDEMPOTENCY_KEY_CONFLICT`.
- A replay does not run preflight again and does not dispatch the job again.

No other endpoint honours `Idempotency-Key`. `POST /deployments/{id}/retry` generates its own key.

---

## 8. Re-authentication

Some actions need the session to have re-authenticated recently. Call `POST /api/v1/auth/reauth` with `password` and, if
enrolled, `totp`. The window is `security.reauth_minutes` (default 10). Outside it, the request fails with 403
`REAUTH_REQUIRED`, and `details.reauth_minutes` gives the window.

Endpoints that need re-authentication (marked *reauth* in section 9):

- `POST /credentials`, `POST /credentials/{id}/rotate`
- `POST /deployments/{id}/approve`
- `POST /deployments/{id}/targets/{target_id}/rollback`
- `POST /backups/{id}/restore`, `GET /backups/{id}/download`

---

## 9. Endpoints

Permissions per role are in [security.md](security.md) section 2. In short: **viewer** holds the `:read` permissions; **operator**
adds verify, discover, plan, create, cancel, retry, upload and installation edits; **admin** holds all. Every
state-changing request on this list (POST, PUT, PATCH, DELETE) also needs the CSRF header (section 3).

"Auth" means any signed-in user. "Public" means no sign-in.

### 9.1 Authentication (`/api/v1/auth`)

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/auth/login` | public | Rate-limited. Sets session and CSRF cookies. No CSRF check. |
| POST | `/auth/logout` | auth | Revokes the session. 204. |
| GET | `/auth/me` | auth | Current user, roles, permissions and `csrf_token`. |
| POST | `/auth/reauth` | auth | Password, plus TOTP if enrolled. 204. |
| POST | `/auth/password` | auth | Changes the caller's password. Revokes the caller's other sessions. 204. |
| POST | `/auth/mfa/setup` | auth | Starts TOTP enrolment. |
| POST | `/auth/mfa/enable` | auth | Confirms a TOTP code. 204. |
| POST | `/auth/mfa/disable` | auth | Turns TOTP off. 204. |
| GET | `/auth/oidc/login` | public | Redirects to the identity provider. Only when OIDC is configured. |
| GET | `/auth/oidc/callback` | public | Completes OIDC sign-in. |

### 9.2 Users (`/api/v1/users`)

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/users` | `users:read` | Paged. `q` is a search string (max 100 characters). |
| POST | `/users` | `users:write` | Creates a local account. Password 12 to 256 characters. |
| GET | `/users/{user_id}` | `users:read` | |
| PATCH | `/users/{user_id}` | `users:write` | Profile, enable or disable, password. Disabling and password changes revoke the user's sessions. Disabling the last admin is refused. |
| PATCH | `/users/{user_id}/roles` | `users:roles` | Replaces roles. A role change made by another admin revokes the user's sessions. |
| DELETE | `/users/{user_id}` | `users:write` | |

### 9.3 Credentials (`/api/v1/credentials`)

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/credentials` | `credentials:read` | Not paged. Key material is never returned. |
| POST | `/credentials` | `credentials:write` | reauth. Stores an SSH private key, with optional passphrase. |
| POST | `/credentials/{credential_id}/rotate` | `credentials:write` | reauth. Replaces the stored key material. |
| DELETE | `/credentials/{credential_id}` | `credentials:write` | |

### 9.4 Servers and environments

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/servers` | `servers:read` | Paged. Filters `q`, `environment`, `status`. |
| POST | `/servers` | `servers:write` | |
| GET | `/servers/{server_id}` | `servers:read` | |
| PATCH | `/servers/{server_id}` | `servers:write` | |
| POST | `/servers/{server_id}/disable` | `servers:write` | |
| POST | `/servers/{server_id}/enable` | `servers:write` | |
| DELETE | `/servers/{server_id}` | `servers:write` | |
| POST | `/servers/{server_id}/host-key/scan` | `servers:hostkey` | Fetches the host key. Does not enrol it. |
| POST | `/servers/{server_id}/host-key/enroll` | `servers:hostkey` | The posted key and fingerprint must match a fresh scan (409 `HOST_KEY_CHANGED_DURING_ENROLL` otherwise). Replacing an enrolled key needs `replace=true` (409 `HOST_KEY_ALREADY_ENROLLED` otherwise). |
| POST | `/servers/{server_id}/test-connection` | `servers:test` | Runs the connection steps: DNS, TCP, host key, authentication, helper, OS and services. |
| POST | `/servers/{server_id}/discover` | `discovery:run` | 202, returns the job. |
| GET | `/environments` | `environments:read` | Not paged. |
| POST | `/environments` | `environments:write` | |
| PATCH | `/environments/{env_id}` | `environments:write` | `is_production` and `requires_approval` drive approval rules. |
| DELETE | `/environments/{env_id}` | `environments:write` | |

### 9.5 Certificates and installations

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/certificates` | `certificates:read` | Paged. Filters `q`, `status` (`valid`, `info`, `warning`, `high`, `critical`, `expired`, `expiring`), `expiring_within`, `server_id`, `environment`, `include_ca`, `sort`. |
| GET | `/certificates/{certificate_id}` | `certificates:read` | Detail: PEM, chain, installations, deployments, backups, drift counts. |
| POST | `/certificates/{certificate_id}/verify` | `certificates:verify` | Probes up to 50 installations. |
| GET | `/installations` | `installations:read` | Paged. Filters: `server_id`, `certificate_id`, `classification`, `drift_status`, `service_type`, `environment`, `q`, `include_missing`. |
| GET | `/servers/{server_id}/installations` | `installations:read` | Paged. |
| GET | `/installations/{installation_id}` | `installations:read` | |
| PATCH | `/installations/{installation_id}` | `installations:write` | Edits `owner`, `tags`, verify host, port and SNI, and `classification` (`managed`, `requires_mapping`, `unmanaged`). See [certificate-discovery.md](certificate-discovery.md) section 6.3. |
| POST | `/installations/{installation_id}/verify` | `installations:verify` | Probes the installation's endpoint and stores `last_verification`. |

### 9.6 Discovery

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/discovery-jobs/bulk` | `discovery:run` | 202. `server_ids`, up to 200. Per-server refusals in `errors`. |
| GET | `/discovery-jobs` | `discovery:read` | Paged. Filters `server_id`, `status`. |
| GET | `/discovery-jobs/{job_id}` | `discovery:read` | Includes `findings`. |
| GET | `/discovery-jobs/{job_id}/events` | `discovery:read` | Server-sent events (section 10). |
| GET | `/servers/{server_id}/discovery-jobs` | `discovery:read` | Paged. |

### 9.7 Certificate versions (uploads)

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/certificate-versions` | `versions:upload` | Multipart form: `certificate`, `private_key`, `chain`, `pkcs12`, `password`, `certificate_id`. 201. Returns findings and `validation_status`. |
| GET | `/certificate-versions/{version_id}` | `versions:read` | Never returns key material. |
| POST | `/certificate-versions/{version_id}/validate` | `versions:upload` | Re-validates against `installation_ids`, or against the certificate's installations. |

### 9.8 Deployments

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/deployments/plan` | `deployments:plan` | Read-only plan with all findings. |
| POST | `/deployments` | `deployments:create` | Requires `Idempotency-Key` (section 7). 201. Blocking findings give 409 `PREFLIGHT_BLOCKED`. |
| GET | `/deployments` | `deployments:read` | Paged. Filters `status` (comma-separated), `version_id`, `server_id`, `initiated_by`, `since`, `until`, `q` (ID prefix). |
| GET | `/servers/{server_id}/deployments` | `deployments:read` | Paged. |
| GET | `/deployments/{deployment_id}` | `deployments:read` | Job with targets, steps, logs and the stored plan. |
| GET | `/deployments/{deployment_id}/events` | `deployments:read` | Server-sent events (section 10). |
| POST | `/deployments/{deployment_id}/approve` | `deployments:approve` | reauth. Dispatches the job. |
| POST | `/deployments/{deployment_id}/cancel` | `deployments:cancel` | Cancels at once if awaiting approval. Otherwise requests cancellation (deployment-engine section 14). |
| POST | `/deployments/{deployment_id}/retry` | `deployments:retry` | 201. A new job for the failed and rolled-back targets. |
| POST | `/deployments/{deployment_id}/targets/{target_id}/rollback` | `deployments:rollback` | reauth. Restores the target's verified backup. See [rollback.md](rollback.md). |

### 9.9 Backups

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/backups` | `backups:read` | Paged. Filters `server_id`, `installation_id`, `deployment_id`. |
| GET | `/backups/{backup_id}` | `backups:read` | Metadata and file list. No artifact IDs. |
| POST | `/backups/{backup_id}/restore` | `backups:restore` | reauth. Synchronous. See [rollback.md](rollback.md) section 7. |
| GET | `/backups/{backup_id}/download` | `backups:download` | reauth. Returns a tar.gz with decrypted files, private keys included. See [backup-restore.md](backup-restore.md) section 1.6. |

### 9.10 Notifications (`/api/v1/notifications`)

Reads need `notifications:read`. Writes need `notifications:write`.

| Method | Path | Notes |
|---|---|---|
| GET | `/notifications/event-types` | Event types and severities. |
| GET | `/notifications/channels` | Not paged. Secrets are never returned (`has_secret`). |
| POST | `/notifications/channels` | SMTP or webhook. The secret is stored encrypted. |
| GET | `/notifications/channels/{channel_id}` | |
| PATCH | `/notifications/channels/{channel_id}` | |
| DELETE | `/notifications/channels/{channel_id}` | |
| POST | `/notifications/channels/{channel_id}/test` | Sends a test message through the channel and returns the outcome. |
| GET | `/notifications/rules` | Not paged. |
| POST | `/notifications/rules` | Fields: `event_type`, `channel_id`, `min_severity`, `filters` (for example `environment`), `reminder_interval_hours`, `enabled`. |
| PATCH | `/notifications/rules/{rule_id}` | |
| DELETE | `/notifications/rules/{rule_id}` | |
| GET | `/notifications/deliveries` | Paged. Filters `status`, `event_type`, `channel_id`. |

### 9.11 Settings, audit, dashboard and health

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/settings` | `settings:read` | All sections (`general`, `notifications`, `security`, `ssh`). |
| PATCH | `/settings/{section}` | `settings:write` | Body `{version, data}`. Returns 409 `SETTINGS_VERSION_CONFLICT` if `version` is not the current version (optimistic concurrency). |
| GET | `/audit-events` | `audit:read` | Paged. Filters `actor`, `action`, `resource_type`, `resource_id`, `outcome` (`success`, `failure`, `denied`), `from`, `to`. |
| GET | `/dashboard/summary` | `dashboard:read` | Counts of unique certificates, and of installations not marked missing. One certificate on five servers is one certificate and five installations. |
| GET | `/dashboard/expiry-trend` | `dashboard:read` | Expiry histogram buckets, and expiries per month for the next 12 months. |
| GET | `/healthz` | public | Liveness. Not rate-limited. |
| GET | `/readyz` | public | Checks PostgreSQL and Redis. Returns 503 when either is down. |

---

## 10. Server-sent events

`GET /discovery-jobs/{job_id}/events` and `GET /deployments/{deployment_id}/events` stream `text/event-stream`:

- `event: snapshot` is sent first, built from the database. A client that reconnects gets a fresh snapshot.
- `event: progress` carries each job event published on Redis pub/sub (for example a target's step change).
- `event: end` is sent when the job reaches a terminal state, and then the stream closes.

Each `data:` line is JSON with `kind`, `job_id`, `type`, `ts` and the event's own fields. Events are advisory. If Redis is
down, the client sees snapshots only. The database is the source of truth.

The deployment event response carries `Cache-Control: no-cache` and `X-Accel-Buffering: no`, so the proxy does not buffer
the stream.

---

## 11. Known gaps

- There is no endpoint to revoke every session at once. Sessions are revoked one at a time, by logout, password change,
  disabling a user, or a role change by another admin (security.md section 1.2).
- `GET /backups/{id}/download` returns decrypted private keys (section 9.9). The archive is not encrypted. Its protection
  is TLS in transit, re-authentication, and the `no-store` header.

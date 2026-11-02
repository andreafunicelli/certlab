# Cert Deploy Pro — Architecture Assessment, Plan & Progress

## 1. Assessment of the imported prototype (frontend/)

* TanStack Start 1.168 (SSR, file routes) + React 19 + TanStack Query 5 + Tailwind 4 + Radix/shadcn primitives,
  IBM Plex Sans/Mono, semantic tokens in `src/styles.css`, dark/light via `components/theme.tsx`.
* `src/components/layout/AppShell.tsx` — sidebar + header (uses `currentUser` from mock-data).
* `src/components/ui/status.tsx`, `dtable.tsx` — status badges / dense table primitives — reuse everywhere.
* **All data comes from `src/lib/mock-data.ts`** (servers, certificates w/ embedded installations, deployments with
  step arrays, audit, discovered certs, stats). Every route imports it directly; no API layer, no auth.
* Renewal wizard `certificates.$id.renew.tsx` (5 steps: Upload → Validation → Target Servers → Plan → Deployment)
  simulates validation and deployment with timers. `servers.new.tsx` simulates connection tests.
* `QueryClientProvider` is already wired in `__root.tsx`, router context has `queryClient`.

Required change: add a typed API client + query hooks, replace each mock import with real queries/mutations,
add auth (login route + session), RBAC-aware UI, live job progress (SSE). Visual design is kept as-is.

## 2. Target architecture

```
frontend/                TanStack Start app (existing design), talks to /api/v1 (same origin via reverse proxy)
backend/app/
  core/                  config (pydantic-settings, env CDP_*), db (SQLAlchemy 2, sync, psycopg3), logging
                         (structlog + redaction), errors (AppError -> {"error":{code,message,correlation_id,details}}),
                         security (argon2 passwords, opaque session tokens, CSRF double-submit), crypto (envelope enc.)
  models/                SQLAlchemy models (one module per aggregate)
  schemas/               Pydantic v2 request/response models
  repositories/          DB access only (no business rules)
  services/              domain logic (servers, credentials, discovery, uploads/validation, deployment engine,
                         backups, monitoring, notifications, audit, settings, auth)
  api/v1/                thin FastAPI routers -> services (DI via Depends)
  integrations/
    contracts.py         shared dataclasses/protocols (DO NOT duplicate)
    certificates/        pure crypto: parse, classify, validate, chain, key-match, pkcs12  (no I/O)
    services/parsers/    pure text parsers: nginx -T, apache dump, haproxy cfg -> ConfigCertRef
    services/adapters/   per-service adapters: discovery, staging plan, configtest, reload, verify endpoints, restore
    ssh/                 asyncssh RemoteHost impl, strict host keys, connection test, error classification,
                         per-host concurrency limit, retries for idempotent reads only
    tls/                 live endpoint TLS probe (SNI aware)
  workers/               Celery app + tasks (discovery, deployment, monitoring, notifications); beat schedule
backend/alembic/         migrations
backend/tests/{unit,integration}
infra/remote-helper/     cdp-helper (POSIX sh, fixed subcommands) + sudoers example + install script
infra/test-target/       scripts that provision a disposable local SSH + nginx + apache + haproxy test target
docker-compose.yml       frontend, api, worker, beat, postgres, redis, proxy (Caddy) — only proxy published
```

Key decisions
* **Sync SQLAlchemy** (psycopg3) shared by API and Celery; SSH is asyncio (asyncssh) run inside worker tasks via
  `asyncio.run`. Short ops (connection test, host-key fetch, endpoint verify) run inline with hard timeouts;
  discovery & deployments are always Celery jobs persisted in Postgres.
* **Privilege model**: remote service account (e.g. `cdpdeploy`) + `/usr/local/libexec/cdp-helper` allowed via a
  single sudoers line. Helper has fixed subcommands, validates every path against `ALLOWED_ROOTS` from
  `/etc/cdp-helper.conf`, refuses to print private keys except in `backup`. Backend sends argv only (each arg
  `shlex.quote`d by asyncssh-call builder; no user string is ever interpolated into a shell command).
* **Host keys**: `Server.host_key_*` stores the enrolled OpenSSH public key; unknown/changed key -> hard failure
  (HOST_KEY_UNKNOWN / HOST_KEY_MISMATCH) + audit + notification. Enrollment endpoint shows the SHA256 fingerprint
  for explicit admin confirmation.
* **Envelope encryption**: master KEK from `CDP_MASTER_KEY` (base64 32 bytes) or `CDP_MASTER_KEY_FILE`; each
  artifact gets a random 256-bit DEK, AES-256-GCM; DEK wrapped with KEK (AES-GCM, key id recorded). Ciphertext files
  under `CDP_ARTIFACT_DIR`; DB stores reference + wrapped DEK + sha256. KEK never in Postgres.
* **Auth**: local accounts (argon2id), opaque session token in `cdp_session` HttpOnly/SameSite=Lax/Secure cookie,
  hashed in DB; CSRF via `cdp_csrf` cookie + `X-CSRF-Token` header on unsafe methods; optional TOTP; OIDC (Authlib,
  authorization code + PKCE) mapping groups->roles. Roles: admin, operator, viewer. Recent re-auth required for
  sensitive ops (credential create, backup download/restore, approve production deployment).
* **Deployment engine**: per-target state machine persisted after every step; durable locks
  (`deployment_locks` table, unique on server_id+path, expiry + owner heartbeat); canary → batches with concurrency
  and failure threshold; rollback restores from centrally stored encrypted backup and must be *verified*
  (fingerprints on disk + live TLS) or the target goes to `manual_intervention_required`.

## 3. API contract (all under /api/v1, JSON, cookie session; list endpoints return {items,total,page,page_size})

auth: POST /auth/login {username,password,totp?} · POST /auth/logout · GET /auth/me · POST /auth/reauth {password}
      · GET /auth/oidc/login · GET /auth/oidc/callback
users: CRUD /users (admin) · PATCH /users/{id}/roles
credentials: GET/POST /credentials (admin; POST is multipart/JSON with private_key PEM + optional passphrase;
      responses never contain secrets: {id,name,type,fingerprint,public_key,created_at,rotated_at,server_count})
      · POST /credentials/{id}/rotate · DELETE /credentials/{id}
servers: GET/POST /servers · GET/PATCH/DELETE /servers/{id} · POST /servers/{id}/host-key/scan -> {key_type,
      fingerprint_sha256, public_key} · POST /servers/{id}/host-key/enroll {public_key, fingerprint_sha256}
      · POST /servers/{id}/test-connection -> {ok, steps:[{name,status,detail,duration_ms}], probe, error_code}
      · POST /servers/{id}/discover -> DiscoveryJob · GET /servers/{id}/installations · /deployments · /discovery-jobs
discovery-jobs: GET /discovery-jobs · GET /discovery-jobs/{id} (with findings) · POST /discovery-jobs/bulk {server_ids}
certificates: GET /certificates (q, status, expiring_within, server_id, sort, page) · GET /certificates/{id}
      (installations, versions, deployments, backups) · POST /certificates/{id}/verify
installations: GET /installations · GET/PATCH /installations/{id} (admin mapping: verify endpoint host/port/sni,
      managed flag) · POST /installations/{id}/verify
certificate-versions: POST /certificate-versions (multipart: certificate, private_key?, chain?, pkcs12?, password?,
      certificate_id?) -> {id, leaf, chain, findings:[{code,severity,message}], validation_status}
      · GET /certificate-versions/{id} · POST /certificate-versions/{id}/validate {installation_ids}
deployments: POST /deployments/plan {version_id, installation_ids, strategy} -> dry-run plan (read-only)
      · POST /deployments (Idempotency-Key header) {version_id, installation_ids, strategy:{mode:"canary"|"batch"|
      "all", concurrency, failure_threshold, continue_on_failure, allow_restart}, acknowledged_warnings:[codes]}
      · GET /deployments · GET /deployments/{id} (targets with steps) · GET /deployments/{id}/events (SSE)
      · POST /deployments/{id}/approve · /cancel · /retry · POST /deployments/{id}/targets/{tid}/rollback
backups: GET /backups · GET /backups/{id} (manifest) · POST /backups/{id}/restore · GET /backups/{id}/download (admin+reauth)
notifications: GET/POST/PATCH/DELETE /notifications/channels · /notifications/rules · POST /notifications/channels/{id}/test
      · GET /notifications/deliveries
audit-events: GET /audit-events (actor, action, resource_type, outcome, from, to)
settings: GET /settings · PATCH /settings/{section} (general|notifications|security|ssh) with `version` for optimistic concurrency
dashboard: GET /dashboard/summary · GET /dashboard/expiry-trend
health: GET /healthz (liveness) · GET /readyz (db+redis)

Error shape: `{"error":{"code":"SERVER_NOT_FOUND","message":"…","correlation_id":"…","details":{}}}`.
Every response carries `X-Correlation-ID`.

## 4. Work breakdown

| Stream | Owner | Scope |
|---|---|---|
| A backend foundation | subagent | core/, models/, alembic, auth/RBAC, users, credentials, servers CRUD, settings, audit, dashboard |
| B certificate crypto + config parsers | subagent | integrations/certificates, integrations/services/parsers + unit tests |
| C SSH + remote helper + TLS | subagent | integrations/ssh, integrations/tls, infra/remote-helper, infra/test-target + integration tests |
| D jobs | subagent (after A,B,C) | discovery, uploads/validation, deployment engine, backups, rollback, monitoring, notifications, Celery, SSE |
| E frontend integration | subagent (after A) | API client, auth, replace mock data, live progress, RBAC UI, Playwright |
| F docs | subagent | docs/*.md |
| Integration/acceptance + security review | lead | end-to-end scenario against disposable target |

## 5. Progress log
(updated as streams land — see bottom of file)

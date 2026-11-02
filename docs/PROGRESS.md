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

## 5. Status (2026-11-02)

### 5.1 Acceptance scenario (section 22 of the brief)

Executed against the **local disposable target**: Ubuntu 24.04, sshd :2222, nginx :8443, apache :9443, haproxy :10443,
on a private test CA. No production system was touched.

| # | Criterion | Result | Evidence |
|---|---|---|---|
| 1 | Admin logs in | Pass | Playwright `e2e/smoke.spec.ts` |
| 2 | Register real Linux server | Pass | `smoke.spec.ts`, `deploy.spec.ts` |
| 3 | Verified SSH connection (host-key confirm + enroll) | Pass | 7-step connection test in UI; integration tests for unknown/mismatched keys |
| 4 | Detect nginx / apache | Pass | probe + `test_discovery_live.py` |
| 5 | Discover existing certificate | Pass | discovery job (Celery) via UI |
| 6 | Metadata, expiry, path, service shown | Pass | certificate detail screenshots |
| 7 | Upload replacement | Pass | renew wizard step 1 |
| 8 | Cryptographic validation and compatibility | Pass | findings (blocking/warning/info) |
| 9 | Select target installation | Pass | wizard step 3 |
| 10 | Truthful dry run | Pass | `test_deploy_live` (i): remote files byte-identical, no staging dirs |
| 11 | Approve deployment | Pass | approval path in unit/integration tests. Approval of a Production deployment was **not** exercised in the browser. |
| 12 | Backup files + metadata | Pass | verified encrypted backup per target |
| 13 | Stage + activate safely | Pass | stage → validate → atomic rename |
| 14 | Config validation | Pass | `nginx -t` / `apachectl configtest` / `haproxy -c` |
| 15 | Graceful reload | Pass | non-systemd fallback only (container has no systemd) |
| 16 | TLS verification of new fingerprint | Pass | engine probe **and** independent `openssl s_client` in e2e |
| 17 | Shown as successful | Pass | deployment detail |
| 18 | Complete audit record | Pass | DEPLOYMENT_CREATED/STARTED/STATE/TARGET_STATE/FINISHED rows |
| 19 | Previous cert available as backup | Pass | backups API; DR verification decrypts all backups |
| 20 | Failed deployment → verified rollback | Pass | live API run: verify endpoint sabotaged → `VERIFY_FINGERPRINT_MISMATCH` → rolled back, files byte-identical, original cert served. Also integration scenarios (e), (f), (g), (l). |
| 21 | Worker/browser restart keeps history | Pass | API + worker + beat restarted, all jobs/backups present; crash-resume tests (k, k2) |
| 22 | Critical tests pass | Pass | see 5.2 |

### 5.2 Test results (actual, final run)

| Suite | Result |
|---|---|
| Backend: unit + live integration (`cd backend && .venv/bin/pytest -q`) | **441 passed, 1 skipped** (stale scaffold test, since removed), 252 s |
| Backend lint (`ruff check .`) | clean |
| Migrations | single head `0004`; `alembic check` reported no drift at 0001 |
| Frontend typecheck / production build | clean / succeeds (node-server output) |
| Playwright live e2e (`frontend/e2e`) | **2/2 passed** against live API + worker + SSH target, re-run after the dependency upgrade |
| Disaster-recovery restore test | pass; see `docs/backup-restore.md` (wrong KEK → nothing decrypts) |
| `pip-audit` | no known vulnerabilities |
| `bun audit` | 1 high (zod 3, used client-side only), 1 moderate (minimatch, build tooling). 4 critical, including the TanStack Start reflected XSS, were fixed by upgrading. |
| Docker Compose | `docker compose config` valid; **images never built or run here** because Docker Hub is blocked by the network policy |

### 5.3 Completed functionality

Server registry with credential profiles (encrypted keys, passphrases), strict host-key enrollment, bastion, connection
tests; restricted remote helper + single-line sudoers policy; nginx/apache/haproxy config discovery + bounded filesystem
scan with classification, confidence, idempotent inventory, drift/missing detection; certificate upload (PEM, chain,
PKCS#12) with validation; dry-run planner; durable per-target deployment state machine with locks, verified encrypted
backups, staging, atomic activation, config test, graceful reload, live TLS verification, automatic verified rollback,
crash reconciliation, canary/batch strategy, approvals, idempotency; backups API (restore/download); expiry & drift
monitoring; SMTP + signed webhook notifications with dedupe; local auth + TOTP + OIDC, RBAC, re-auth, CSRF, rate
limits, audit trail; settings with optimistic concurrency; SSE live progress; the existing Lovable UI wired to all of it
(mock data retained only under `frontend/src/lib/demo`, unused); Docker Compose stack; 12 docs.

### 5.4 Known limitations / remaining work

- **Not exercised here**: systemd reload path; RHEL-family targets (code paths exist; only Ubuntu 24.04 ran live);
  SELinux contexts; OIDC against a real IdP; SMTP against a real server; Compose images; ACME TLS on the proxy.
- Engine replaces **existing** files only (no first-time install of a new path, no file deletion).
- Certbot-managed paths are detected and **blocked by design** (use certbot deploy hooks).
- HAProxy combined PEMs are not readable by the helper (key inside), so their discovery fingerprint comes from the live endpoint.
- JKS/PKCS#12 keystores on targets, Tomcat, Postfix, Docker-mounted certificates: **unsupported** (plugin interface only).
- Bastion reuses the target's credential.
- Cancellation after activation starts is intentionally not honoured (would leave a half-applied state); API says so.
- Remaining known-issue register: `docs/deployment-engine.md` (K-table, each item marked Fixed/Kept with reason).
- Frontend: approval-required and viewer/operator RBAC flows are covered by backend tests only, not by browser tests.
- Each e2e run registers a new server; servers with deployment history can't be deleted (by design), so dev DBs accumulate.

### 5.5 Security review summary

Fixed during review: TOTP brute-force lockout gap; `CDP_TLS_DIRECTIVE` not wired (proxy always internal CA); critical
TanStack Start XSS dependency; false-negative SAN blocking from composite vhost labels; restore/rollback moved out of
HTTP requests; per-environment trusted-chain enforcement (on for Production by migration).
Verified by inspection: no shell interpolation (helper takes argv only; every arg quoted; paths canonicalised and
allow-listed server-side), no `shell=True`/`eval`/pickle in backend, host-key checking never disabled, TLS probe
intentionally retrieves without trust then verifies separately, secrets redacted from logs, private keys never in
API responses, KEK never in Postgres, Postgres/Redis not published.
Open: zod 3 advisory (client-side only); the helper runs as root through sudo, so a compromised worker with SSH
credentials can overwrite any file under `ALLOWED_ROOTS` on enrolled hosts (narrow roots per host; threat model in `docs/security.md`).
No independent penetration test has been done.

### 5.6 Operational readiness

**Not production-ready yet.** Functionally complete and verified end to end against a disposable target, but before
production use: build and run the Compose stack on the target VM; run the integration suite against a disposable RHEL/Rocky
target with systemd; test OIDC/SMTP with real providers; narrow `ALLOWED_ROOTS` per host; external security review.
Pilot on staging servers first; production deployments default to requiring approval.

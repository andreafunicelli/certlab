# Architecture

How Cert Deploy Pro (CDP) is put together: processes, layers, data, the job pipeline, and the extension point for
new services.

Basis: `docs/PROGRESS.md` (design decisions) checked against the source tree (working tree, including uncommitted
changes). Where the code and `PROGRESS.md` differ, this document follows the code and says so.

Related: [installation.md](installation.md), [configuration.md](configuration.md), [security.md](security.md),
[ssh-permissions.md](ssh-permissions.md). Planned, not yet written: `docs/certificate-discovery.md` and
`docs/deployment-engine.md`.

---

## 1. Components

```
                         operator browser
                               |  HTTPS :443 (CDP_HTTPS_PORT)
                    +----------v-----------+
                    | proxy   (Caddy 2)    |   only published service
                    | Caddyfile, HSTS,     |
                    | 2 MB /api body cap   |
                    +----+-----------+-----+
                /api/*   |           |   everything else
                         |           |
          +--------------v--+    +---v-------------------+
          | api             |    | frontend              |
          | FastAPI+uvicorn |    | TanStack Start (Nitro |
          | :8000           |    | node-server) :3000    |
          | lifespan: KEK   |    +-----------------------+
          | check, bootstrap|
          +--+----+------+--+
   SQL       |    |      | enqueue (Celery)   |  SSE: Redis pub/sub
   +---------v-+  |  +---v-------------+      |
   | postgres  |  |  | redis           |<-----+
   | 16        |  |  | broker, rate    |
   +-----^-----+  |  | limits, pub/sub |
         |        |  +---^----------^--+
         |        |      |          |
         |   +----v------v-+   +----+-------+
         +---| worker       |   | beat       |  schedules (Celery beat)
             | Celery,      |   +------------+
             | asyncssh     |
             +------+-------+
                    |  SSH :22 (publickey, pinned host key)
                    |  sudo -n cdp-helper <subcommand>
                    v
          +--------------------------+
          | managed Linux target     |
          | nginx / apache / haproxy |
          | cdp-helper (root, sh)    |
          +--------------------------+

  Shared volume "artifacts": encrypted ciphertext (api, worker, beat mount it)
  Secret file ./secrets/cdp_master_key -> /run/secrets/cdp_master_key (api, worker, beat, migrate)
```

Startup order: `postgres` and `redis` (healthy) -> `migrate` (`alembic upgrade head`, exits 0) -> `api`, `worker`,
`beat` -> `frontend` -> `proxy` (see [installation.md](installation.md) section 2.3).

### 1.1 Container topology

| Service | Image | Role | Port | Published | Memory limit |
|---|---|---|---|---|---|
| `proxy` | `caddy:2-alpine` | TLS, routing, security headers | 80, 443 | yes | none |
| `frontend` | built from `frontend/Dockerfile` (`node:22-bookworm-slim`) | SSR UI, Nitro node server | 3000 | no | 512 MiB |
| `api` | built from `backend/Dockerfile` (`python:3.12-slim-bookworm`) | FastAPI, uvicorn `app.main:app` | 8000 | no | 768 MiB |
| `worker` | same backend image | Celery worker (`--concurrency`, default 4) | none | no | 1 GiB |
| `beat` | same backend image | Celery beat schedule | none | no | 256 MiB |
| `migrate` | same backend image | `alembic upgrade head`, one-shot | none | no | none |
| `postgres` | `postgres:16-alpine` | database | 5432 | no | 1 GiB |
| `redis` | `redis:7-alpine` | broker, rate limits, pub/sub; AOF on | 6379 | no | 256 MiB |

---

## 2. Backend layering

```
api/v1/*.py          thin FastAPI routers: parse input, call one service, shape output
   |  Depends(...)   api/deps.py: session, CSRF, RBAC, re-auth
   v
services/*.py        domain logic: auth, discovery, deployment engine and planner, backups,
   |                 credentials, servers, settings, audit, notifications, monitoring, events
   v
repositories/*.py    database access for users, servers, settings, audit
models/*.py          SQLAlchemy 2 models (the other services query models directly)
   |
integrations/*       outside systems, no business rules:
                       ssh/       asyncssh client, helper calls, host keys, error classification
                       tls/       live endpoint probe (SNI aware)
                       certificates/  pure parsing and validation (no I/O)
                       services/  per-service adapters (nginx, apache, haproxy) and config parsers
                       notify/    SMTP and webhook delivery
core/*               config, db session factory, crypto (envelope), security (argon2, tokens, CSRF, TOTP),
                     permissions (RBAC matrix), logging (redaction), middleware, rate limiting, errors
workers/*            Celery app and task definitions (call services)
```

`PROGRESS.md` describes this as the intended layering. In the code, `repositories/` covers only `users`, `servers`,
`settings` and `audit`. Several services, for example `credentials` and `backups`, query the models directly. Treat the
repositories package as partial.

Errors: services raise `AppError(code, message, status, details)`. The handler returns
`{"error": {"code", "message", "correlation_id", "details"}}`.

### 2.1 Module map

| Path | Responsibility |
|---|---|
| `backend/app/main.py` | App factory. Middleware order, CORS, lifespan (KEK check, bootstrap admin), router include. |
| `backend/app/api/v1/router.py` | Includes one router per area: auth, users, credentials, servers, certificates, installations, discovery, versions, notifications, deployments, backups, misc (health, dashboard, audit, settings). |
| `backend/app/services/auth.py` | Login, sessions, re-auth, password change, TOTP. |
| `backend/app/services/oidc.py` | OIDC authorization code with PKCE; group mapping. |
| `backend/app/services/connectivity.py` | Host-key scan and enrollment; connection test; builds SSH targets and loads credentials. |
| `backend/app/services/discovery.py` | Discovery jobs: filesystem scan, service config dump, reference matching. |
| `backend/app/services/deployment_planner.py` | Dry-run plans: per-target checks, file plan, free space, configtest. |
| `backend/app/services/deployment_engine.py` | Per-target state machine executed by the worker. |
| `backend/app/services/deployments.py` | Creating, approving, cancelling and retrying deployment jobs. |
| `backend/app/services/backups.py` | Backup creation, restore, retention purge. |
| `backend/app/services/locks.py` | Durable resource locks (`deployment_locks`). |
| `backend/app/services/events.py` | Job progress: Redis pub/sub publishing and the SSE generator. |
| `backend/app/services/monitoring.py`, `notifications.py`, `inventory.py`, `dashboard.py`, `cert_status.py` | Expiry checks, endpoint verification, notification rules and delivery, inventory views, dashboard. |
| `backend/app/integrations/ssh/` | `connection.py` (asyncssh `SSHRemoteHost`, per-host semaphore, retry on idempotent calls), `paths.py` (helper argv and path validation), `hostkeys.py`, `testconn.py`, `errors.py`, `sanitize.py`, `parsing.py`. |
| `backend/app/integrations/services/adapters/` | `base.py` (`ServiceAdapter`, registry), `builtin.py` (nginx, apache, haproxy). |
| `backend/app/integrations/services/parsers/` | Pure text parsers for nginx, apache and haproxy configuration. |
| `backend/app/integrations/certificates/` | Parsing, classification, validation, key matching, chain checks. |
| `backend/app/integrations/tls/probe.py` | Live TLS probe with SNI, used for verification. |
| `backend/app/workers/` | `celery_app.py` (broker, reliability settings, beat schedule), `tasks.py`, `deploy_tasks.py`. |
| `backend/alembic/versions/` | Migrations `0001` (initial schema and seed), `0002` (one active discovery job per server; notification dedupe index), `0003` (deployment request hash, retry link, target working state). |
| `infra/remote-helper/` | `cdp-helper` (root shell helper), `install.sh`, sudoers rule, example configuration. |
| `infra/caddy/Caddyfile` | Proxy routes and TLS directive. |
| `infra/test-target/` | Disposable SSH and web-server target for integration tests. |
| `frontend/` | TanStack Start application (Vite, Tailwind 4, TanStack Query). Talks to `/api/v1` on the same origin. |

---

## 3. Data model

22 tables, all with UUID primary keys (`IdMixin`) and timestamps (`TimestampMixin`) unless noted. Migrations are in
`backend/alembic/versions/`.

| Group | Table | Purpose | Key relationships |
|---|---|---|---|
| Identity | `users` | Local and OIDC accounts. Argon2 hash, TOTP secret (encrypted), failure counter, lock. | |
| | `roles` | `admin`, `operator`, `viewer` (seeded). | |
| | `user_roles` | Many-to-many. | users (CASCADE), roles (RESTRICT) |
| | `sessions` | Opaque session token hash, IP, user agent, expiry, revocation, re-auth time. | users (CASCADE) |
| Inventory | `environments` | Named environments with `is_production` and `requires_approval`. Seeded: Production, Staging, Test, Development. | Referenced by `servers.environment` by name (RESTRICT, cascade on update). |
| | `credentials` | SSH private key references: public key, fingerprint, algorithm, encrypted passphrase. The key itself is an encrypted artifact. | artifact (RESTRICT), users (SET NULL) |
| | `servers` | Managed hosts: address, SSH user and port, privilege mode (`helper-sudo` or `none`), enrolled host key, connection status, detected services, optional bastion. | credential (RESTRICT), bastion server (self, SET NULL), environment (by name) |
| Certificates | `certificates` | Logical certificate identity: fingerprint, subject, SANs, validity, type, owner, tags. | |
| | `certificate_versions` | Uploaded versions: leaf, chain, key artifact references, validation status. | certificate (SET NULL), three encrypted artifacts (RESTRICT), uploader (SET NULL) |
| | `certificate_installations` | Where a certificate is used: server, service type, file paths, verify endpoint, managed flag, last deployment. | certificate (SET NULL), server (CASCADE), last deployment (SET NULL) |
| Discovery | `discovery_jobs` | One job per scan. Unique partial index: at most one `pending` or `running` job per server (migration 0002). | server (CASCADE) |
| | `discovery_findings` | Per-job results. | job (CASCADE) |
| Deployments | `deployment_jobs` | A deployment request: version, strategy, status, request hash (idempotency), approver, retry link. | version (RESTRICT), initiator, approver (SET NULL), retry of (self, SET NULL) |
| | `deployment_targets` | One row per installation in a job: state, steps, verification, backup link. | job (CASCADE), installation (SET NULL), server (RESTRICT), backup (SET NULL) |
| | `deployment_locks` | Resource locks keyed by `resource_key` (unique), with owner, expiry and heartbeat. | job and target (CASCADE) |
| Backups | `backups` | Pre-change copies of destination files: manifest, verification, retention date. Content is an encrypted artifact. | server (RESTRICT), installation (SET NULL), target (SET NULL) |
| Artifacts | `encrypted_artifacts` | Envelope-encrypted blobs: purpose, KEK `key_id`, wrapped DEK, nonce, plaintext SHA-256, size, filename, soft-delete marker. The ciphertext is a file in the artifacts volume. | |
| Notifications | `notification_channels` | Email and webhook targets. Secrets encrypted inline. | |
| | `notification_rules` | Which events go to which channel. | channel (CASCADE) |
| | `notification_deliveries` | Delivery attempts. Non-unique index on rule, dedupe key and time (migration 0002). | rule (SET NULL), channel (SET NULL) |
| Audit | `audit_events` | Actor, action, resource, before and after (redacted), outcome, IP, user agent, correlation ID. No update or delete endpoint was found for audit events. | actor (SET NULL) |
| Settings | `app_settings` | One row per section (`general`, `notifications`, `security`, `ssh`), with a version counter. | updated_by (SET NULL) |

Relationship summary:

```
users 1--* sessions
users *--* roles (user_roles)
credentials 1--* servers ---- servers *--1 environments (by name)
servers 1--* certificate_installations *--1 certificates 1--* certificate_versions
certificate_versions 1--* deployment_jobs 1--* deployment_targets *--1 certificate_installations
deployment_targets 1--* deployment_locks ; deployment_targets *--0..1 backups
servers 1--* backups ; servers 1--* discovery_jobs 1--* discovery_findings
encrypted_artifacts <--- credentials, certificate_versions, backups, notification channels (secrets inline)
```

---

## 4. Job pipeline

Long-running work (discovery, deployments, backups, notifications) is always a database row plus a Celery task. Short
operations (connection test, host-key scan) run inline in the API request with hard timeouts.

### 4.1 Deployment

1. **Plan.** `POST /api/v1/deployments/plan` builds a dry-run plan in the request (`deployment_planner.py`). It
   connects through the helper for `probe`, `stat`, `read-public`, `backup` (in memory), `df` and `configtest`. It writes
   nothing on the target.
2. **Create.** `POST /api/v1/deployments` with an `Idempotency-Key` header. The service stores the job and one target per
   installation (`deployment_jobs`, `deployment_targets`), with a request hash for idempotency. It enqueues
   `deployments.run` with the job ID (`services/deployments.py`, through `workers/celery_app.enqueue`). Environments
   that need approval wait for `POST /api/v1/deployments/{id}/approve` (admin, re-auth).
3. **Execute.** The worker runs `deployments.run` (`workers/deploy_tasks.py`). The engine processes targets in batches
   or canary order, with `deployment_concurrency` parallel targets. Per target, steps are:

   `connect` -> `lock` -> `recheck` -> `backup` -> `stage` -> `validate` -> checkpoint `before_activation` ->
   `activate` (install) -> `config_test` -> `reload` -> `verify` -> `cleanup` -> `finalize`

   Any failure after activation begins runs `rollback`, which restores from the backup, then `reconcile` checks the
   restored hashes against the manifest. A canary failure stops the remaining batches.
4. **Persist.** Each step writes its state to PostgreSQL before the next step. A worker that dies mid-run is
   redelivered (`acks_late`, `reject_on_worker_lost`). A resumed run continues from the persisted state, and the
   durable lock expires if its heartbeat stops.
5. **Publish.** Each state change is also published to Redis channel `cdp:job:<kind>:<job_id>` (best effort).
6. **Observe.** The browser opens `GET /api/v1/deployments/{id}/events` (Server-Sent Events). The generator
   (`services/events.py`):
   - sends a `snapshot` event built from the database, so late subscribers miss nothing,
   - forwards each pub/sub message as `event: progress`,
   - re-reads the snapshot periodically and sends a new `snapshot` when it changed (so a Redis outage only delays
     updates),
   - sends `event: end` and closes when the database shows a terminal status.

   Frame format: `event: snapshot|progress|end` followed by `data: {"kind":..., "job_id":..., "type":..., "ts":...}`.

### 4.2 Discovery

`POST /api/v1/servers/{id}/discover` (or `POST /api/v1/discovery-jobs/bulk`) creates a `discovery_jobs` row, guarded by
the one-active-per-server index, and enqueues `discovery.run`. Beat runs `discovery.schedule_all` every 5 minutes. The
events stream is `GET /api/v1/discovery-jobs/{id}/events`.

### 4.3 Reliability settings (`workers/celery_app.py`)

| Setting | Value | Effect |
|---|---|---|
| Broker | Redis, password from `REDIS_PASSWORD` in compose | |
| Serialisation | JSON only | |
| `task_acks_late`, `task_reject_on_worker_lost` | true | Unfinished tasks are redelivered after a worker dies. |
| `worker_prefetch_multiplier` | 1 | One task reserved per process at a time. |
| `visibility_timeout` | 6 hours | Longer than any task, so redelivery does not start early. |
| `task_ignore_result` | true | No result backend. State lives in PostgreSQL. |
| `CDP_CELERY_EAGER` | off | When on, tasks run inline (tests). |

Beat schedule:

| Task | Schedule |
|---|---|
| `discovery.schedule_all` | every 5 minutes |
| `notifications.sweep_pending` | every 10 minutes |
| `deployments.purge_locks` | every 10 minutes |
| `monitoring.check_expiry` | 06:17 daily |
| `backups.purge_expired` | 03:23 daily |
| `monitoring.verify_endpoints` | every 6 hours, minute 41 |

The last two are added to the beat schedule by `workers/deploy_tasks.py` at import time, not in `celery_app.py`.

---

## 5. Discovery and deployment, overview

These are summaries only. Detailed design will be in `docs/certificate-discovery.md` and `docs/deployment-engine.md`,
which have not been written yet.

**Discovery** scans the configured roots on each target (`find`), reads public certificates (`read-public`, `stat`),
dumps each service's configuration (`dump`), and matches certificate and key references in those configurations to
known certificates. Private keys are never returned to the backend by discovery. The helper refuses `read-public`
for key material. Discovery produces installations and findings. It does not change the target.

**Deployment** takes an uploaded certificate version and writes it to each selected installation. It does this as a
checked sequence: back up the current files, stage the new ones, validate the staged files against the certificate,
install, test the service configuration, reload, and verify live TLS and file hashes. Any failure after the first
install rolls back from the backup, and the rollback is verified the same way. Canary and batch strategies, approval,
and durable locks govern the order and the concurrency.

---

## 6. Service adapters (plugin model)

`backend/app/integrations/services/adapters/base.py` defines the extension point for a managed service.

```python
class ServiceAdapter(ABC):
    service_type: str                       # unique key, e.g. "nginx"
    def discover(self, host) -> list[ConfigCertRef]: ...     # read-only
    def plan_files(self, installation) -> list[PlannedFile]: ...   # pure
    def config_test(self, host) -> CommandResult: ...        # delegates to host.config_test
    def reload(self, host, allow_restart) -> CommandResult: ...    # delegates to host.reload
    def default_verify_endpoints(self, ref): ...             # candidate (host, port, sni)

@register_adapter                  # registry keyed by service_type
class NginxAdapter(ServiceAdapter): ...
```

`get_adapter(service_type)` instantiates the registered class. An unknown key raises `UnsupportedServiceError`.
Built-in adapters: `NginxAdapter`, `ApacheAdapter`, `HaproxyAdapter` in `builtin.py`.

The contract, as written in the module docstring:

- `discover` is read-only. It calls `host.dump_config(...)` and a pure parser.
- `plan_files` is pure. It maps each installation to destination paths and artifact kinds. It raises `PlanError` when
  automatic deployment is not possible.
- `config_test` and `reload` return a `CommandResult`. A non-zero exit status means failure.
- Adapters never run commands themselves. They call `RemoteHost` methods, which call helper subcommands.

**Limits, from the code.** Adding a fourth service is not a single plugin file:

- `SSHRemoteHost._svc` (`integrations/ssh/connection.py`) accepts only `nginx`, `apache` and `haproxy`. Any other
  service raises `COMMAND_FAILED`.
- The helper's `dump`, `configtest` and `reload` subcommands accept only `nginx`, `apache` and `haproxy`.
- The `ServiceType` enum (`integrations/contracts.py`) lists `nginx`, `apache`, `haproxy` and `filesystem`, where
  `filesystem` is used only for filesystem-scan results.
- Adding a service therefore requires: a parser module, an adapter subclass, new artifact kinds if needed, changes to
  `_svc` and to the `ServiceType` enum, and new helper branches for `dump`, `configtest` and `reload`. The registry
  itself is an in-process dictionary; there is no dynamic plugin loading.

Only the three built-in services have been exercised by the test target
(`infra/test-target/setup-local.sh`). Its integration tests were not run while writing this document.

# Installation and operations

Audience: operators installing Cert Deploy Pro (CDP) on a single Linux VM with Docker Compose.

Status of this document: every command, variable and path below was taken from the repository files
(`docker-compose.yml`, `.env.example`, `infra/caddy/Caddyfile`, `backend/Dockerfile`, `frontend/Dockerfile`,
`backend/app/core/config.py`, `backend/alembic`, `frontend/package.json`, `frontend/vite.config.ts`).
Nothing in this document was executed while it was written. Items marked **(not run)** are standard tool usage
that the repository does not exercise in its own tests.

Related: [configuration.md](configuration.md) (all variables), [security.md](security.md),
[ssh-permissions.md](ssh-permissions.md) (managed targets), [architecture.md](architecture.md).

---

## 1. Prerequisites

| Item | Requirement | Notes |
|---|---|---|
| Host | One Linux VM | Only this topology is described. Other topologies are not documented. |
| Container runtime | Docker Engine with the Compose v2 plugin (`docker compose`) | `depends_on: condition: service_completed_successfully` is used, so Compose v2 is required. |
| Memory | Sum of compose limits is 3.75 GiB (postgres 1 GiB, redis 256 MiB, api 768 MiB, worker 1 GiB, beat 256 MiB, frontend 512 MiB) | Sizing derived from the limits; not load-tested. The proxy has no limit. |
| Host ports | 80 and 443 free (`CDP_HTTP_PORT`, `CDP_HTTPS_PORT`) | Only the `proxy` service publishes ports. |
| DNS | A name for `CDP_DOMAIN` that operator browsers resolve | Required for any HTTPS option. |
| Outbound network | The VM must reach managed targets over SSH (TCP 22 by default, or each server's `ssh_port`) | |
| Managed targets | Prepared as described in [ssh-permissions.md](ssh-permissions.md) | Not part of the VM install. |

---

## 2. Clean install

### 2.1 Clone and create the environment file

```bash
git clone <repository-url> certlab
cd certlab
cp .env.example .env
```

Edit `.env` and set at least:

| Variable | Why |
|---|---|
| `POSTGRES_PASSWORD` | Required. Compose refuses to start without it (`:?` guard). |
| `REDIS_PASSWORD` | Required. Compose refuses to start without it. |
| `CDP_DOMAIN` | Hostname the proxy serves. See section 3. |
| `CDP_PUBLIC_BASE_URL` | External base URL, e.g. `https://<CDP_DOMAIN>`. Used for OIDC redirect URIs. |
| `CDP_CORS_ORIGINS` | Usually the same external origin. |
| `CDP_BOOTSTRAP_ADMIN_PASSWORD` | Initial admin password, at least 12 characters. Remove after first login (section 2.4). |

`.env` and `secrets/` are listed in `.gitignore`. Keep it that way.

### 2.2 Generate and protect the master key

The master key (KEK) encrypts every stored secret. Losing it makes all encrypted keys and backups unrecoverable.

```bash
mkdir -p secrets
head -c32 /dev/urandom | base64 > secrets/cdp_master_key
chmod 600 secrets/cdp_master_key
```

This is the exact command from `.env.example`. The file holds base64 of 32 random bytes. Compose mounts it into
the backend containers as `/run/secrets/cdp_master_key` (`CDP_MASTER_KEY_FILE`).

**Back up `secrets/cdp_master_key` to offline storage now, separately from the database and the artifacts volume.**
A backup of the database and artifacts without this file cannot be decrypted.

### 2.3 Start the stack

```bash
docker compose up -d --build
docker compose ps
docker compose logs migrate
```

Startup order, enforced by compose:

1. `postgres` and `redis` start and must report healthy.
2. `migrate` runs `alembic upgrade head` and exits. Its status is `Exited (0)` by design (`restart: "no"`).
3. `api`, `worker` and `beat` start only after `migrate` completes successfully.
4. `frontend` starts, then `proxy` (which depends on `api` and `frontend`).

Health check through the proxy (use `-k` only if the proxy uses the internal CA, see section 3):

```bash
curl -fsS https://<CDP_DOMAIN>/api/v1/healthz     # liveness: {"status":"ok"}
curl -fsS https://<CDP_DOMAIN>/api/v1/readyz      # checks database and redis
```

### 2.4 Bootstrap the first administrator

On API startup, if the `users` table is empty and both `CDP_BOOTSTRAP_ADMIN_USERNAME` and
`CDP_BOOTSTRAP_ADMIN_PASSWORD` are set, one admin account is created. Behaviour from `services/bootstrap.py`
and `services/users.py`:

- A password shorter than 12 characters is rejected. The API logs an error event `bootstrap_admin_skipped`
  and keeps starting.
- If any user already exists, nothing happens.
- Check the outcome with `docker compose logs api` and look for `bootstrap_admin_created` or `bootstrap_admin_skipped`.

After the first successful login:

1. Remove or blank `CDP_BOOTSTRAP_ADMIN_PASSWORD` in `.env`.
2. Run `docker compose up -d` so `api`, `worker`, `beat` and `migrate` are recreated without it.

The value stays in `.env` and in the container environment until step 2 is done. `env_file: .env` injects every
variable into every backend container.

Next steps: create a credential (`POST /api/v1/credentials`, requires re-authentication), register servers, and
prepare targets per [ssh-permissions.md](ssh-permissions.md).

---

## 3. HTTPS and the reverse proxy

The `proxy` service runs Caddy 2 with `infra/caddy/Caddyfile` mounted read-only. Routing as shipped:

| Path | Destination |
|---|---|
| `/api/*` | `api:8000` with `flush_interval -1` (no buffering, needed for SSE). Request body capped at 2 MB. |
| everything else | `frontend:3000` |

Caddy adds HSTS (`max-age=31536000; includeSubDomains`), `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, gzip, and removes the `Server` header.

### 3.1 Which TLS mode is active

The proxy's TLS mode is selected by `CDP_TLS_DIRECTIVE` in `.env`. Compose passes it to the proxy container, and the
Caddyfile places it inside the site block. The default is `tls internal`.

| Option | `CDP_TLS_DIRECTIVE` | Status |
|---|---|---|
| Internal CA (default) | `tls internal`. Clients must trust Caddy's local root CA, stored in the `caddydata` volume. | Default. Exporting the root CA has not been tested here. |
| Public ACME certificate | `tls admin@example.com`. `CDP_DOMAIN` must be a public DNS name pointing at the VM, with ports 80 and 443 reachable. | Not tested here (no outbound ACME from the build environment). |
| Your own certificate files | `tls /certs/fullchain.pem /certs/privkey.pem`. Also add `- ./certs:/certs:ro` to the `proxy` service volumes. | Not tested here. |

Apply a change with `docker compose up -d proxy`.

After any change, check the active configuration with
`docker compose exec proxy caddy validate --config /etc/caddy/Caddyfile` **(not run; standard Caddy command)**.

### 3.2 Using an existing corporate reverse proxy instead of the bundled Caddy

This is supported only in the sense that the API is designed to sit behind a proxy. It has not been tested behind a
corporate proxy. Requirements derived from the code:

1. **Route `/api/` to the API and everything else to the frontend.** The `api` and `frontend` services publish no
   host ports. Your proxy must be able to reach `api:8000` and `frontend:3000` on the compose network, or the
   compose file must be changed to publish them. Keep the API off the public network.
2. **Disable response buffering for SSE paths.** These endpoints stream: `/api/v1/deployments/{id}/events` and
   `/api/v1/discovery-jobs/{id}/events`. The API sends `X-Accel-Buffering: no` on the discovery stream.
3. **Set forwarded headers.** `CDP_TRUST_PROXY_HEADERS=true` (the example value) makes the API use the first
   `X-Forwarded-For` value for rate limiting and audit IPs. Only do this if the API is reachable exclusively
   through your proxy. Otherwise clients can spoof the address.
4. **Body size.** Credential bodies are limited to 128 KiB and certificate parsing to 256 KiB by the application.
   The bundled proxy allows 2 MB for `/api/*`. Set your proxy's limit to at least that.
5. **Security headers.** The API sends its own headers (section in [security.md](security.md)). The bundled proxy
   also adds HSTS and the others listed above. Replicate those in your proxy if you want them.
6. **Cookies.** Session and CSRF cookies are `Secure` by default (`CDP_COOKIE_SECURE=true`). Serve everything over HTTPS.

---

## 4. Upgrades

### 4.1 Back up first

Back up three things. The database and artifacts volume are both required to restore; the master key is required to
read either.

```bash
# database (standard PostgreSQL tooling run inside the postgres container) (not run)
docker compose exec -T postgres pg_dump -U cdp -d cdp -Fc > cdp-$(date +%F).dump

# artifacts volume. Compose project name is "cert-deploy-pro", so the volume is cert-deploy-pro_artifacts (not run)
docker run --rm -v cert-deploy-pro_artifacts:/src -v "$PWD":/dst alpine \
  tar -C /src -czf /dst/artifacts-$(date +%F).tgz .

# master key: already backed up offline (section 2.2). Verify the copy exists.
```

Redis holds only the job queue and rate-limit counters, so it does not need to be backed up.

### 4.2 Apply the upgrade

```bash
git pull                      # or check out the target revision
docker compose build          # builds cert-deploy-pro/backend and cert-deploy-pro/frontend
docker compose up -d          # migrate runs first; api, worker and beat wait for it
docker compose logs migrate   # confirm alembic reached head
```

Images are tagged `cert-deploy-pro/<service>:${CDP_VERSION:-local}`. Set `CDP_VERSION` to keep older tags for rollback.

### 4.3 Rollback

Schema migrations run automatically on upgrade. Revisions 0001 and 0002 define `downgrade()` functions; the
downgrade for 0003 was not reviewed, and no downgrade has been tested. Treat a rollback as a restore:

1. `docker compose down`.
2. Restore the database from the pre-upgrade dump (`pg_restore`, into an empty database) and the artifacts volume
   from the pre-upgrade archive **(not run)**.
3. Set `CDP_VERSION` to the previous tag and run `docker compose up -d`.

---

## 5. Local development (not for production)

The compose stack is the supported deployment. This section is for working on the code. Requirements from the
repository: Python 3.12 or later (`backend/pyproject.toml`), Bun (the frontend Dockerfile uses Bun 1.2), and
PostgreSQL 16 and Redis 7 (the compose image versions).

### 5.1 Services

Run PostgreSQL and Redis locally. The default `CDP_DATABASE_URL` expects a database `cdp` with user `cdp` and
password `cdp-dev-only` on `127.0.0.1:5432`. Create it that way or override the variable.

### 5.2 Backend

```bash
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'

mkdir -p ../secrets && head -c32 /dev/urandom | base64 > ../secrets/cdp_master_key && chmod 600 ../secrets/cdp_master_key

export CDP_ENV=dev
export CDP_COOKIE_SECURE=false                       # plain HTTP on localhost
export CDP_MASTER_KEY_FILE="$PWD/../secrets/cdp_master_key"
export CDP_ARTIFACT_DIR="$PWD/var/artifacts"         # default /var/lib/cdp/artifacts may not be writable for a dev user
export CDP_DATABASE_URL='postgresql+psycopg://cdp:cdp-dev-only@127.0.0.1:5432/cdp'
export CDP_REDIS_URL='redis://127.0.0.1:6379/0'
export CDP_BOOTSTRAP_ADMIN_USERNAME=admin
export CDP_BOOTSTRAP_ADMIN_PASSWORD='change-me-dev-password'

alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

In two more terminals, with the same environment:

```bash
celery -A app.workers.celery_app worker --loglevel=INFO
celery -A app.workers.celery_app beat --loglevel=INFO
```

The Celery invocations are the ones given in the `celery_app.py` module docstring. `backend/var/` is git-ignored.

`CDP_ENV` has no behavioural effect; it is only logged at startup (see [configuration.md](configuration.md)).

### 5.3 Frontend

```bash
cd frontend
bun install
bunx vite dev --host 127.0.0.1 --port 5173
```

`package.json` defines `"dev": "vite dev"`, so `bun run dev` is equivalent apart from the host and port flags. Open
`http://127.0.0.1:5173`. Requests to `/api` are proxied to `CDP_API_PROXY_TARGET`, which defaults to
`http://127.0.0.1:8000` (`frontend/vite.config.ts`). The same-origin proxy is what keeps cookies and CSRF working
in development.

### 5.4 Tests

The backend test suite is under `backend/tests` (`unit/`, `integration/`). Integration tests need the disposable
target in section 8. Set `CDP_CELERY_EAGER=1` to run Celery tasks inline in tests (see configuration).
**(Test commands not run in this document.)**

---

## 6. Managed targets

Do not start with the test target. Prepare each real Linux host with the restricted helper as described in
[ssh-permissions.md](ssh-permissions.md). Summary of what that involves:

- A dedicated `cdpdeploy` account, public-key login only.
- `/usr/local/libexec/cdp-helper` installed root-owned, with one sudoers rule that lets `cdpdeploy` run only that
  binary as root.
- `/etc/cdp-helper.conf` listing the directories the helper may touch.

Then enroll the host key (fingerprint confirmed out of band) and run a connection test from the UI or
`POST /api/v1/servers/{id}/test-connection`.

---

## 7. Operating the stack

| Task | Command or endpoint |
|---|---|
| Stack status | `docker compose ps` |
| Service logs (JSON) | `docker compose logs -f api worker` |
| Restart one service | `docker compose restart <service>` |
| Apply a `.env` change | `docker compose up -d` (recreates only changed services) |
| Stop, keep data | `docker compose down` |
| Stop and delete volumes | `docker compose down -v` **destroys the database, Redis data and artifacts. Do not run without a verified backup.** |

Logs are structured JSON from structlog. Secret-looking keys and PEM blocks are redacted before output (see
[security.md](security.md)).

Scheduled jobs run from the `beat` service. The schedule is defined in `backend/app/workers/celery_app.py` and
`backend/app/workers/deploy_tasks.py`:

| Schedule | Task |
|---|---|
| every 5 minutes | `discovery.schedule_all` |
| every 10 minutes | `notifications.sweep_pending` |
| every 10 minutes | `deployments.purge_locks` |
| 06:17 daily | `monitoring.check_expiry` |
| 03:23 daily | `backups.purge_expired` |
| every 6 hours at minute 41 | `monitoring.verify_endpoints` |

Beat keeps its schedule file in `/tmp`, which is a tmpfs in compose, so the file is recreated on each start.

---

## 8. Disposable test target (testing only)

`infra/test-target/setup-local.sh` provisions a throwaway SSH server and nginx, Apache and HAProxy on the local
machine for integration tests. Its header states that it runs as root, has no systemd and no Docker, and is test
infrastructure only. It:

- creates test keys and a test passphrase under `/var/lib/cdp-test` (the passphrase is written to a file there),
- installs the remote helper for `cdpdeploy` using `infra/remote-helper/install.sh` with the generated public key,
- listens on `127.0.0.1` ports 2222 (ssh), 8443 (nginx), 9443 (apache) and 10443 (haproxy),
- writes test certificates under `/etc/ssl/cdp-test`.

Teardown: `infra/test-target/teardown-local.sh`.

Do not run either script on a host you care about. `infra/test-target/docker-compose.snippet.yml` is marked in its
own file as not exercised.

**I did not run `setup-local.sh` or `teardown-local.sh` while writing this document.**

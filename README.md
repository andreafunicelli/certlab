# Cert Deploy Pro

Cert Deploy Pro (CDP) is a self-hosted platform that discovers TLS certificates on Linux servers over SSH and
deploys replacements with backup, verification and automatic rollback. It connects to each managed host as a
restricted account. Privileged operations run through one root helper, `cdp-helper`, which accepts a fixed set of
subcommands and only touches paths under an allow-list. The stack runs as Docker Compose services: a FastAPI API,
Celery worker and beat, PostgreSQL, Redis, a Caddy proxy and a TanStack Start frontend.

## Features

- Discovery of nginx, Apache and HAProxy configurations, plus a filesystem scan for certificate files. Discovery is read-only and never reads private keys.
- Upload and validation of certificate, chain, private key and PKCS#12 material, with policy findings.
- Dry-run planning that lists every blocking finding and warning before anything is written.
- Canary and batched deployment, with durable locks and state persisted after every step.
- Verified backups: encrypted, manifest-checked and restorable.
- Live TLS verification (SNI-aware) combined with on-disk fingerprint checks.
- Automatic rollback to the verified previous certificate. A target that cannot be verified is marked `manual_intervention_required`.
- Expiry and drift monitoring, with scheduled endpoint verification.
- Notifications by SMTP and webhook.
- Local accounts with RBAC (admin, operator, viewer), OIDC (PKCE), optional TOTP and re-authentication for sensitive actions.
- Audit trail, and envelope encryption: each artifact has its own AES-256-GCM data key, wrapped by a master key that never reaches the database.

## Support matrix

| Target | Discovery | Deploy and rollback | Status |
|---|---|---|---|
| nginx | `nginx -T` | full chain and key, `nginx -t`, `nginx -s reload` | Discovery, deploy, verify and rollback tested live |
| Apache | `apachectl -D DUMP_INCLUDES` | chain file or full chain and key, `apachectl configtest`, `apachectl -k graceful` | Discovery, deploy, verify and rollback tested live |
| HAProxy | `crt` directives in `haproxy.cfg` | combined PEM, `haproxy -c`, seamless `-sf` reload | Tested live with combined PEM |
| Certbot-managed paths | Detected (`managed_by_certbot`) | Blocked by design (`CERTBOT_MANAGED`); use certbot deploy hooks | Detection and blocking covered by a live test |
| Filesystem certificate files | Scanned (`unmanaged`) | Not deployable | Discovery tested live |
| Tomcat, JKS, Postfix, Docker | Not supported | Not supported | Not supported yet |

Operating systems are identified by the host probe. Supported IDs are `ubuntu`, `debian`, `rhel`, `rocky`,
`almalinux` and `ol`. Only Ubuntu 24.04 has been exercised live. RHEL-family paths (`/etc/httpd`, `httpd` unit
names) are not covered by any live test. The systemd reload path is not exercised, because the test target has no
systemd.

## Quick start (Docker Compose)

Run from a checkout of this repository. The full procedure is in [docs/installation.md](docs/installation.md).

```bash
cp .env.example .env
# Set POSTGRES_PASSWORD, REDIS_PASSWORD, CDP_DOMAIN, CDP_PUBLIC_BASE_URL, CDP_CORS_ORIGINS
# and CDP_BOOTSTRAP_ADMIN_PASSWORD (at least 12 characters).

mkdir -p secrets && head -c32 /dev/urandom | base64 > secrets/cdp_master_key && chmod 600 secrets/cdp_master_key

docker compose up -d --build
docker compose logs migrate                              # alembic upgrade head, exits 0
curl -fsS https://<CDP_DOMAIN>/api/v1/readyz             # checks database and redis
```

- Back up `secrets/cdp_master_key` offline now. Without it, encrypted keys and backups cannot be recovered.
- The default `CDP_TLS_DIRECTIVE=tls internal` uses a private CA that clients must trust.
- After the first login, blank `CDP_BOOTSTRAP_ADMIN_PASSWORD` in `.env` and run `docker compose up -d`.

## Preparing a target server

Each managed host needs the `cdpdeploy` account and the root helper. See [docs/ssh-permissions.md](docs/ssh-permissions.md).
On the target, as root, from a checkout of this repository:

```bash
sudo ./infra/remote-helper/install.sh --user cdpdeploy --pubkey-file /root/cdp_deploy.pub
```

The script creates the account, installs `/usr/local/libexec/cdp-helper`, writes `/etc/cdp-helper.conf` (the
allowed roots) and adds a sudoers rule that lets `cdpdeploy` run only that helper. Then enroll the host key in CDP
(fingerprint confirmed out of band) and run a connection test.

## Local development

Not for production. Requires Python 3.12 or later, Bun, PostgreSQL 16 and Redis 7 on `127.0.0.1`. The default
database URL expects user `cdp`, password `cdp-dev-only` and database `cdp`.

Backend, in `backend/`:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'

export CDP_ENV=dev CDP_COOKIE_SECURE=false
export CDP_MASTER_KEY_FILE="$PWD/../secrets/cdp_master_key"   # create it as in Quick start
export CDP_ARTIFACT_DIR="$PWD/var/artifacts"
export CDP_DATABASE_URL='postgresql+psycopg://cdp:cdp-dev-only@127.0.0.1:5432/cdp'
export CDP_REDIS_URL='redis://127.0.0.1:6379/0'
export CDP_BOOTSTRAP_ADMIN_USERNAME=admin CDP_BOOTSTRAP_ADMIN_PASSWORD='change-me-dev-password'

alembic upgrade head
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

In two more terminals, with the same environment, from `backend/`:

```bash
celery -A app.workers.celery_app worker --loglevel=INFO
celery -A app.workers.celery_app beat --loglevel=INFO
```

Frontend, in `frontend/`:

```bash
bun install
bunx vite dev --host 127.0.0.1 --port 5173
```

Requests to `/api` are proxied to `CDP_API_PROXY_TARGET` (default `http://127.0.0.1:8000`).

## Running tests

Backend, in `backend/`:

```bash
.venv/bin/pytest -q
```

Integration tests in `backend/tests/integration` need the disposable target and skip themselves when it cannot be
started. Provision it only in a disposable container, as root:

```bash
bash infra/test-target/setup-local.sh        # sshd :2222, nginx :8443, apache :9443, haproxy :10443
bash infra/test-target/teardown-local.sh     # remove it
```

Frontend, in `frontend/`:

```bash
bunx tsc --noEmit
bun run build
bun run e2e                                  # Playwright, specs in frontend/e2e
```

`frontend/e2e/deploy.spec.ts` needs the backend on `:8000` (with worker, Redis and PostgreSQL), the Vite dev server at
`E2E_BASE_URL` and the disposable target. It replaces the target's nginx certificate and restores it afterwards, so run
it against the disposable target only. Variables are documented in its header: `PW_CHROMIUM_PATH` (system Chromium), `E2E_ADMIN_USER`,
`E2E_ADMIN_PASSWORD`, `E2E_SSH_KEY_FILE`, `E2E_SSH_PORT`, `E2E_SSH_USER`, `E2E_CA_DIR`, `E2E_NGINX_DIR`,
`E2E_NGINX_PORT` and `E2E_SHOTS`.

## Repository layout

```
certlab/
├── backend/             FastAPI API, Celery tasks, SQLAlchemy models, Alembic migrations, pytest suite
│   ├── alembic/         migrations 0001 to 0004
│   ├── app/             api/v1, services, integrations (ssh, tls, certificates, service adapters), workers
│   ├── scripts/         verify_restore.py
│   └── tests/           unit/, integration/, fixtures/
├── frontend/            TanStack Start UI (Vite, Tailwind 4, TanStack Query); e2e/ Playwright specs
├── infra/
│   ├── caddy/           Caddyfile: proxy routes and TLS directive
│   ├── remote-helper/   cdp-helper, install.sh, sudoers rule, example configuration
│   └── test-target/     disposable SSH, nginx, Apache and HAProxy target for tests
├── docs/                documentation (index below)
├── docker-compose.yml   services; only proxy publishes ports
└── .env.example         environment template; copy to .env
```

## Documentation

- [docs/PROGRESS.md](docs/PROGRESS.md): original architecture assessment, work breakdown and progress log.
- [docs/architecture.md](docs/architecture.md): processes, backend layers, data model and job pipeline.
- [docs/installation.md](docs/installation.md): Compose install, TLS modes, upgrades, local development and operations.
- [docs/configuration.md](docs/configuration.md): `CDP_*` environment variables and database-stored settings.
- [docs/security.md](docs/security.md): authentication, RBAC, envelope encryption, host-key policy and threat model.
- [docs/ssh-permissions.md](docs/ssh-permissions.md): managed-target account, sudoers rule and helper configuration.
- [docs/certificate-discovery.md](docs/certificate-discovery.md): discovery workflow, classification, drift and limits.
- [docs/deployment-engine.md](docs/deployment-engine.md): planning, strategies, state machine, steps and verification.
- [docs/rollback.md](docs/rollback.md): automatic rollback, what "verified" means, and the manual recovery runbook.
- [docs/backup-restore.md](docs/backup-restore.md): deployment backups, restore, and platform disaster recovery.
- [docs/api.md](docs/api.md): authentication, CSRF, errors, pagination, idempotency and endpoint list.
- [docs/troubleshooting.md](docs/troubleshooting.md): logs, error codes and failure diagnosis by area.

## Status

Readiness assessment and known limitations: [docs/PROGRESS.md](docs/PROGRESS.md).

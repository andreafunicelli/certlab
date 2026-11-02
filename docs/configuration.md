# Configuration reference

Every variable below was read from source. Defaults are the values in code unless the table says otherwise.
Installation steps are in [installation.md](installation.md); security implications are in [security.md](security.md).

---

## 1. How configuration is read

| Layer | Source | Notes |
|---|---|---|
| Backend settings | Process environment, prefix `CDP_` (`backend/app/core/config.py`, pydantic-settings) | `env_file=None` in `Settings`: the backend does not read `.env` itself. |
| Containers under compose | `.env` via `env_file: .env` on `api`, `worker`, `beat`, `migrate` | Every variable in `.env` becomes a container environment variable. Visible to `docker inspect`. |
| Compose interpolation | `.env` via `${VAR}` references in `docker-compose.yml` | Only variables the compose file references take effect. |
| Application settings | Database table `app_settings`, edited through the API | Section 4. Not environment variables. |

Unknown `CDP_*` variables are ignored (`extra="ignore"`). Settings are cached per process (`lru_cache`).
List values (`CDP_CORS_ORIGINS`, `CDP_OIDC_ADMIN_GROUPS`, `CDP_OIDC_OPERATOR_GROUPS`) accept comma-separated text
or a JSON array.

---

## 2. Backend settings (`CDP_*`, `backend/app/core/config.py`)

### 2.1 Core and secrets

| Variable | Default | Purpose |
|---|---|---|
| `CDP_ENV` | `prod` | `dev`, `prod` or `test`. Only written to the startup log line; it does not change behaviour. |
| `CDP_DATABASE_URL` | `postgresql+psycopg://cdp:cdp-dev-only@127.0.0.1:5432/cdp` | SQLAlchemy URL (psycopg 3). Compose overrides it using `POSTGRES_PASSWORD`. The default password is for local development only. |
| `CDP_REDIS_URL` | `redis://127.0.0.1:6379/0` | Celery broker, rate-limit counters, `/readyz`, and SSE pub/sub. Compose overrides it using `REDIS_PASSWORD`. |
| `CDP_MASTER_KEY` | unset | Base64 of 32 random bytes (the KEK), given inline. Used only when non-empty. Not in `.env.example`; prefer the file form. |
| `CDP_MASTER_KEY_FILE` | unset (compose sets `/run/secrets/cdp_master_key`) | Path to a file containing the base64 KEK. Read at process start. |
| `CDP_ARTIFACT_DIR` | `/var/lib/cdp/artifacts` | Directory for encrypted artifact ciphertext. Created with mode 0700. Compose mounts the `artifacts` volume here. |

The KEK must decode to exactly 32 bytes. Standard or URL-safe base64 is accepted, and surrounding whitespace is
stripped. The API refuses to start without a valid key (`get_vault()` in the lifespan hook).

### 2.2 Sessions and cookies

| Variable | Default | Purpose |
|---|---|---|
| `CDP_SESSION_TTL` | `28800` (8 h) | Upper bound on session lifetime, in seconds. Effective lifetime is `min(security.session_minutes, CDP_SESSION_TTL / 60)`. |
| `CDP_COOKIE_SECURE` | `true` | `Secure` attribute on the session, CSRF and OIDC state cookies. Also turns on the HSTS header from the API. Set `false` only for plain HTTP development. |
| `CDP_COOKIE_DOMAIN` | unset | `Domain` attribute for cookies. |
| `CDP_CORS_ORIGINS` | `[]` | Allowed CORS origins with credentials. Set to your external origin. |
| `CDP_TRUST_PROXY_HEADERS` | `false` | When `true`, the client IP is the first `X-Forwarded-For` value. Used for rate limiting and audit records. Safe only if the API is reachable exclusively through the proxy. `.env.example` sets `true`. |
| `CDP_PUBLIC_BASE_URL` | unset | External base URL. The OIDC redirect URI is `<base>/api/v1/auth/oidc/callback`. |

### 2.3 Bootstrap administrator

| Variable | Default | Purpose |
|---|---|---|
| `CDP_BOOTSTRAP_ADMIN_USERNAME` | unset | Username of the first admin. Used only when the `users` table is empty. |
| `CDP_BOOTSTRAP_ADMIN_PASSWORD` | unset | Password, at least 12 characters. Shorter values are skipped with an error log. Remove after first login. |
| `CDP_BOOTSTRAP_ADMIN_EMAIL` | unset (then `<username>@localhost.invalid`) | Email for the bootstrap account. Not in `.env.example`. |

### 2.4 OIDC (authorization code with PKCE)

OIDC is enabled only when `CDP_OIDC_ISSUER`, `CDP_OIDC_CLIENT_ID` and `CDP_OIDC_CLIENT_SECRET` are all set.
Discovery is read from `<issuer>/.well-known/openid-configuration`.

| Variable | Default | Purpose |
|---|---|---|
| `CDP_OIDC_ISSUER` | unset | Issuer URL, for example a Keycloak realm URL. |
| `CDP_OIDC_CLIENT_ID` | unset | Client ID. The ID token audience must include it. |
| `CDP_OIDC_CLIENT_SECRET` | unset | Client secret. Secret. |
| `CDP_OIDC_SCOPES` | `openid profile email groups` | Requested scopes. |
| `CDP_OIDC_GROUPS_CLAIM` | `groups` | ID-token claim holding group names. |
| `CDP_OIDC_ADMIN_GROUPS` | `[]` | A matching group gives role `admin`. Checked first. |
| `CDP_OIDC_OPERATOR_GROUPS` | `[]` | A matching group gives role `operator`. |
| `CDP_OIDC_AUTO_PROVISION` | `true` | Create a local user record on first login when the token has an email. |

A user with no matching group receives `viewer`. Roles are recalculated and overwritten on every OIDC login.

### 2.5 Rate limiting and logging

| Variable | Default | Purpose |
|---|---|---|
| `CDP_RATE_LIMIT_BACKEND` | `redis` | `redis` or `memory`. A Redis error falls back to the in-process limiter. |
| `CDP_RATE_LIMIT_LOGIN_PER_MINUTE` | `10` | Login attempts per client IP per minute. Each username is limited to `max(3, n // 2)`, which is 5 by default. |
| `CDP_RATE_LIMIT_API_PER_MINUTE` | `600` | Requests per client IP per minute for all `/api/` paths except `/api/v1/healthz`. |
| `CDP_LOG_LEVEL` | `INFO` | Log level for the JSON logger. |

### 2.6 Variables read outside `Settings`

| Variable | Read by | Default | Purpose |
|---|---|---|---|
| `CDP_CELERY_EAGER` | `backend/app/workers/celery_app.py` (via `os.environ`) | unset | `1`, `true` or `yes` runs Celery tasks inline in the calling process. For tests. |
| `CDP_API_PROXY_TARGET` | `frontend/vite.config.ts` | `http://127.0.0.1:8000` | Target for the `/api` proxy in the Vite dev server. Development only. |

---

## 3. Compose and proxy variables (`.env`, interpolated by `docker-compose.yml`)

| Variable | Used by | Default | Required | Purpose |
|---|---|---|---|---|
| `POSTGRES_PASSWORD` | `postgres`, `CDP_DATABASE_URL` | none | yes | Database password. Compose refuses to start without it. |
| `REDIS_PASSWORD` | `redis` (`--requirepass`), `CDP_REDIS_URL` | none | yes | Redis password. Compose refuses to start without it. |
| `CDP_DOMAIN` | `proxy` (site address in the Caddyfile) | `localhost` | recommended | Hostname served by the proxy. `.env.example` sets `certs.example.internal`. |
| `CDP_HTTP_PORT` | `proxy` host port mapping | `80` | no | Host port for HTTP. |
| `CDP_HTTPS_PORT` | `proxy` host port mapping | `443` | no | Host port for HTTPS. |
| `CDP_VERSION` | image tags | `local` | no | Tag for `cert-deploy-pro/backend` and `cert-deploy-pro/frontend`. |
| `CDP_WORKER_CONCURRENCY` | `worker` (`--concurrency`) | `4` | no | Celery worker process count. |
| `CDP_TLS_DIRECTIVE` | `.env` → proxy container | `tls internal` | no | Caddy TLS directive for the console: `tls internal`, `tls <acme-email>`, or `tls <cert> <key>`. See [installation.md](installation.md) section 3.1. |

`CDP_DOMAIN` is the only Caddy input passed by compose. The proxy has no `env_file`.

---

## 4. Application settings (stored in the database)

Four sections live in the `app_settings` table. Read and write them through the API:

- `GET /api/v1/settings` returns all sections.
- `PATCH /api/v1/settings/{section}` with body `{"version": <int>, "data": {...}}`. Requires `settings:write`
  (admin only).

Behaviour from `backend/app/services/settings.py` and `backend/app/schemas/settings.py`:

- **Effective value** = schema defaults, overlaid with stored data. Fields missing from the database take their
  default.
- **Patch semantics**: `data` is deep-merged into the current section, then validated. Unknown fields are rejected
  (`extra="forbid"`). Validation failures return HTTP 422 with `VALIDATION_ERROR`.
- **Concurrency**: `version` must equal the stored version. Otherwise HTTP 409 `SETTINGS_VERSION_CONFLICT`. The
  write is a compare-and-set on the version.
- **Versioning**: the `version` integer is incremented on each successful update. The database keeps no history
  table. The history that exists is the audit trail: each update writes a `SETTINGS_UPDATED` event with `before`
  and `after` snapshots.
- **Seeding**: migration `20261102_0001_initial_schema.py` inserts the four sections at version 1. Its seed omits
  `security.allow_self_approval` and `security.trust_anchors_pem`, so those take schema defaults.

### 4.1 `general`

| Field | Default | Constraints |
|---|---|---|
| `app_name` | `Cert Deploy Pro` | 1 to 64 characters |
| `timezone` | `UTC` | Must be an IANA timezone name |
| `inventory_refresh_minutes` | `360` | 5 to 10080 |
| `backup_retention_days` | `90` | 1 to 3650. Used when a backup is created to set `retention_until`. |

### 4.2 `notifications`

| Field | Default | Constraints |
|---|---|---|
| `thresholds.info` | `60` | 1 to 730 |
| `thresholds.warning` | `30` | 1 to 730 |
| `thresholds.high` | `14` | 1 to 730 |
| `thresholds.critical` | `7` | 1 to 730. Must satisfy `info > warning > high > critical`. |

The thresholds are compared against certificate expiry in the inventory and monitoring services. The unit is
assumed to be days from the field names and ranges; the comparison code was not reviewed line by line.

### 4.3 `security`

| Field | Default | Constraints and effect |
|---|---|---|
| `session_minutes` | `480` | 5 to 43200. Session lifetime, capped by `CDP_SESSION_TTL`. |
| `require_production_approval` | `true` | Deployments to environments flagged production require approval. |
| `reauth_minutes` | `10` | 1 to 240. Window after re-authentication during which sensitive actions are allowed. |
| `allow_self_approval` | `false` | When `false`, the user who initiated a deployment cannot approve it. |
| `trust_anchors_pem` | `""` | Up to 200000 characters. Extra public CA certificates (PEM) used when validating uploads and probing endpoints. Private keys are rejected. |

### 4.4 `ssh`

| Field | Default | Constraints and effect |
|---|---|---|
| `default_port` | `22` | 1 to 65535. Default SSH port for new servers. |
| `connect_timeout` | `10` | 1 to 120 seconds. |
| `command_timeout` | `60` | 1 to 3600 seconds. |
| `deployment_concurrency` | `3` | 1 to 50. Parallel targets in a deployment. |
| `canary` | `true` | Default deployment mode is `canary` when true, otherwise `batch`. |
| `failure_threshold` | `1` | 0 to 100. |
| `discovery_roots` | `/etc/nginx`, `/etc/apache2`, `/etc/httpd`, `/etc/haproxy`, `/etc/ssl`, `/etc/pki`, `/etc/letsencrypt` | Up to 50 absolute paths without `..`. Each must lie inside the helper's `ALLOWED_ROOTS` on the target. A root outside them makes the helper return `PATH_NOT_ALLOWED` (exit 3). The filesystem scan then records a failed service for that job instead of finishing cleanly. |
| `discovery_max_depth` | `6` | 1 to 20 |
| `discovery_max_files` | `2000` | 10 to 100000. Excluded files still count toward this limit, because exclusion is applied after the helper returns results. |
| `discovery_exclude` | `/etc/ssl/certs`, `/etc/pki/ca-trust`, `/usr/share/ca-certificates`, `*/node_modules/*` | Up to 100 entries. Absolute entries without glob characters are path prefixes; entries with `*`, `?` or `[` are shell-style patterns matched on the backend. |

---

## 5. Changing configuration safely

1. Environment variables: edit `.env`, then `docker compose up -d`. Compose recreates only the services whose
   configuration changed.
2. Caddy: edit `infra/caddy/Caddyfile`, then `docker compose restart proxy`.
3. Application settings: change them through the API or UI. Use the current `version` value. Each change is
   audited.
4. Never commit `.env` or `secrets/`.

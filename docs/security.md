# Security model

Scope: how Cert Deploy Pro (CDP) protects operator accounts, stored secrets, SSH access to managed hosts, and its own
network surface, with a threat model and the known gaps.

Basis: this document was written from the source tree as it stands (working tree, with uncommitted changes). It
describes what the code does. **No penetration test, fuzzing, dependency audit or live-IdP test was performed.**
Claims about runtime behaviour that are not confirmed by the repository are marked **(unverified)**.

Related: [configuration.md](configuration.md), [ssh-permissions.md](ssh-permissions.md),
[architecture.md](architecture.md).

---

## 1. Authentication

### 1.1 Local accounts

| Aspect | Behaviour | Source |
|---|---|---|
| Password hashing | argon2id via `argon2-cffi` `PasswordHasher()` with library defaults. Parameters are not set in code. The code comment labels them "RFC 9106 low-memory profile"; that label was not checked against the installed library. The local venv has argon2-cffi 25.1.0. | `core/security.py` |
| Hash on rehash | Re-hashed at login if the library reports the stored hash needs it. | `services/auth.py` |
| Unknown user | A dummy hash is verified so response time does not reveal whether the username exists. | `core/security.py` |
| Password policy | 12 to 256 characters for create and update. No complexity rules and no breached-password check. | `schemas/user.py` |
| Lockout | 5 failed password attempts lock the account for 15 minutes. The counter resets when the lock is set. | `services/auth.py` |
| Rate limits | Per client IP: 10 login attempts per minute. Per username: `max(3, 10 // 2)` = 5 per minute. Both return HTTP 429. | `services/auth.py`, `core/config.py` |
| Error uniformity | Unknown user, wrong password, disabled account and locked account all return `INVALID_CREDENTIALS` (401). | `services/auth.py` |

A wrong TOTP code counts as a failed login and triggers the same temporary account lock as a wrong password.

### 1.2 Sessions

| Aspect | Behaviour |
|---|---|
| Token | `secrets.token_urlsafe(32)`, opaque, returned only in the `cdp_session` cookie. |
| Storage | Only the SHA-256 of the token is stored (`sessions.token_hash`, unique). |
| Lifetime | Absolute. `expires_at` is set at creation and not extended. Effective lifetime is `min(security.session_minutes, CDP_SESSION_TTL / 60)`. Defaults: 480 minutes. |
| Activity | `last_seen_at` is written at most once per 60 seconds. |
| Revocation | Logout; password change (all other sessions of that user); admin password reset; disabling the user; any role change made by another admin. |
| Recorded per session | IP, user agent (300 characters max), created, last seen, expires, revoked, last re-authentication time. |

### 1.3 Cookies

| Cookie | Attributes | Purpose |
|---|---|---|
| `cdp_session` | `HttpOnly`, `Secure` (per `CDP_COOKIE_SECURE`), `SameSite=Lax`, `Path=/`, `Max-Age` = session lifetime | Session token |
| `cdp_csrf` | not `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`, `Max-Age` = session lifetime | CSRF token, read by the frontend |
| `cdp_oidc` | `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/api/v1/auth/oidc`, `Max-Age=600` | Signed OIDC state; deleted after the callback |

Logout deletes `cdp_session` and `cdp_csrf`.

### 1.4 CSRF

- Every authenticated route that uses `get_auth_context` checks CSRF on `POST`, `PUT`, `PATCH` and `DELETE`.
- The request must carry header `X-CSRF-Token`, which must equal the `cdp_csrf` cookie and equal
  `HMAC-SHA256(key, session_token)`. The key is derived from the KEK with label `csrf-v1`. The check is stateless.
- Not covered: `POST /api/v1/auth/login` and the OIDC routes, which do not use `get_auth_context`. Login CSRF was
  not analysed further.

### 1.5 TOTP (optional, per user)

- Setup (`POST /api/v1/auth/mfa/setup`) returns the secret and an `otpauth://` URI. The secret is stored encrypted
  inline with the KEK.
- Enabling requires a valid 6-digit code. Disabling requires the account password.
- Login without a code after a correct password returns `MFA_REQUIRED` (401). This reveals that MFA is enabled,
  but only after the password is correct.
- No organisation-wide MFA enforcement was found in the reviewed code.

### 1.6 OIDC (authorization code with PKCE)

Enabled only when issuer, client ID and client secret are all set (see [configuration.md](configuration.md)).

- Login start: random `state`, `nonce` and PKCE verifier. The verifier and nonce are kept in an HMAC-signed,
  10-minute state cookie (key derived with label `oidc-state`). PKCE method is `S256`.
- Callback: state compared in constant time. Token exchange uses the client secret with HTTP Basic. The ID token is
  verified with Authlib against the IdP's JWKS, then `claims.validate()` runs. The code also checks `iss` against
  the discovery document, that `aud` contains the client ID, and that `nonce` matches.
- Failures return the generic `OIDC_LOGIN_FAILED` (401) and write an audit event.
- Discovery documents are cached in-process for 10 minutes. JWKS is fetched on every login.
- Role mapping: a group in `CDP_OIDC_ADMIN_GROUPS` gives `admin`; otherwise a group in
  `CDP_OIDC_OPERATOR_GROUPS` gives `operator`; otherwise `viewer`. Roles are overwritten on every login, so removing
  a user from an IdP group takes effect at the next login.
- Provisioning: a new user requires an email in the token (`OIDC_USER_NOT_PROVISIONED` otherwise). If a local
  account already uses that email, login fails with 409 `OIDC_EMAIL_CONFLICT`. Accounts are not linked
  automatically.

**Gap:** the OIDC flow has not been tested against a live identity provider. No automated test in `backend/tests`
references OIDC.

### 1.7 Re-authentication for sensitive actions

`POST /api/v1/auth/reauth` takes the password (plus TOTP if MFA is enabled) and sets `sessions.reauth_at`. Routes
marked reauth require `reauth_at` within `security.reauth_minutes` (default 10). A new session starts with
`reauth_at` set to login time, so a fresh login satisfies the requirement for that window. Failed re-auth is
audited as `REAUTH_FAILED`.

| Route | Permission | Re-auth |
|---|---|---|
| `POST /api/v1/credentials` (create SSH credential) | `credentials:write` | yes |
| `POST /api/v1/credentials/{id}/rotate` | `credentials:write` | yes |
| `DELETE /api/v1/credentials/{id}` | `credentials:write` | **no** |
| `POST /api/v1/deployments/{id}/approve` | `deployments:approve` | yes |
| `POST /api/v1/deployments/{id}/targets/{tid}/rollback` | `deployments:rollback` | yes |
| `POST /api/v1/backups/{id}/restore` | `backups:restore` | yes |
| `GET /api/v1/backups/{id}/download` | `backups:download` | yes |

---

## 2. Authorization (RBAC)

`require_permission(name, reauth=...)` (`api/deps.py`) checks: session present, CSRF valid for unsafe methods,
account enabled, and the role grants the permission. A denial raises 403 `FORBIDDEN` with `required_permission`
and writes an `ACCESS_DENIED` audit event. Permissions come from `backend/app/core/permissions.py`. The table below
is copied from that file: `viewer`, `operator` and `admin` columns show which roles hold each permission.

| Permission | viewer | operator | admin |
|---|:-:|:-:|:-:|
| `dashboard:read` | yes | yes | yes |
| `servers:read` | yes | yes | yes |
| `environments:read` | yes | yes | yes |
| `certificates:read` | yes | yes | yes |
| `installations:read` | yes | yes | yes |
| `discovery:read` | yes | yes | yes |
| `versions:read` | yes | yes | yes |
| `deployments:read` | yes | yes | yes |
| `backups:read` | yes | yes | yes |
| `logs:read` | yes | yes | yes |
| `audit:read` | yes | yes | yes |
| `settings:read` | yes | yes | yes |
| `servers:test` | | yes | yes |
| `discovery:run` | | yes | yes |
| `certificates:verify` | | yes | yes |
| `installations:verify` | | yes | yes |
| `versions:upload` | | yes | yes |
| `deployments:plan` | | yes | yes |
| `deployments:create` | | yes | yes |
| `deployments:cancel` | | yes | yes |
| `deployments:retry` | | yes | yes |
| `installations:write` | | yes | yes |
| `users:read` | | | yes |
| `users:write` | | | yes |
| `users:roles` | | | yes |
| `credentials:read` | | | yes |
| `credentials:write` | | | yes |
| `servers:write` | | | yes |
| `servers:hostkey` | | | yes |
| `environments:write` | | | yes |
| `settings:write` | | | yes |
| `deployments:approve` | | | yes |
| `deployments:rollback` | | | yes |
| `backups:restore` | | | yes |
| `backups:download` | | | yes |
| `notifications:read` | | | yes |
| `notifications:write` | | | yes |

Totals: viewer 12, operator 22, admin 37. The admin role lists its permissions explicitly. The code also honours a
wildcard `*` in `has_permission`, but no role grants it.

Other enforced rules:

- Deployment approval: a deployment is blocked for approval when its environment has `requires_approval`, or when
  `security.require_production_approval` is true and the environment is production. The initiator cannot approve
  unless `security.allow_self_approval` is true (default false).
- Last-admin guard: the last enabled admin cannot be disabled, deleted or demoted. Users cannot disable or delete
  their own account.

---

## 3. Stored secrets: envelope encryption

Design from `backend/app/core/crypto.py`.

### 3.1 Keys

| Key | Source | Use |
|---|---|---|
| KEK (master key) | `CDP_MASTER_KEY` or `CDP_MASTER_KEY_FILE`. Compose mounts `./secrets/cdp_master_key` at `/run/secrets/cdp_master_key` in `api`, `worker`, `beat` and `migrate`. | Wraps per-artifact DEKs and encrypts inline values. Never stored in PostgreSQL. |
| `key_id` | First 16 hex characters of SHA-256(KEK). | Recorded with each artifact and inline value to identify the KEK. It is not secret. |
| DEK | Random 256-bit key per artifact, generated with `AESGCM.generate_key`. | Encrypts one artifact with AES-256-GCM. |
| Derived keys | `HMAC-SHA256(KEK, "cdp-derive:" + label)`. Labels: `csrf-v1`, `oidc-state`. | Domain-separated keys for CSRF and OIDC state. |

### 3.2 Artifacts

Stored artifact purposes: `ssh_private_key`, `certificate_pem`, `certificate_chain`, `certificate_private_key`,
`backup`.

Write path (`Vault.store`):

1. Generate DEK and a 96-bit nonce. Encrypt plaintext with AES-256-GCM, AAD = `"<artifact_id>|<purpose>"`.
2. Wrap the DEK with the KEK using AES-256-GCM, AAD = `"<artifact_id>|dek"`. Stored as nonce || ciphertext.
3. Write ciphertext to `<artifact_dir>/<artifact_id>.bin` with mode 0600, via a temporary file, `fsync` and rename.
   The directory is mode 0700.
4. Insert `encrypted_artifacts`: purpose, `key_id`, `wrapped_dek`, `nonce`, `sha256_plain`, size, filename.
5. If the database insert fails, the ciphertext file is removed.

Read path (`Vault.load`): unwrap the DEK, decrypt, which checks the GCM tag, then compare SHA-256 of the plaintext
with the stored hash. Mismatch raises `ArtifactIntegrityError`.

Delete path: overwrite the file with random bytes, unlink it, mark the row deleted and blank `wrapped_dek`. The
overwrite is best-effort: it does not guarantee erasure on copy-on-write, journaled or SSD storage.

### 3.3 Inline values

`v1:<key_id>:<base64(nonce || ciphertext)>`, AES-256-GCM with AAD `cdp-inline-v1`. Used for SSH key passphrases,
TOTP secrets and notification channel secrets.

### 3.4 Properties and limits

- A database dump alone cannot decrypt artifacts or inline values, because DEKs are wrapped by the KEK.
- Ciphertext files, the database and the KEK are together sufficient. On a single VM these usually sit on the same
  host. The design protects against a stolen database backup, not against host compromise.
- No KEK rotation or re-wrap function was found in `core/crypto.py`. Rotating the KEK means a migration that does
  not exist in this repository.
- The KEK is held in memory by `api`, `worker` and `beat`. Mode and ownership of the secret file inside the
  container were not verified **(unverified)**.

---

## 4. Secrets in responses, logs and audit

- **Responses.** Credential responses contain the fingerprint, public key, algorithm and a `has_passphrase` flag.
  Private keys and passphrases are never returned. Stored SSH keys are not readable through the API. Backup download
  returns backup content and is restricted to admins with re-auth.
- **Logs.** structlog JSON output passes through a redaction processor. Keys matching
  `password|passwd|passphrase|private[_-]?key|secret|token|authorization|cookie|api[_-]?key|credential_pem|csrf`
  are replaced with `[REDACTED]` (boolean values are kept). Any string containing a PEM block has the block replaced
  with `[REDACTED PEM]`. Bytes become `[BINARY]`. Nesting is limited to 12 levels.
- **Audit.** `before` and `after` snapshots pass through the same redaction. Error text is redacted and truncated to
  2000 characters. Audit records carry IP, user agent, correlation ID, outcome and error.
- **SSH errors.** Messages from the SSH layer pass through `sanitize_output` before being stored or returned.
- **Limit.** Redaction is pattern-based on key names and PEM markers. It does not inspect arbitrary free text. The
  reviewed code does not show every call site, so leakage through a differently named field is possible
  **(unverified)**.
- **Environment variables.** Secrets in `.env` are visible in every backend container's environment. Remove the
  bootstrap password after first login.

---

## 5. Rate limiting

Redis fixed-window counters (`core/ratelimit.py`), keys `cdp:rl:<scope>:<window>`.

| Scope | Limit | Behaviour when exceeded |
|---|---|---|
| Login per IP | 10 per minute | 429 `RATE_LIMITED` with `Retry-After` |
| Login per username | 5 per minute | 429 `RATE_LIMITED` |
| All `/api/` per IP, except `/api/v1/healthz` | 600 per minute | 429 `RATE_LIMITED` |

If Redis is unreachable, the limiter logs a warning and uses an in-process counter. That counter is per process, so
the effective limit grows with the number of processes. Set `CDP_RATE_LIMIT_BACKEND=memory` only for development.

---

## 6. HTTP headers and CORS

| Header | API (`SecureHeadersMiddleware`) | Proxy (Caddy) |
|---|---|---|
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`. For `/api/docs` and `/api/redoc`: a relaxed policy that allows scripts and styles from `cdn.jsdelivr.net`. | not set |
| `X-Content-Type-Options` | `nosniff` | `nosniff` |
| `X-Frame-Options` | `DENY` | `DENY` |
| `Referrer-Policy` | `no-referrer` | `no-referrer` |
| `Permissions-Policy` | `geolocation=(), microphone=(), camera=()` | not set |
| `Cache-Control` | `no-store` on `/api/` paths (not docs) | not set |
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains`, only when `CDP_COOKIE_SECURE` is true | `max-age=31536000; includeSubDomains` |
| `Server` | not removed | removed |

CORS: `allow_credentials=true`; origins from `CDP_CORS_ORIGINS`; allowed methods GET, POST, PUT, PATCH, DELETE,
OPTIONS; allowed request headers `Content-Type`, `X-CSRF-Token`, `X-Correlation-ID`, `Idempotency-Key`.

**Exposure:** `/api/docs` (Swagger UI) and `/api/v1/openapi.json` are always served. No setting turns them off.
Anyone who can reach the proxy can read the full API schema. The proxy does not block these paths. Frontend
responses were not reviewed beyond what Caddy adds.

Correlation IDs: `X-Correlation-ID` from the client is accepted if it matches `[A-Za-z0-9._-]{8,64}`; otherwise a
new one is generated. The ID is echoed in responses and attached to logs and audit records.

---

## 7. Network exposure and container hardening

### 7.1 Exposure

| Service | Published to host | Notes |
|---|---|---|
| `proxy` | `CDP_HTTP_PORT` (80), `CDP_HTTPS_PORT` (443) | The only published service. |
| `postgres`, `redis`, `api`, `worker`, `beat`, `frontend` | no | Reachable from other containers on the `internal` network. |

The `internal` network is declared without `internal: true`. Containers can therefore open outbound connections,
which the worker needs for SSH. The compose file does not restrict egress. All services share one network, so
Postgres and Redis are reachable from `frontend` and `proxy` as well. Redis requires a password and runs with
`--protected-mode yes`. Postgres uses password authentication and no TLS is configured in the compose file.

### 7.2 Container settings (from `docker-compose.yml` and Dockerfiles)

| Service | Image | User | Read-only root | `cap_drop` | `no-new-privileges` | `/tmp` |
|---|---|---|:-:|:-:|:-:|---|
| `api`, `worker`, `beat`, `migrate` | built from `backend/Dockerfile` (python:3.12-slim-bookworm) | `cdp` (uid 10001, non-root) | yes | ALL | yes | tmpfs |
| `frontend` | built from `frontend/Dockerfile` (node:22-bookworm-slim) | `node` | yes | ALL | yes | tmpfs |
| `postgres` | postgres:16-alpine | image default | not set | not set | not set | n/a |
| `redis` | redis:7-alpine | image default | not set | not set | not set | n/a |
| `proxy` | caddy:2-alpine | image default | not set | not set | not set | n/a |

Base images are referenced by tag, not digest. Memory limits are set on every service except `migrate` and `proxy`.
In the backend containers the only writable paths are the `artifacts` volume and the `/tmp` tmpfs.

---

## 8. SSH host-key policy

Implementation: `integrations/ssh/hostkeys.py`, `connection.py`, `services/connectivity.py`.

- Each server stores its enrolled host key (`host_public_key`, type, fingerprint, enrolled-at and enrolled-by).
- Every SSH connection builds a `known_hosts` entry containing only the enrolled key, for `host` (port 22) or
  `[host]:port` (other ports). `known_hosts=None` is never used. A server with no enrolled key fails with
  `HOST_KEY_UNKNOWN` before any authentication attempt.
- Scanning the key (`POST /api/v1/servers/{id}/host-key/scan`) does not authenticate and does not connect with the
  stored credential. It returns key type, SHA-256 fingerprint and public key for the admin to check.
- Enrollment (`POST /api/v1/servers/{id}/host-key/enroll`, permission `servers:hostkey`, admin only) re-scans the
  server. The posted public key and fingerprint must both match the fresh scan. Otherwise 409
  `HOST_KEY_CHANGED_DURING_ENROLL`. Replacing an already-enrolled different key requires `replace: true`, or the
  request fails with 409 `HOST_KEY_ALREADY_ENROLLED`. Every attempt writes an audit event
  (`HOST_KEY_ENROLLED`, `HOST_KEY_REPLACED` or a failure event).
- A key that later differs from the enrolled one produces `HOST_KEY_MISMATCH`. The server's connection status becomes
  `host_key_mismatch`. Discovery writes a `HOST_KEY_CHANGED` audit event.
- Client settings: public-key authentication only; no agent; no password or keyboard-interactive; `~/.ssh/config`
  ignored (`config=[]`); keepalive every 15 seconds.
- **Notifications on host-key events:** `docs/PROGRESS.md` says a notification is sent. No notification trigger for
  host-key events was found in the reviewed code **(unverified)**.

Trust depends on the admin confirming the fingerprint out of band before enrolling. The backend cannot detect a
man-in-the-middle during the first scan.

---

## 9. The remote helper: privilege boundary on managed hosts

Details of installation and each operation are in [ssh-permissions.md](ssh-permissions.md). This section covers the
security properties.

- **Sudo rule.** `cdpdeploy ALL=(root) NOPASSWD: /usr/local/libexec/cdp-helper`. It is not `NOPASSWD: ALL`. It is,
  however, not argument-restricted: any arguments are allowed. The helper's own validation is the only control on
  what those arguments do.
- **Client side.** The backend builds argv as `sudo -n /usr/local/libexec/cdp-helper <subcommand> <args>`. Each
  element is passed through `shlex.quote`. Subcommands are checked against a fixed set (14 entries). No remote or
  user string is interpolated into a shell line.
- **Helper side.** POSIX `sh` with `set -eu` and `umask 077`. Refuses to run unless UID is 0 (except `version`).
  Reads `/etc/cdp-helper.conf` only if it is a root-owned regular file with an allowed mode. Path rules: absolute,
  no control characters or newlines, no `..` component, canonicalised with `realpath -m`, and the canonical path must
  lie under `ALLOWED_ROOTS`. Symlinks are resolved before the check. Staging paths must be direct children of the
  staging root.
- **Private key exposure.** Only some paths can return key material:
  - `backup PATH` returns the raw bytes of any regular file under `ALLOWED_ROOTS`, up to 10 MiB. This includes private
    keys. The backend uses it for backups, which are stored encrypted, and for in-memory planning.
  - `read-public` refuses files containing `PRIVATE KEY` and files named `*.key`, `*.p12`, `*.pfx`, `*.jks`.
  - `stat` returns the SHA-256 of any readable regular file, including private keys. Hashes, not content.
  - `find` reads the first 2 MiB of candidate files to classify them. It reports only the classification.
- **Staging.** Plaintext key material is written to a 0700 root-owned staging directory under
  `/var/lib/cdp-helper/staging` during deployments, and removed by `cleanup`.
- **Install mode.** `install` accepts modes of 3 or 4 octal digits. Setuid and setgid bits are not rejected. The
  planner takes the mode from the observed target file, so an operator does not choose it, but the helper would
  accept it **(hardening item)**.
- **Race window.** Path checks are performed before the operation they guard. Between a check and an action, a local
  user with write access to an allowed directory could change what a symlink points to. Not formally assessed.
- **Not a sandbox.** Once the sudo rule is used, the helper can read or overwrite any file under `ALLOWED_ROOTS`
  and control `nginx`, `apache` and `haproxy`. The default roots include `/opt` and `/usr/local/etc`, which are broad.
  Narrow them (see [ssh-permissions.md](ssh-permissions.md)).
- **Login shell.** `install.sh` creates `cdpdeploy` with `/bin/sh` as its shell. Without sudo, the account can run
  any command as itself. The sudo rule does not restrict the account's own shell.

---

## 10. Threat model

Each entry lists impact, mitigations present in the code, and residual risk.

### T1. Compromised administrator

- **Impact.** Full control of CDP: credentials and their use, deployments (approval included, if a second admin
  approves), settings (including turning off production approval), user roles, backups (including download of
  backed-up private keys), and through the helper, overwriting files on any managed host within `ALLOWED_ROOTS`.
- **Mitigations present.** Re-auth for credential creation and rotation, approval, rollback, backup download and
  restore. Self-approval off by default. Last-admin guard. Sessions revoked on role change. Audit of settings,
  credentials, roles and host keys, with before and after values.
- **Residual risk.** Re-auth is a password prompt on an authenticated session, not a second factor unless the user
  enabled TOTP. Audit records live in the same database and have no hash chain (the `AuditEvent` model has no
  integrity field), so an attacker with database write access can alter them. Credential delete is not re-auth gated.

### T2. Stolen SSH credentials (the CDP key or the `cdpdeploy` account)

- **Impact.** Whoever holds the private key can log in as `cdpdeploy` on every host authorised with it. The account
  has a login shell. Through sudo, the helper can read allowed-root files, including private keys, and overwrite
  certificates and service configuration.
- **Mitigations present.** Keys are stored encrypted and never returned by the API. Passphrases are encrypted inline.
  Key-only login; the account has no password. Host-key pinning limits network impersonation. The helper validates
  every path.
- **Residual risk.** One credential can be attached to many servers (`server_count`), so one key compromise affects
  all of them. Nothing restricts the account's shell or the key's source address in `authorized_keys`. Rotation exists
  (`POST /api/v1/credentials/{id}/rotate`, re-auth required) but is manual. The bastion uses the same credential for
  its hop (see section 11).

### T3. Malicious uploads (certificate, chain, private key, PKCS#12, PEM)

- **Impact.** A crafted file could crash or stall the API or a worker (denial of service), or pass validation and be
  deployed as a broken or misleading certificate.
- **Mitigations present.** Upload size cap of 256 KiB per uploaded part (`MAX_INPUT_BYTES`), plus the proxy's 2 MB
  limit for `/api/*`. Uploads require `versions:upload` (operator or admin). Uploaded keys are stored encrypted.
  Before activation, the deployment validate step checks the leaf fingerprint and that the key matches the
  certificate, and it compares the staged file's SHA-256 with the plan. Chain and validity findings are produced
  at upload time by the certificate validation code, which was not reviewed in full.
- **Residual risk.** No fuzzing harness exists in the repository. Parser robustness rests on the `cryptography`
  library and in-house PEM and PKCS#12 handling that was not fuzzed. A chain that validates cryptographically may
  still be wrong for the intended service; the admin reviews findings before deploying.

### T4. Compromised worker

- **Impact.** The worker holds the KEK, decrypts artifacts, has SSH keys in memory during jobs, and can issue any
  helper command on any host with a credential. Impact equals a compromised API.
- **Mitigations present.** Non-root, read-only, no-new-privileges, all capabilities dropped, no published ports.
  Deployments checkpoint state, use durable locks with expiry, and verify rollback. Helper path rules still apply.
- **Residual risk.** The worker and API share one trust domain and the KEK. The broker is Redis with a password.
  Anyone holding the Redis password can enqueue arbitrary jobs by name. Tasks carry IDs, not commands, but the broker
  is not separately authenticated per message.

### T5. Compromised database dump without the KEK

- **Impact.** Exposure of user accounts (argon2id hashes, enabling offline guessing), session token hashes (not
  directly usable), TOTP secrets and passphrases (encrypted), wrapped DEKs (useless without the KEK), host inventory,
  certificate metadata, public keys and audit history.
- **Mitigations present.** Envelope encryption with the KEK outside PostgreSQL. Session tokens hashed. argon2id.
  Audit values redacted.
- **Residual risk.** The protection holds only if the KEK is not in the same place as the dump. On a single VM with
  the compose volumes, a copy of the database volume and the KEK file are often together. Password hashes and
  inventory are exposed regardless of the KEK.

### T6. Compromised or untrusted remote server (and bastion)

- **Impact.** A target controls its own configuration text, file listings and command output, which CDP parses. It
  receives its own deployed private key and can use it. A deployed key reused on other servers spreads the exposure.
  A compromised bastion sees and forwards the target hop; it cannot obtain the key itself, but it holds the same
  credential's access to the bastion.
- **Mitigations present.** Output size caps (16 MiB stdout default, 64 KiB stderr) and JSON parsing with error
  classification. Error text is sanitised. Verification after deployment checks file fingerprints on disk and a live
  TLS probe from the backend. Rollback checks the hashes of restored files against the backup manifest. The target cannot choose which paths CDP writes
  (the helper enforces `ALLOWED_ROOTS`).
- **Residual risk.** A target that lies in its verification output can pass its own checks. Parsing untrusted text
  (for example `nginx -T` output) is a parser-robustness risk. The bastion reuses the target credential (section 11).

### T7. Network attacker

- **Impact.** Man-in-the-middle on operator access, on SSH to targets, or on the IdP connection. Credential stuffing,
  and TOTP guessing.
- **Mitigations present.** HTTPS (see [installation.md](installation.md) for the TLS mode actually configured). Secure,
  HttpOnly session cookies. Host-key pinning on SSH. OIDC PKCE, state and nonce checks, and ID-token verification.
  Login rate limits and lockout.
- **Residual risk.** The shipped proxy uses Caddy's internal CA, so operators must distribute the CA root to clients,
  or the first connection is unverified. TOTP guessing is limited only by rate limits (section 1.1). The first SSH
  scan trusts whatever key the network presents until the admin confirms the fingerprint.

---

## 11. Known gaps and open items

Stated plainly, from the review. None of these is fixed by configuration alone.

| # | Gap | Where | Status |
|---|---|---|---|
| 1 | OIDC not tested against a live identity provider. No automated OIDC tests. | `services/oidc.py`, `backend/tests` | Open |
| 2 | The systemd branch of `reload` (`systemctl reload` and `restart`) is untested. The repository has no CI configuration (no `.github` directory). No test drives the systemctl path. The disposable target has no systemd. | `infra/remote-helper/cdp-helper` | Open |
| 3 | The bastion reuses the target's credential for its hop. | `services/connectivity.py` `build_target`, `integrations/ssh/connection.py` `open_connection` | Open |
| 4 | Wrong TOTP codes did not trigger the account lock. | `services/auth.py` `login` | Fixed |
| 5 | No KEK rotation or re-wrap. | `core/crypto.py` | Open |
| 6 | Audit trail has no integrity chain. | `models/audit.py`, `services/audit.py` | Open |
| 7 | Helper `install` accepts setuid and setgid mode bits. | `infra/remote-helper/cdp-helper` `cmd_install` | Open |
| 8 | `CDP_TLS_DIRECTIVE` was not wired into compose. | `infra/caddy/Caddyfile`, `docker-compose.yml` | Fixed |
| 9 | API docs and OpenAPI schema are always exposed through the proxy. | `main.py` | Open |
| 10 | Single compose network without `internal: true`; no egress restriction; no TLS to PostgreSQL. | `docker-compose.yml` | Open |
| 11 | Backend dependencies are declared with lower bounds only (`pyproject.toml`), and no backend lock file exists in the repository. Base images are not pinned by digest. | `backend/pyproject.toml`, Dockerfiles | Open |
| 12 | No fuzzing of certificate and key parsers. | `integrations/certificates` | Open |
| 13 | Host-key notification described in `PROGRESS.md` not found in code. | `docs/PROGRESS.md` | Unverified |
| 14 | Backup retention purge is scheduled daily; its effect on private-key backups has not been tested. | `workers/deploy_tasks.py` | Unverified |
| 15 | Login-endpoint CSRF was not analysed. | `api/v1/auth.py` | Not analysed |
| 16 | Frontend response headers were not reviewed beyond what Caddy adds. | `frontend/` | Not analysed |
| 17 | No penetration test has been performed. | n/a | Not done |

---

## 12. Reporting

The repository has no `SECURITY.md` or other security-contact file. Establish a private reporting channel before the
software is distributed to others.

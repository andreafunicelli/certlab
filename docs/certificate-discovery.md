# Certificate discovery

How Cert Deploy Pro (CDP) finds certificates on a managed server, how each finding is classified, how repeated runs keep
the inventory stable, and what discovery cannot see.

Basis: source at commit `a353f1e` (backend, `infra/remote-helper`, `docs` and `docker-compose.yml` had no uncommitted
changes). The two live tests, `backend/tests/integration/test_discovery_live.py` and the parser and discovery unit tests,
were read for what they assert. **No test was run for this page.** Behaviour that rests on reading alone is stated as
such. Anything not confirmed by running is marked **(unverified)**. Known defects are marked **Known issue**.

Related: [architecture.md](architecture.md) (job pipeline), [ssh-permissions.md](ssh-permissions.md) (what the helper may
read), [deployment-engine.md](deployment-engine.md) (what happens to classified installations),
[configuration.md](configuration.md) (`ssh` and `general` settings).

---

## 1. Principles

- Discovery is read-only. It never writes to the target.
- Private keys are never read. A key file is only `stat`-ed for existence. Combined PEM files (certificate and key in one
  file) are read through the live TLS endpoint instead. The helper refuses any file that contains `PRIVATE KEY` text
  (`services/discovery.py` module docstring; `infra/remote-helper/cdp-helper`, `cmd_read_public`).
- Only public certificate data is stored: subject, SANs, fingerprints, validity, chain, and the PEM of the leaf.

---

## 2. Workflow

1. **Start.** One of three entry points creates a `discovery_jobs` row:
   - `POST /api/v1/servers/{id}/discover` (202). Requires `discovery:run`.
   - `POST /api/v1/discovery-jobs/bulk` with up to 200 `server_ids` (202). Per-server refusals come back in `errors`.
   - Beat task `discovery.schedule_all`, every 5 minutes. It selects enabled servers that have a credential and an
     enrolled host key, whose `last_discovery_at` is empty or older than `general.inventory_refresh_minutes` (default 360,
     range 5 to 10080). It takes the oldest first, up to 200 per tick, with no requesting user.
2. **Job creation** (`create_job`). It returns 409 `SERVER_DISABLED` for a disabled server. It returns 409
   `DISCOVERY_ALREADY_RUNNING` if a `pending` or `running` job exists for the server. A job with no progress for 30 minutes
   is set to `failed` with the text `abandoned: no progress for 30 minutes` the next time a job is requested for that
   server.
3. **Enqueue** (`discovery.run`). If the broker call fails, the job is marked `failed` with `QUEUE_UNAVAILABLE` and the
   API returns 503.
4. **Execution** (`execute_job`, Celery). The job row is locked with `SELECT ... FOR UPDATE`. A job that another worker
   started less than 30 minutes ago is skipped. For a manual job, the requesting user's `discovery:run` permission is
   checked again. The SSH target is built, the credential is decrypted in memory, and `collect()` runs under a 20-minute
   timeout (`JOB_TIMEOUT_SECONDS`).
5. **Collection** (`collect`):
   - `probe`: helper `probe` (OS, kernel, installed services, helper version) plus `id -un`.
   - For each installed service (`nginx`, `apache`, `haproxy`): helper `dump <service>`, the parser for that service, then
     `resolve()` for each certificate reference.
   - Filesystem scan across the configured roots.
   - Deduplication by `(service_type, cert_path, vhost)`. The first entry wins.
6. **Persistence** (`persist_collection`, one transaction). Certificates are upserted by SHA-256 fingerprint, installations
   by identity key (section 6), findings are written to `discovery_findings`, and installations no longer seen are marked
   missing (section 7). Notifications are sent for drift and failures.
7. **Result.** `completed`, `partial` (at least one service or the filesystem scan failed; the rest is saved), or
   `failed`. Progress is published on Redis pub/sub and streamed from `GET /api/v1/discovery-jobs/{id}/events`. The
   stream is advisory. The database is the source of truth.

### 2.1 Job error codes (`discovery_jobs.error`, format `CODE: message`)

| Code | When |
|---|---|
| `AUTHORIZATION_REVOKED` | The requesting user is missing or lost `discovery:run` before execution. |
| `SERVER_NOT_FOUND`, `SERVER_DISABLED` | Server deleted or disabled after the job was queued. |
| `SERVER_HAS_NO_CREDENTIAL`, `SSH_UNAVAILABLE` | Raised by `connectivity.load_credential` and the SSH import (`_import_ssh`). |
| `HOST_KEY_MISMATCH`, `HOST_KEY_UNKNOWN`, `AUTH_REJECTED`, `TIMEOUT`, `CONNECTION_REFUSED`, `DNS_FAILURE`, `UNKNOWN` | A `RemoteErrorCode` raised while connecting. See [troubleshooting.md](troubleshooting.md). |
| `TIMEOUT` | The 20-minute job timeout expired (`discovery timed out`). |
| `UNEXPECTED_ERROR` | Any other exception in collection. The traceback is logged, not stored. |
| `PERSIST_FAILED` | The collected results could not be saved. The transaction is rolled back. |

A `HOST_KEY_MISMATCH` also writes an audit event `HOST_KEY_CHANGED` and a critical `hostkey.changed` notification.
`TIMEOUT`, `CONNECTION_REFUSED`, `DNS_FAILURE` and `AUTH_REJECTED` also produce `server.unreachable`.

---

## 3. Per-service configuration discovery

The helper returns the configuration as text. The parser is pure (no I/O). Helper and parser details are in
`infra/remote-helper/cdp-helper` (`cmd_dump`) and `backend/app/integrations/services/parsers/`.

### 3.1 nginx

Source: `nginx -T` (helper `dump nginx`). If `nginx -T` exits non-zero, the helper exits 9 and nginx is recorded as a
failed service (`partial` job). The dump is not filtered by `ALLOWED_ROOTS`. `nginx -T` prints every file nginx loaded.
Only parsed references are stored.

| Handled | Not handled |
|---|---|
| `include` with globs, expanded from the dump. Recursion limit 10. | Variables (`$name`, `${name}`) in a certificate or key path. Result: `unsupported`, confidence 0. |
| Server blocks under `http` and `stream`, and a top-level `server` in a fragment. | `ssl_certificate` directives in `location`, `map` or other contexts. They are not walked. |
| `ssl_certificate` and `ssl_certificate_key` inherited from `http`/`stream` when the server omits them. | `include` whose path contains a variable. It is dropped silently. |
| Key and certificate paired by position within a server. | |
| Listen ports. Only `ssl`/`quic` listeners are kept, or all listeners when a server has none marked `ssl` (`ssl on` applies to the server). | |

Confidence is 1.0 for a resolved reference and 0.0 when a variable is present.

### 3.2 Apache

Source: helper `dump apache`. It runs `apachectl -t -D DUMP_INCLUDES` for the list of included files and `-V` for
`HTTPD_ROOT`. Included files outside `ALLOWED_ROOTS` are skipped and a `# skipped ...` comment is written into the dump.

| Handled | Not handled / reduced confidence |
|---|---|
| `Include` and `IncludeOptional`, expanded from the dump. | `${VAR}` that is not defined by an earlier `Define`. Result: `unsupported`, confidence 0. |
| `ServerRoot`, `Define`, `Undefine`, applied in file order. | Define order is positional. A `Define` that follows its use does not expand it. |
| `VirtualHost` blocks with `ServerName`/`ServerAlias`. | `IfDefine` and other `If*` sections other than `IfModule`. Bodies are read for both branches, and confidence is capped at 0.8. |
| `IfModule` not negated: confidence 1.0. | Whether the module is actually loaded is not checked. An `IfModule` body is treated as active. |
| `SSLEngine off`: no reference. | `SSLEngine` absent with no own certificate: no reference. Absent with its own certificate: confidence times 0.5. |
| `SSLCertificateChainFile` becomes `chain_path`. | Without `SSLCertificateKeyFile` the entry is treated as combined PEM (`is_combined_pem`). |
| Global `SSLCertificateFile` is used only if no virtual host produced a reference. | |

### 3.3 HAProxy

Source: helper `dump haproxy`, which reads `HAPROXY_CFG` (default `/etc/haproxy/haproxy.cfg`) and `HAPROXY_EXTRA_CFG`
(a file or a directory of `*.cfg`, one level deep). Files outside `ALLOWED_ROOTS` are skipped.

| Handled | Not handled |
|---|---|
| `bind ... ssl crt <path>` in `frontend` and `listen` sections. | `crt-list` files. The `crt-list` line is reported as `unsupported` with confidence 0.2. |
| `crt-base` from `global`, applied to relative paths. | `bind` lines in `defaults`/`backend`, and `server ... crt` lines. |
| `default-crt` is treated like `crt`. | Variables. Result: `unsupported`, confidence 0. |
| `crt <dir>` (trailing `/`, or no file extension) is a directory: `requires_mapping`, confidence 1.0 with a trailing `/` and 0.7 without. | Contents of a directory are not enumerated. |

HAProxy certificate files are always treated as combined PEM (`is_combined_pem = true`). The key is not stat-ed. See
section 4.5 for how that file is read.

---

## 4. Path resolution and file reading

### 4.1 Allowed roots

The helper canonicalises every path (`realpath -m`, symlinks resolved) and requires it to be one of `ALLOWED_ROOTS` or
below one. Default roots are `/etc/ssl /etc/pki /etc/nginx /etc/apache2 /etc/httpd /etc/letsencrypt /etc/haproxy /opt
/usr/local/etc`. A symlink that points outside the roots gets `PATH_NOT_ALLOWED` (exit 3). Discovery records that as
`unreadable`. Changing the roots is covered in [ssh-permissions.md](ssh-permissions.md) section 4.

### 4.2 stat and symlinks

Every referenced path is `stat`-ed by the helper (`stat_json`). The result includes `file_type`, `realpath`,
`symlink_target`, `broken_symlink`, `mode`, `owner`, `group`, `size`, a SHA-256 of the real file, and `readable`. The
result is stored in `file_metadata` (`cert_stat`, `chain_stat`, `key_stat`).

- A **broken symlink** yields classification `error` with the message `broken symlink -> <target>` and the note
  `broken_symlink`.
- A **missing file** yields `error` (`certificate file does not exist`). A **directory** yields `error`.
- The stored fingerprint is that of `realpath`. A symlink is therefore reported with the same fingerprint as its target.

### 4.3 certbot

`is_certbot_path` is true when the configured path starts with `/etc/letsencrypt/live/`, or when the real path starts
with `/etc/letsencrypt/archive/`. Such an installation gets `managed_by_certbot = true` and classification `unmanaged`
with the message *renewed by certbot; deployments would be overwritten*. The planner refuses to deploy to it (`CERTBOT_MANAGED`,
see [deployment-engine.md](deployment-engine.md) section 3). Live test (j) in `test_deploy_live.py` exercises that refusal.

### 4.4 Permissions

The helper runs as root through sudo. Its `readable` flag comes from `[ -r ]` run as root, and its reads run as root too.
Permission failures are therefore rare in the helper-sudo mode. A file that root cannot read (for example, an SELinux
denial) would be reported as `unreadable` (**unverified** on SELinux hosts; not tested).

### 4.5 Size limits and combined PEM

| Limit | Value | Result when exceeded |
|---|---|---|
| Helper `read-public` maximum (`read_public_file` default) | 1 MiB | `unsupported`, "larger than the 1 MiB read limit" (exit 11). |
| Parser input (`MAX_INPUT_BYTES` in `parse.py`) | 256 KiB | The parser refuses the input (`INPUT_TOO_LARGE`), so no leaf is found. Config references become `error` (no certificate could be parsed). The filesystem scan records a note. |

**Known issue.** The 1 MiB read limit is four times the parser limit. A file between 256 KiB and 1 MiB is read and then
refused by the parser, and the error text says only that no certificate could be parsed. The impact is limited to
unusually large files.

A file containing a private key (combined PEM) cannot be read with `read-public`. Discovery then asks the live endpoint
for its leaf certificate (`endpoint_leaf`, default probe of the verify endpoint). The result is marked
`fingerprint_source = endpoint` and a note `fingerprint taken from live endpoint (file contains private key)`. Confidence
is capped at 0.7. If the probe fails, the classification is `unreadable` with confidence at most 0.3.

Config references whose path ends in `.p12`, `.pfx`, `.jks` or `.key` are refused by the helper by extension
(`PRIVATE_KEY_REFUSED`). They follow the same endpoint path as a combined PEM. The filesystem scan never turns
PKCS#12 or JKS files into installations.

### 4.6 Chain files (Apache)

A separate `SSLCertificateChainFile` is read in the same way. Its certificates are appended to the installation's chain,
without duplicates. If it is missing or unreadable, the note `chain file missing or unreadable` is stored and the
installation is not affected.

### 4.7 Key presence

The key file is only `stat`-ed (`key_stat`). `key_exists` is true or false. It is `null` for combined PEM and endpoint
cases. A missing key gives `requires_mapping` with confidence at most 0.6, meaning the operator must confirm the key path.

---

## 5. Filesystem scan

The scan always runs after the service parsers. It is the only source of certificates that no configuration references.

### 5.1 Settings

Configured in the `ssh` settings section (`services/settings`, `schemas/settings.py`):

| Setting | Default | Limits |
|---|---|---|
| `discovery_roots` | `/etc/nginx /etc/apache2 /etc/httpd /etc/haproxy /etc/ssl /etc/pki /etc/letsencrypt` | Absolute paths, no `..`. |
| `discovery_max_depth` | 6 | 1 to 20 (helper maximum 20). |
| `discovery_max_files` | 2000 | 10 to 100000. |
| `discovery_exclude` | `/etc/ssl/certs /etc/pki/ca-trust /usr/share/ca-certificates */node_modules/*` | Absolute prefixes or shell globs. |

### 5.2 What the helper finds

`cdp-helper find ROOT MAXDEPTH MAXFILES` uses `find -P`. Symlinked directories are not followed. Symlinked files are listed
when their target is inside `ALLOWED_ROOTS`. Only these names are matched: `*.pem *.crt *.cer *.cert *.key *.p12 *.pfx
*.jks`. A file without one of these extensions is never seen, for example an extensionless `fullchain`.

### 5.3 Limits and their consequences

- **Exclusions are applied after the budget.** The backend removes excluded paths after the helper returns
  (`connection.find_cert_files` for absolute prefixes, `_scan` for globs), and the helper does not receive the exclusion
  list. Excluded entries therefore use up `discovery_max_files` and the depth walk is not reduced. On a host with many files under `/etc/ssl/certs`, the
  budget can run out before real certificates are reached. **Known issue** (from reading; not measured).
- **Truncation is silent.** The helper prints `truncated: true` when the budget is hit. `find_cert_files` discards that flag.
  No finding or note is stored.
- **A root outside the allowed roots fails the scan.** A missing root (exit 12) is skipped. A root that is not allowed
  (exit 3) raises an error. That error stops the filesystem scan, so the job is `partial`
  (`failed_services.filesystem`). Other roots already scanned are not kept in that case. **Known issue** (from reading).

### 5.4 What is kept

For each candidate path (already-referenced paths are skipped):

- Candidates are grouped by real path. The symlink is preferred over its target, so the certbot `live` path is recorded
  rather than the `archive` file.
- The file is read with `read-public`, then parsed. Only the leaf certificate is kept.
- **CA certificates** (`is_ca` true) are dropped with no finding and no note.
- Combined PEM files produce a note (`unreadable`, "contains private key material; content not read").
- PKCS#12 and JKS files produce a note (`unsupported`). Other kinds (private keys, CSRs, unrelated PEM) are skipped with
  no note.
- A kept certificate becomes an installation with `service_type = filesystem`, `classification = unmanaged`, confidence
  0.5, vhost empty, and the message *certificate found by filesystem scan; no service configuration references it*.

---

## 6. Classification, confidence and identity

### 6.1 Classification values

| Value | Meaning | Typical sources | Deployable |
|---|---|---|---|
| `managed` | Certificate and key located. Eligible for deployment. The planner still checks it. | nginx, apache, haproxy with a readable key or combined PEM. | Yes, subject to preflight. |
| `unmanaged` | Known but not to be replaced automatically. | certbot paths; filesystem scan results. | No. Operator can change it. |
| `requires_mapping` | Needs an operator decision. | Directory `crt`; missing or unresolvable key; adapter refuses the file layout. | No, until mapped. |
| `unsupported` | Cannot be read or parsed by design. | Variables; `crt-list`; PKCS#12 or JKS; file over 1 MiB; scan notes. | No. |
| `unreadable` | Exists, but CDP cannot read it. | Path not allowed; permission error; combined PEM whose endpoint probe fails. | No. |
| `error` | Missing or broken. | Missing file; broken symlink; directory; no certificate parsed. | No. |

The stored value is `classification`. `drift_status` is a separate field (section 7).

### 6.2 Confidence

`discovery_confidence` is stored and shown in the API. **Nothing in the backend acts on it** (verified by searching for
its use; only `inventory.py` writes it and only the API returns it). Values come from the parsers and the resolver:

| Source | Confidence |
|---|---|
| nginx, resolved | 1.0 (0.0 when a variable is present) |
| apache, resolved | 1.0, or 0.8 inside an `IfDefine`/other `If*` section, or 0.5 when `SSLEngine` is absent |
| haproxy `crt` file, with an extension or trailing `/` | 1.0 |
| haproxy extensionless path (treated as directory) | 0.7 |
| haproxy `crt-list` | 0.2 |
| endpoint-derived fingerprint | at most 0.7 |
| key missing, plan refused | at most 0.6 |
| endpoint unavailable for a combined PEM | at most 0.3 |
| filesystem scan | 0.5 |

### 6.3 Operator overrides

`PATCH /api/v1/installations/{id}` (`installations:write`) can set `classification` to `managed`, `requires_mapping` or
`unmanaged`. It can also set `verify_host`, `verify_port`, `verify_sni`, `owner` and `tags`.

- `managed` is refused (422 `CLASSIFICATION_NOT_ALLOWED`) for `unsupported`, `unreadable` or `error` installations, and
  for an installation with no identified certificate.
- An override is kept across re-discovery when the new result is `managed`, `unmanaged` or `requires_mapping`. An
  installation that discovery now reports as `error` is reclassified.
- Verification fields set by an operator are kept across re-discovery (`verify_mapped`).

Live test `test_endpoint_verify_and_inventory_api` asserts that overrides survive a second run.

### 6.4 Identity

- **Certificate identity:** the SHA-256 fingerprint of the leaf (`certificates.fingerprint_sha256`). One certificate can
  have many installations.
- **Installation identity:** `identity_key = sha256(server_id, service_type, cert_path, vhost)`, joined with the unit
  separator `\x1f` (`models/certificate.py`, `make_identity_key`).
- `vhost` is the sorted, comma-joined server names (or `-` when there are none), a colon, and the sorted listen ports, for
  example `app.example.com:443` or `-:10443`. Filesystem installations have no vhost.

Consequences:

- Re-running discovery on an unchanged server creates no installations and no duplicate certificates. The live test
  asserts this.
- Changing a `server_name` or a listen port changes the vhost, so the identity changes. The old installation is then
  not seen, so it is marked missing. The new one starts with no operator overrides and no deployment history. This
  follows from the identity construction and `upsert_installation` (**unverified** at runtime).
- Changing the certificate path has the same effect.

---

## 7. Drift, missing installations and verification

### 7.1 Drift

`upsert_installation` sets `drift_status` on every run:

- `unknown`: no fingerprint could be observed.
- `drifted`: an observed fingerprint differs from the **expected** fingerprint. Expected is the fingerprint the last
  completed deployment (or rolled-back target) left on the installation (`expected_fingerprint`).
- `in_sync`: otherwise.

A `drift.detected` notification is sent when an installation becomes `drifted` (the previous value was not `drifted`).

Live endpoint check: beat task `monitoring.verify_endpoints` runs every 6 hours at minute 41. It probes up to 1000
installations, least recently checked first, with 8 concurrent probes. When a served fingerprint differs from
`last_observed_fingerprint`, the installation becomes `drifted` (only from `in_sync` or `unknown`) and a `drift.detected`
notification is sent with `source = live_endpoint`. Nothing sets it back to `in_sync` in this task. The next discovery run
recomputes it.

### 7.2 Missing installations

After a job, every installation of a **successful** service type that was not seen in this run is marked
`drift_status = missing` with `missing_since` set, and a finding `installation no longer found on the server` is written.
Services that failed in this run are not marked missing. An installation seen again has `missing_since` cleared. No
notification is sent for a missing installation. The live test `test_removed_certificate_is_marked_missing_and_scan_finds_extras`
checks this for a filesystem installation.

### 7.3 Manual verification

- `POST /api/v1/installations/{id}/verify` (`installations:verify`)
- `POST /api/v1/certificates/{id}/verify` (`certificates:verify`), which verifies up to 50 installations

Both probe the installation endpoint (`inventory.endpoint_for`): host is `verify_host` or the server address; port is
`verify_port` or `listen_port`; SNI is `verify_sni` or the first server name that is neither a wildcard, `_`, nor a regex.
With no endpoint, the result is `ok: false`. The result is stored in `last_verification` with the served fingerprint,
`matches_file`, `chain_valid` (against the system store or `security.trust_anchors_pem`), `hostname_matches` and the TLS
version. The endpoint rules differ from the deployment rules (see [deployment-engine.md](deployment-engine.md) section 11,
**Known issue**).

---

## 8. Scheduling, concurrency and timeouts

| Item | Value | Source |
|---|---|---|
| Schedule | every 5 minutes (`discovery.schedule_all`) | `workers/celery_app.py` |
| Refresh interval | `general.inventory_refresh_minutes`, default 360 | `schemas/settings.py` |
| Active jobs per server | 1 | `create_job` (`DISCOVERY_ALREADY_RUNNING`) |
| Stale job | no progress for 30 minutes | `STALE_AFTER` |
| Job timeout | 20 minutes | `JOB_TIMEOUT_SECONDS` |
| SSH connect timeout | `ssh.connect_timeout`, default 10 s (max 120) | `schemas/settings.py` |
| Wait for an SSH slot | 300 s | `connect(queue_timeout=300)` |
| SSH sessions per host | 4 | `connection._default_limit` |
| Worker processes | `CDP_WORKER_CONCURRENCY`, default 4 | `docker-compose.yml` |
| Retries | up to 3 attempts for idempotent helper calls on retryable errors | `connection._with_retry` |

**Known issue.** `set_host_concurrency_limit` is exported but never called, so the per-host SSH limit is always 4.
Discovery calls `dump`, `probe`, `stat`, `read-public`, `find` and `df` as idempotent calls, so these are retried.

---

## 9. Limitations

- **HAProxy fingerprints come from the live endpoint when the file holds a key.** A combined PEM (the usual HAProxy
  layout) is never read, so its fingerprint is taken from the endpoint. That probe sends no SNI and gets the default
  certificate of the port. If the bind selects certificates by SNI, the fingerprint can be that of a different
  certificate from the file.
- **HAProxy files without a key are classified `managed`.** `is_combined_pem` is always true for `crt`, so the key is not
  checked. A certificate-only file is therefore `managed`. Deployment then fails at preflight (`KEY_REQUIRED` or
  `REUSE_KEY_UNAVAILABLE`). This follows from `resolve()` and is **unverified** at runtime.
- **JKS and PKCS#12 are detected, not parsed.** Discovery does not produce an installation for them. Upload accepts
  PKCS#12 (see [deployment-engine.md](deployment-engine.md) section 16), but JKS uploads are refused.
- **Apache conditional sections** report both branches of an `IfDefine`, and treat `IfModule` bodies as loaded.
- **Filesystem scan misses** names without the listed extensions, excluded paths still spend the budget, and truncation is
  silent (section 5.3).
- **CA certificates** found by the scan are dropped without any record.
- **Identity changes** when names or ports change (section 6.4).
- **Live test coverage.** `test_discovery_live.py` covers nginx (direct, symlink and certbot paths), apache with a chain,
  haproxy with a combined PEM, a filesystem extra, idempotency, verification, overrides and missing marking, a second
  concurrent request, and a host-key mismatch. It does not cover `crt-list`, Apache `IfDefine`, budget exhaustion,
  truncation, broken symlinks, large files, PKCS#12 or JKS files, or identity changes.

---

## 10. Adding a service (plugin adapters)

The adapter contract lives in `backend/app/integrations/services/adapters/base.py`. The built-in adapters are in
`builtin.py`. Future candidates named in that file are Tomcat, JKS keystores and Postfix. **None of them is implemented.**

1. **Parser.** Add a module under `integrations/services/parsers/` that is a pure function from the dump text to a list
   of `ConfigCertRef`. Model new artifact kinds (for example a keystore) by extending `ArtifactKind`.
2. **Adapter.** Subclass `ServiceAdapter` and implement `discover`, `plan_files`, `config_test`, `reload` and
   `default_verify_endpoints`. Register it with `@register_adapter`. The registry key is the `service_type` string.
3. **Helper.** Add the matching `dump`, `configtest` and `reload` subcommands to `infra/remote-helper/cdp-helper`. Adapters
   can only call fixed helper subcommands (`ssh/paths.py`, `SUBCOMMANDS`). They cannot run arbitrary commands.

Beyond these three steps, the current code also hard-codes the three built-in services in these places. Each must change
for a new service (read from code; not tested):

| Location | Why it matters |
|---|---|
| `integrations/contracts.py`, `ServiceType` | `ConfigCertRef.service` and `RemoteHost.dump_config` are typed with this enum. |
| `integrations/ssh/connection.py`, `_svc()` | Accepts only `nginx`, `apache` and `haproxy`; anything else raises `COMMAND_FAILED`. |
| `integrations/ssh/parsing.py`, `_SERVICE_NAMES` | Maps the helper's probe names to services. Unknown names are ignored. |
| `infra/remote-helper/cdp-helper`, `cmd_probe`, `cmd_dump`, `cmd_configtest`, `cmd_reload` | Only the three services are probed, dumped, tested and reloaded. |
| `integrations/ssh/paths.py`, `SUBCOMMANDS` | Only if a new helper subcommand is added. |

A new installation's `service_type` is stored in a `String(16)` column (`models/certificate.py`). Names up to 16 characters
fit.

Keystore-based services (JKS) also need the helper to install a keystore, and `ArtifactKind` plus a planner rule for it.
Today JKS uploads are refused (`parse.py`), and discovery detects JKS without parsing it.

---

## 11. Live tests and what they prove

| Test | Asserts |
|---|---|
| `test_discovery_finds_nginx_apache_haproxy_and_is_idempotent` | Services and fingerprints checked with `openssl x509` (independent of the parser); symlink and certbot classification; haproxy endpoint-sourced fingerprint; filesystem certificates are `unmanaged`; no `PRIVATE KEY` in output or audit; a second run creates nothing. |
| `test_endpoint_verify_and_inventory_api` | Endpoint verification; certificate verification; list and filter queries; overrides survive re-discovery. |
| `test_removed_certificate_is_marked_missing_and_scan_finds_extras` | The scan finds an extra file; removing it marks the installation missing. |
| `test_second_concurrent_discovery_is_refused` | 409 for a second job; bulk reports `DISCOVERY_ALREADY_RUNNING`. |
| `test_host_key_mismatch_fails_job_and_flags_server` | `HOST_KEY` failure; server status set; audit event. |

None of these was run for this page.

The live tests need the disposable target from `infra/test-target/setup-local.sh`. They skip themselves when it cannot be
started (`tests/integration/conftest.py`). The unit tests `tests/unit/parsers/`, `tests/unit/test_discovery_logic.py` and
`tests/unit/certificates/` cover the parsers and the discovery logic with fake hosts. Their names were read; they were not
run for this page.

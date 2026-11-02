# Backup and restore

Two different things are called "backup" in Cert Deploy Pro (CDP), and they fail in different ways:

- **Section 1, deployment backups.** A copy of every file a deployment replaces, taken from the target server before the
  change and kept encrypted inside CDP. They exist so that a rollback can restore the previous files.
- **Section 2, platform disaster recovery.** What an operator must copy so that the whole CDP stack can be rebuilt on
  another host, and what is lost if a piece is missing.

Basis: source at commit `a353f1e`. Read: `services/backups.py`, `core/crypto.py` (vault), `core/config.py`,
`services/deployment_engine.py` (backup use), `services/locks.py`, `services/events.py`, `services/notifications.py`,
`services/uploads.py`, `services/credentials.py`, `services/auth.py` (MFA and sessions), `workers/celery_app.py`,
`workers/tasks.py`, `workers/deploy_tasks.py`, `docker-compose.yml`, `backend/Dockerfile`, `infra/caddy/Caddyfile`.
`docs/installation.md` sections 2.2, 4 and 7 were read for the commands it already gives.

**No command on this page was run, and no backup or restore was performed.** Commands are marked **(not run)**.
Behaviour that rests on reading alone is marked **(unverified)**. Defects found by reading are marked **Known issue**.

Related: [rollback.md](rollback.md) (using a backup to roll back), [security.md](security.md) (key handling, sessions),
[installation.md](installation.md) (install, upgrades, and the first backup), [configuration.md](configuration.md)
(`CDP_MASTER_KEY_FILE`, `CDP_ARTIFACT_DIR`).

---

## 1. Deployment backups

### 1.1 What is backed up

For each deployment target, `backups.create_backup` copies every destination file the target will replace:

- the file **content**, read through the symlink (the real file), with `backup` in the remote helper;
- its **metadata**: path, real path, symlink target, SHA-256, size, mode, uid and gid, owner and group, SELinux context.

Key files are included. A combined PEM (HAProxy) is included whole, so it contains the private key. The helper refuses
any single file over 10 MiB (`MAX_STAGED_BYTES`). A backup is one row per target (`backups.deployment_target_id`),
linked to the installation and the server.

### 1.2 Storage: envelope encryption (the vault)

`core/crypto.py` implements the vault:

| Step | Detail |
|---|---|
| Key hierarchy | The KEK (master key) is 32 bytes, from `CDP_MASTER_KEY` or `CDP_MASTER_KEY_FILE`. Each artifact has its own random 256-bit data key (DEK). |
| Content encryption | AES-256-GCM. The nonce is 12 random bytes. The associated data is `"<artifact id>|<purpose>"`, so a ciphertext cannot be moved to another artifact or purpose. |
| Key wrapping | The DEK is encrypted with the KEK (AES-256-GCM, associated data `"<artifact id>|dek"`). The wrapped DEK, the nonce and the key ID are stored in the database. |
| Ciphertext | `<artifact_dir>/<artifact id>.bin`. The directory is mode 0700 and each file 0600. Writes go to a `.tmp` file, are fsynced, then renamed. |
| Metadata | Table `encrypted_artifacts`: `purpose`, `key_id`, `wrapped_dek`, `nonce`, `sha256_plain`, `size`, `filename`, `deleted_at`. |
| Key ID | `key_id` is the first 16 hex characters of SHA-256 of the KEK. It identifies which KEK an artifact needs. |
| Reading | Load checks the GCM tag, then the SHA-256 of the plaintext against `sha256_plain`. Any mismatch raises an integrity error. |
| Purposes | `backup` (deployment backups); `certificate_pem`, `certificate_chain`, `certificate_private_key` (uploads); `ssh_private_key` (credentials). |

Small secrets are encrypted inline with `encrypt_value`: SSH key passphrases (`credentials.passphrase_encrypted`), TOTP
secrets (`users.mfa_secret_encrypted`), and notification channel secrets (`notification_channels.secret_encrypted`). The
inline format is `v1:<key_id>:<base64>`.

The API container's startup only checks that the KEK is the right length (`lifespan` calls `get_vault()`). It does not
check the KEK against any stored `key_id`. **A wrong KEK starts without error and fails at first use** (verified from
code; not run).

### 1.3 Manifest and integrity

The backup row holds a manifest (JSON) with `version`, `created_at` and a `files` list. Each file entry holds the metadata
above and the `artifact_id`. It never holds content.

`integrity_sha256` is an HMAC-SHA256 over the canonical JSON of the `files` list (sorted keys, no spaces). The key is
derived from the KEK with the label `backup-manifest` (`cdp-derive:` prefix, see [security.md](security.md) section 3.1).
`verify_backup` does two things:

1. recomputes the HMAC and compares it in constant time;
2. loads each artifact, which checks the GCM tag and its hash, then compares the length and SHA-256 with the manifest.

A change to any manifest entry, or to any stored file, is therefore detected before a restore or a download.

### 1.4 Creation and verification

1. Each file is read with `backup`. The SHA-256 of the returned bytes must equal the SHA-256 that `stat` reported. If not,
   the backup fails (`BACKUP_FAILED`, "changed or was corrupted while it was read").
2. Each file is stored in the vault (`purpose = backup`).
3. The manifest and `integrity_sha256` are written, and `retention_until` is set.
4. Verification runs **before** the backup is marked `verified`. It decrypts every artifact again and re-hashes it.
5. On any failure, the stored artifacts from this attempt are deleted and nothing is marked verified.

A deployment does not change any file unless its backup is verified (`BACKUP_FAILED` otherwise).

**Known issue (minor).** `public_manifest` returns the manifest with `artifact_id` values intact. The download archive's
`manifest.json` therefore contains the artifact IDs. The API's `backup_out` removes them. The IDs are not secret on their
own, but the file's name suggests they are.

### 1.5 Retention and purge

- `retention_until = created + general.backup_retention_days` (default 90, range 1 to 3650).
- Beat task `backups.purge_expired` runs daily at 03:23 UTC.
- It deletes every backup past `retention_until`, with its artifacts. It never deletes the **newest** backup of an
  installation, or of a server when the backup has no installation, even when that one is also expired.
- Deleting an artifact overwrites its ciphertext with random bytes, then unlinks the file. The `encrypted_artifacts` row is
  marked `deleted_at`, and its wrapped DEK is emptied.
- Each purged backup writes a `BACKUP_PURGED` audit event.

**Known issue.** If deleting an artifact raises, `purge_expired` logs `backup_artifact_delete_failed` and still deletes the
`backups` row. The ciphertext file can then remain on disk with no row pointing at it. The purge task does not retry.

Retention does not touch the audit log or notification deliveries. The deployment target keeps its record. Its `backup_id`
is set to NULL by the database (`ON DELETE SET NULL`), so a purged backup can no longer be used for a manual rollback.

### 1.6 Listing and download

| Action | Endpoint | Permission | Notes |
|---|---|---|---|
| List | `GET /api/v1/backups` | `backups:read` | Filters: `server_id`, `installation_id`, `deployment_id`. Metadata only. |
| Detail | `GET /api/v1/backups/{id}` | `backups:read` | Metadata and the file list without `artifact_id`. |
| Download | `GET /api/v1/backups/{id}/download` | `backups:download`, re-auth | Admin only. |

The download verifies the backup first (`BACKUP_INTEGRITY_FAILED` if not). It then builds a gzip tar with:

- `manifest.json` (the public manifest with `backup_id`, see the known issue in 1.4);
- `files/<path without the leading slash>`, the **decrypted** content, mode 0600.

The response has `Content-Disposition: attachment; filename="backup-<id>.tar.gz"` and `Cache-Control: no-store`. Each
download writes `BACKUP_DOWNLOADED` to the audit log with the file paths.

**The archive contains private keys in plaintext.** Handle it like a key file: keep it only as long as needed, store it
encrypted, and delete it.

### 1.7 Restore

Restore writes backed-up content back to the server with the verified routine described in
[rollback.md](rollback.md) sections 2 and 7. It is available to administrators through `POST /api/v1/backups/{id}/restore`
and `POST /api/v1/deployments/{job}/targets/{target}/rollback`, both with recent re-authentication.

A backup restores only the files it recorded. It cannot restore a file a deployment did not touch.

---

## 2. Platform disaster recovery

### 2.1 What must be backed up

| # | Item | Where it lives (compose) | Needed for | Back up with |
|---|---|---|---|---|
| 1 | PostgreSQL database `cdp` | volume `pgdata` (`cert-deploy-pro_pgdata`) | Inventory, jobs, targets, backups metadata, audit, users, sessions, settings, notification rules, encrypted-artifact metadata (wrapped DEKs). | `pg_dump -Fc` (2.3). |
| 2 | Artifact ciphertext | volume `artifacts` (`cert-deploy-pro_artifacts`), path `/var/lib/cdp/artifacts` | The encrypted bytes for every row in `encrypted_artifacts`. | `tar` of the volume (2.3). |
| 3 | Master key (KEK) | host file `secrets/cdp_master_key` | Decrypting items 2 and all inline secrets. The database and artifacts are useless without it. | Copy the file to offline storage, separate from items 1 and 2 (installation section 2.2). |
| 4 | `.env` | host file | `POSTGRES_PASSWORD`, `REDIS_PASSWORD` and other settings. Compose refuses to start without the two passwords. | Copy to your secrets store. |
| 5 | Caddy state | volume `caddydata` | TLS material. With `CDP_TLS_DIRECTIVE` at its default (`tls internal`), the internal CA lives here (**unverified** Caddy behaviour). Losing it makes browsers see a new CA. | Optional. Copy the volume. |
| 6 | Source and images | the repository, and images tagged `cert-deploy-pro/<service>:${CDP_VERSION}` | Rebuilding the same version. | Git tag, and the tag used (installation 4.3). |

Redis is not on this list. Section 2.2 explains why.

**Item 3 is the critical one.** Items 1 and 2 are both ciphertext without it. Backing up items 1 and 2 to the same place
as item 3 defeats the purpose of encryption at rest. The design protects against a stolen database backup, not against
the host being compromised (see [security.md](security.md) section 10, threat T5).

### 2.2 What Redis holds, and what that means

From the code, Redis holds three kinds of data and nothing else:

| Data | Source | If Redis is lost |
|---|---|---|
| Celery broker queue (default queue `celery`) | `celery_app.py` | Messages not yet consumed are lost. Their database rows remain. |
| Progress pub/sub channels `cdp:job:<kind>:<id>` | `services/events.py` | Live progress stops. The database snapshot still shows the state. |
| Rate-limit counters (`CDP_RATE_LIMIT_BACKEND=redis`, the default) | `core/ratelimit.py` | Counters reset. When Redis is unavailable, each process falls back to its own in-memory limiter (`rate_limit_redis_unavailable`), so limits are per process rather than shared. |

Jobs, locks, backup metadata, notification deliveries, audit and sessions are all in PostgreSQL. Compose enables AOF
(`--appendonly yes`) on the `redisdata` volume, so queued messages normally survive a Redis restart.

**Consequence (from code; not tested).** After a Redis loss, a discovery job or deployment that was queued but not yet
consumed stays in the database as `pending`. Only notification deliveries have a sweep that re-enqueues them
(`notifications.sweep_pending`). Discovery `pending` jobs are marked failed after 30 minutes. Deployment jobs have no such
rule, and `cancel` does not move them out of `pending`. See [troubleshooting.md](troubleshooting.md) for the check.

### 2.3 Backup procedure (compose stack)

Run from the project directory, on the host, as the user that owns the compose project. **(not run)**

1. **Check nothing is mid-deployment.** `GET /api/v1/deployments?status=pending,preflight,activating` should return an empty
   list. Backing up during a deployment can capture target rows and artifacts in a transitional state.

2. **Create a directory outside the project.**

   ```bash
   BACKUP_DIR="/srv/cdp-backups/$(date -u +%Y%m%dT%H%M%SZ)"
   mkdir -p "$BACKUP_DIR" && chmod 700 "$BACKUP_DIR"
   ```

3. **Dump the database first.** Taking the database before the artifacts means every artifact a dumped row points to
   already exists when the archive is taken.

   ```bash
   docker compose exec -T postgres pg_dump -U cdp -d cdp -Fc > "$BACKUP_DIR/cdp.dump"
   ```

   This is the command from [installation.md](installation.md) section 4.1.

4. **Check the dump is readable.** `pg_restore --list` reads the archive's table of contents and writes nothing. (**unverified**:
   piping a custom-format dump on stdin into `pg_restore`; if it fails, copy the file into the container first.)

   ```bash
   docker compose exec -T postgres pg_restore --list < "$BACKUP_DIR/cdp.dump" > /dev/null && echo "dump ok"
   ```

5. **Archive the artifacts volume.** The volume is mounted read-only for the archive.

   ```bash
   docker run --rm -v cert-deploy-pro_artifacts:/src:ro -v "$BACKUP_DIR":/dst alpine \
     tar -C /src -czf /dst/artifacts.tgz .
   ```

   The volume name assumes the compose project is `cert-deploy-pro` (`name:` in `docker-compose.yml`). Check it with
   `docker volume ls` (**unverified** on your host).

6. **Record checksums.**

   ```bash
   (cd "$BACKUP_DIR" && sha256sum cdp.dump artifacts.tgz > SHA256SUMS)
   ```

7. **Confirm the master key matches the data.** This command does not print the key. It compares the key's ID with the IDs
   the artifacts were written with.

   ```bash
   # key ID of the file (must print one value)
   base64 -d secrets/cdp_master_key | sha256sum | cut -c1-16

   # key IDs stored with the artifacts (must match, and be the only ones)
   docker compose exec -T postgres psql -U cdp -d cdp -tAc "SELECT DISTINCT key_id FROM encrypted_artifacts;"
   ```

   If they differ, the file is not the key that created the data. Stop, and find the right key before taking more backups.

8. **Store the pieces apart.** Move `$BACKUP_DIR` off the host. Store the KEK and `.env` somewhere else, and do not put them
   in `$BACKUP_DIR`. Keep an offline copy of the KEK (installation section 2.2).

**Consistency notes (from reasoning; not tested).**

- An artifact written after step 3 but before step 5 is in the archive without being in the dump. It is harmless orphaned
  ciphertext.
- An artifact deleted by the purge after step 3 but before step 5 is missing from the archive while its row is still in
  the dump. That backup then fails verification after restore. Avoid the 03:23 UTC purge window.

### 2.4 Restore procedure (compose stack, fresh host)

Run on the new host. **(not run)**

1. **Install the same version.** Install Docker and compose, check out the same repository revision, and set
   `CDP_VERSION` to the release that wrote the dump. Migrations run on start, so the dump must not come from a newer release
   than the code you start (installation section 4.3).

2. **Put back the files.** Copy `.env` and `secrets/cdp_master_key` into place. Use mode 600 for the key. Check the copies
   against `SHA256SUMS`. Set `BACKUP_DIR` to the directory you copied the backup into:

   ```bash
   BACKUP_DIR=/srv/cdp-restore/<timestamp>     # the copied backup directory
   chmod 600 secrets/cdp_master_key
   (cd "$BACKUP_DIR" && sha256sum -c SHA256SUMS)
   test "$(base64 -d secrets/cdp_master_key | wc -c)" -eq 32 && echo "KEK length ok"
   ```

3. **Start only the database and Redis.**

   ```bash
   docker compose up -d postgres redis
   docker compose ps          # wait for "healthy"
   ```

4. **Restore the database into the empty `cdp` database** that the postgres image creates. Use it only on a freshly
   initialised database.

   ```bash
   docker compose exec -T postgres pg_restore -U cdp -d cdp --no-owner --clean --if-exists < "$BACKUP_DIR/cdp.dump"
   ```

   The same stdin caveat as in 2.3 step 4 applies (**unverified**).

5. **Restore the artifacts volume.** Docker creates the volume if it is missing. Archive ownership is kept, because the
   tar runs as root.

   ```bash
   docker run --rm -v cert-deploy-pro_artifacts:/dst -v "$BACKUP_DIR":/src alpine \
     tar -C /dst -xzf /src/artifacts.tgz
   ```

   The API and worker run as uid 10001 (`backend/Dockerfile`, `USER cdp`). Their artifact files must stay readable and writable
   by that uid. Check the ownership after the restore:

   ```bash
   docker run --rm -v cert-deploy-pro_artifacts:/d alpine sh -c 'ls -ln /d | head'
   ```

   If the owner is not 10001, correct it with `chown -R 10001:10001` run in an alpine container against the volume
   (**unverified**: not tested on this stack).

6. **Start the whole stack.**

   ```bash
   docker compose up -d
   docker compose logs migrate        # alembic should report it is at head
   ```

7. **Check the health endpoints.** `readyz` returns 503 when PostgreSQL or Redis is unreachable.

   ```bash
   curl -k https://<console host>/api/v1/readyz
   ```

8. **Prove the key works.** Test SSH to one server that has a credential. The test decrypts the SSH key from the vault.

   ```text
   POST /api/v1/servers/{id}/test-connection   (operator or admin, CSRF header)
   ```

   A passing test shows that the KEK, the artifacts and the database agree for at least that credential.

9. **Consider the sessions.** Sessions are restored with the database. They stay valid until they expire (sessions are
   opaque tokens stored as hashes; see [security.md](security.md) section 1.2). There is no API to revoke all sessions at
   once. Change the administrator password, or disable and re-enable accounts, if the old sessions may have been exposed.

**Order matters.** The database and the artifacts must come from the same backup set. Restoring a database dump with an
artifacts archive from another day produces rows that point to missing or different files. Such backups fail verification.

---

### 2.5 Key loss

The KEK is not stored anywhere in CDP. There is **no re-keying tool** in the codebase (searched for re-encrypt, rekey and
master-key rotation; nothing found). If the KEK is lost or replaced, the encrypted data cannot be read again.

| Data | With the KEK | Without it (lost or wrong KEK) |
|---|---|---|
| SSH private keys and passphrases (`ssh_private_key` artifacts, `passphrase_encrypted`) | Connections work. | Discovery, testing and deployment fail to load the credential. Create new credentials and install their public keys on each target. |
| Certificate private keys in uploaded versions (`certificate_private_key`) | Versions can be deployed. | Versions with a key cannot be deployed. The version's own certificate PEM is an artifact too, so it is lost as well. The copy in the `certificates` table, for certificates that were discovered or deployed, remains. |
| Deployment backups (`backup` artifacts) | Restore and download work. | No restore. `verify_backup` fails on the HMAC, which uses the KEK, so downloads are refused. |
| Notification channel secrets (`secret_encrypted`) | Email and webhook deliveries work. | Deliveries fail with "channel secret cannot be decrypted (master key changed?)". The error is not retried. Re-enter the secrets after creating new channels. |
| TOTP secrets (`mfa_secret_encrypted`) | TOTP sign-in works. | TOTP verification decrypts the secret, so TOTP sign-in for those users fails (**unverified** exact response). |
| Derived keys: CSRF (`csrf-v1`), OIDC state, backup manifest HMAC (security.md section 3.1) | Unchanged. | Derived keys change. Browser sessions fail the CSRF check and need to sign in again (**unverified**). Old backup manifests fail their HMAC. |
| Inventory, certificate PEMs stored in `certificates`, jobs, audit, users, settings | Readable. | Still readable. These are stored in plaintext in PostgreSQL. |

**Recovery options in practice:**

- If the old KEK file exists anywhere, restore it. Nothing else helps.
- If it does not, the encrypted items are gone. Plan to rebuild: create new credentials and install new public keys on
  targets, re-upload certificate versions with their keys, reconfigure notification channels, and re-enroll host keys if
  the server was reinstalled. Inventory and history remain.

There is no "rotate KEK" procedure. Changing `secrets/cdp_master_key` in place makes every existing artifact unreadable.

---

## 3. Restoration test

No restoration test has been recorded for this document yet.

<!-- RESTORE_TEST_RESULTS -->
**Restoration test, executed 2026-11-02** (development stack, not the Compose images, which could not be built in
the test environment):

1. `pg_dump -Fc` of the live `cdp` database (12 servers, 13 credentials, 3 deployment backups, 6 certificate
   versions, 179 audit events) and a `tar` of the artifact directory.
2. Restored with `pg_restore --no-owner` into a fresh database `cdp_restore` and a fresh, empty artifact directory.
3. Ran `python -m scripts.verify_restore --ssh` (in `backend/`) against the restored copy with the original master key:
   - schema revision `0004` (head)
   - **3/3 deployment backups verified**: manifest HMAC plus decrypt and SHA-256 of every file
   - **6/6 certificate versions decrypted**
   - **11/13 SSH credentials decrypted**, and **11 live SSH connection tests passed** from the restored data
   - The 2 failing credentials fail identically in the *source* database. They were encrypted under an earlier
     development master key that was later replaced. This shows the key-loss property: data encrypted under a lost
     key cannot be recovered, even from a correct backup.
4. Same restored copy with a **wrong master key**: 0 backups, 0 credentials and 0 versions decrypt, and the script
   exits non-zero. A database and artifact backup is useless without the separately stored key.

Run the same check after any real restore:

```bash
docker compose run --rm api python -m scripts.verify_restore --ssh
```

The Compose command above has not been run, because the images could not be built here.


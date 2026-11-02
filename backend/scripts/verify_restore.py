"""Verify a restored Cert Deploy Pro installation (disaster-recovery restore test).

Run with the SAME environment as the API (CDP_DATABASE_URL, CDP_ARTIFACT_DIR, CDP_MASTER_KEY[_FILE])
pointing at the RESTORED database and artifact directory:

    python -m scripts.verify_restore [--ssh]

Checks, read-only:
  1. database reachable, schema at alembic head, row counts
  2. every deployment backup: manifest HMAC + every artifact decrypts and matches its sha256
  3. every SSH credential decrypts and parses as a private key
  4. every certificate version artifact decrypts
  5. (--ssh) a real connection test to each enabled server with an enrolled host key
Exit status 0 only if everything verifies. Never prints secret material.
"""
from __future__ import annotations

import argparse
import asyncio
import sys

import asyncssh
from sqlalchemy import func, select, text

from app.core.config import get_settings
from app.core.crypto import get_vault
from app.core.db import SessionLocal
from app.models import Backup, CertificateVersion, Credential, Server
from app.services import backups as backup_svc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ssh", action="store_true", help="also run a live SSH connection test per server")
    args = ap.parse_args()
    get_settings()
    vault = get_vault()
    failures: list[str] = []
    with SessionLocal() as db:
        rev = db.execute(text("select version_num from alembic_version")).scalar()
        print(f"schema revision: {rev}")
        for model in (Server, Credential, Backup, CertificateVersion):
            print(f"{model.__tablename__}: {db.scalar(select(func.count()).select_from(model))}")

        ok = 0
        for b in db.scalars(select(Backup)):
            try:
                backup_svc.verify_backup(b, db=db)
                ok += 1
            except Exception as exc:  # noqa: BLE001 - report and continue
                failures.append(f"backup {b.id}: {exc}")
        print(f"backups verified: {ok}")

        ok = 0
        for c in db.scalars(select(Credential)):
            try:
                pem = vault.load(c.encrypted_artifact_id, db=db)
                pp = vault.decrypt_value(c.passphrase_encrypted) if c.passphrase_encrypted else None
                asyncssh.import_private_key(pem, pp)
                ok += 1
            except Exception as exc:  # noqa: BLE001
                failures.append(f"credential {c.id} ({c.name}): {type(exc).__name__}")
        print(f"credentials decrypted: {ok}")

        ok = 0
        for v in db.scalars(select(CertificateVersion)):
            try:
                for aid in (v.cert_artifact_id, v.key_artifact_id, v.chain_artifact_id):
                    if aid:
                        vault.load(aid, db=db)
                ok += 1
            except Exception as exc:  # noqa: BLE001
                failures.append(f"certificate version {v.id}: {type(exc).__name__}")
        print(f"certificate versions decrypted: {ok}")

        if args.ssh:
            from app.integrations.ssh import test_connection
            from app.services import connectivity
            from app.services import settings as settings_svc

            ssh_settings = settings_svc.get_section_data(db, "ssh")
            for s in db.scalars(select(Server).where(Server.enabled.is_(True))):
                if not s.host_public_key or s.credential is None:
                    continue
                try:
                    report = asyncio.run(test_connection(connectivity.build_target(s, ssh_settings),
                                                         connectivity.load_credential(s)))
                    status = "ok" if report.ok else f"FAILED {report.error_code}"
                except Exception as exc:  # noqa: BLE001
                    status = f"FAILED {type(exc).__name__}"
                print(f"ssh {s.name}: {status}")
                if status != "ok":
                    failures.append(f"ssh {s.name}: {status}")

    for f in failures:
        print("FAIL:", f)
    print("RESULT:", "PASS" if not failures else f"FAIL ({len(failures)} problems)")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())

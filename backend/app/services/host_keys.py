"""Bulk host-key scan / enroll (bounded concurrency; every enrollment re-verified against a fresh scan)."""
from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import AppError
from app.models import Server, User
from app.schemas.server import (
    HostKeyBulkEnroll,
    HostKeyBulkEnrollOut,
    HostKeyBulkEnrollResult,
    HostKeyBulkScanItem,
    HostKeyBulkScanOut,
)
from app.services import audit, connectivity
from app.services import settings as settings_service

CONCURRENCY = 5


def _endpoint(s: Server) -> str:
    return f"{s.address or s.hostname}:{s.ssh_port}"


def _load(db: Session, ids: list[uuid.UUID]) -> dict[uuid.UUID, Server]:
    return {s.id: s for s in db.scalars(select(Server).where(Server.id.in_(ids)))}


def scan(db: Session, actor: User, server_ids: list[uuid.UUID]) -> HostKeyBulkScanOut:
    ids = list(dict.fromkeys(server_ids))
    servers = _load(db, ids)
    timeout = float(settings_service.get_section_data(db, "ssh")["connect_timeout"])
    results = connectivity.scan_many([(sid, s.address or s.hostname, s.ssh_port) for sid, s in servers.items()],
                                     timeout, CONCURRENCY)
    items: list[HostKeyBulkScanItem] = []
    for sid in ids:
        s = servers.get(sid)
        if s is None:
            items.append(HostKeyBulkScanItem(server_id=sid, error_code="SERVER_NOT_FOUND", error="Server not found"))
            continue
        info, err = results[sid]
        item = HostKeyBulkScanItem(server_id=sid, server_name=s.name, endpoint=_endpoint(s),
                                   enrolled_fingerprint=s.host_key_fingerprint)
        if info is not None:
            item.key_type, item.fingerprint_sha256, item.public_key = (
                info.key_type, info.fingerprint_sha256, info.public_key_openssh)
            if s.host_key_fingerprint:
                item.matches_enrolled = s.host_key_fingerprint == info.fingerprint_sha256
            audit.record(db, action="HOST_KEY_SCAN", resource_type="server", resource_id=s.id, actor=actor,
                         after={"fingerprint": info.fingerprint_sha256, "key_type": info.key_type, "bulk": True})
        else:
            item.error_code, item.error = (err or {}).get("code", "UNKNOWN"), (err or {}).get("message")
            audit.record(db, action="HOST_KEY_SCAN", resource_type="server", resource_id=s.id, actor=actor,
                         outcome="failure", error=item.error_code)
        items.append(item)
    db.commit()
    return HostKeyBulkScanOut(items=items)


def enroll(db: Session, actor: User, body: HostKeyBulkEnroll) -> HostKeyBulkEnrollOut:
    ids = [i.server_id for i in body.items]
    servers = _load(db, list(dict.fromkeys(ids)))
    timeout = float(settings_service.get_section_data(db, "ssh")["connect_timeout"])
    scans = connectivity.scan_many(
        [(sid, s.address or s.hostname, s.ssh_port) for sid, s in servers.items()], timeout, CONCURRENCY)
    out: list[HostKeyBulkEnrollResult] = []
    for item in body.items:
        sid = item.server_id
        if sid not in servers:
            out.append(HostKeyBulkEnrollResult(server_id=sid, status="error", error_code="SERVER_NOT_FOUND",
                                               error="Server not found"))
            continue
        info, err = scans[sid]
        if info is None:
            out.append(HostKeyBulkEnrollResult(server_id=sid, status="error", error_code="HOST_KEY_SCAN_FAILED",
                                               error=f"Could not retrieve the host key from the server "
                                                     f"({(err or {}).get('code', 'UNKNOWN')})"))
            continue
        try:
            connectivity.enroll_host_key(db, actor, sid, item.public_key, item.fingerprint_sha256, body.replace,
                                         fresh=info)
            out.append(HostKeyBulkEnrollResult(server_id=sid, status="enrolled"))
        except AppError as exc:
            db.rollback()
            out.append(HostKeyBulkEnrollResult(server_id=sid, status="error", error_code=exc.code, error=exc.message))
    return HostKeyBulkEnrollOut(items=out)

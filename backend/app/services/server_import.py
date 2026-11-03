"""CSV server inventory import: parse + validate (dry run) and all-or-nothing creation, then optional host-key pinning.

Rows are validated with the same ``ServerCreate`` schema and reference rules as ``POST /servers``. A pinned
``host_key_fingerprint`` is only ever enrolled when a *fresh* scan returns exactly that fingerprint; rows without a
fingerprint are left unenrolled (never auto-trusted).
"""
from __future__ import annotations

import csv
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import AppError, conflict
from app.core.logging import get_logger
from app.integrations.ssh.sanitize import sanitize_output
from app.models import Credential, Environment, Server, User
from app.schemas.server import (
    ImportFieldError,
    ImportHostKey,
    ImportResultOut,
    ImportRowOut,
    ServerCreate,
)
from app.services import audit, connectivity
from app.services import servers as servers_service
from app.services import settings as settings_service

log = get_logger(__name__)

MAX_BYTES = 1024 * 1024
MAX_ROWS = 1000
SCAN_CONCURRENCY = 5
COLUMNS = ("name", "hostname", "address", "ssh_port", "ssh_username", "environment", "credential", "privilege_mode",
           "bastion", "tags", "description", "host_key_fingerprint")
REQUIRED = ("name", "hostname", "ssh_username", "environment")
_FP = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}=?$")
FILENAME = "cert-deploy-pro-servers-template.csv"

TEMPLATE = """\
# Cert Deploy Pro - server inventory import template. Lines starting with '#' and blank lines are ignored.
# Separate columns with ',' or ';' (auto-detected). Maximum 1000 rows and 1 MiB. Save as UTF-8.
# name: required. Unique server name (letters, digits, space, '.', '_' and '-'; must start with a letter or digit).
# hostname: required. DNS name or IP address used to reach the server.
# address: optional. IP address to connect to instead of resolving the hostname.
# ssh_port: optional. 1-65535; defaults to the SSH default port from the settings (22).
# ssh_username: required. SSH account on the server (e.g. cdpdeploy).
# environment: required. Name of an existing environment (e.g. Production, Staging).
# credential: optional. Name of an existing SSH credential; defaults to the configured default credential, if any.
# privilege_mode: optional. helper-sudo (default) or none.
# bastion: optional. Name of an existing server, or of another server defined in this file, used as SSH jump host.
# tags: optional. Separate tags with '|' or ';' (use '|' when the file delimiter is ';'). Not ','.
# description: optional. Free text, at most 2000 characters.
# host_key_fingerprint: optional. SHA256:... of the server's SSH host key (e.g. from 'ssh-keyscan host | ssh-keygen -lf -').
#   It is enrolled only if a fresh scan of the server returns exactly this fingerprint; without it the server stays
#   unenrolled and you enroll the host key from the server page. Keys are never trusted automatically.
name,hostname,address,ssh_port,ssh_username,environment,credential,privilege_mode,bastion,tags,description,host_key_fingerprint
# Examples (commented out so they are never imported by accident; copy them without the leading '# '):
# bastion-01,bastion.example.com,,,cdpdeploy,Production,,,,,,
# app-01,app-01.example.com,10.0.0.21,22,cdpdeploy,Production,my-ssh-key,helper-sudo,bastion-01,web|dmz,Primary application server,SHA256:<43 base64 characters>
"""


# ------------------------------------------------------------------------------------------------ parsing
@dataclass
class ParsedRow:
    line: int
    values: dict[str, str]


@dataclass
class _Row:
    line: int
    values: dict[str, str]
    errors: list[ImportFieldError] = field(default_factory=list)
    data: ServerCreate | None = None
    credential_id: uuid.UUID | None = None
    bastion_name: str | None = None
    status: str = "valid"
    server_id: uuid.UUID | None = None
    host_key: ImportHostKey = field(default_factory=ImportHostKey)

    @property
    def name(self) -> str | None:
        return self.values.get("name") or None

    def err(self, field_name: str, message: str) -> None:
        self.errors.append(ImportFieldError(field=field_name, message=message))


def _file_error(message: str, status: int = 422, code: str = "IMPORT_INVALID_FILE") -> AppError:
    return AppError(code, message, status)


def decode(raw: bytes) -> str:
    if len(raw) > MAX_BYTES:
        raise _file_error("The file is larger than 1 MiB", 413, "IMPORT_FILE_TOO_LARGE")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise _file_error("The file must be UTF-8 encoded") from exc


def _data_lines(text: str) -> list[tuple[int, str]]:
    out = []
    for n, line in enumerate(text.splitlines(), start=1):
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append((n, line))
    return out


def _split(line: str, delimiter: str) -> list[str]:
    try:
        return next(csv.reader([line], delimiter=delimiter, skipinitialspace=True), [])
    except csv.Error:
        return line.split(delimiter)


def detect_delimiter(lines: list[tuple[int, str]]) -> str:
    header = lines[0][1]
    candidates: list[str] = []
    try:
        candidates.append(csv.Sniffer().sniff("\n".join(line for _, line in lines[:5]), delimiters=",;").delimiter)
    except csv.Error:
        pass
    candidates += [d for d in (",", ";") if d not in candidates]
    for d in candidates:                                         # prefer the one that yields known column names
        if {c.strip().lower() for c in _split(header, d)} & set(COLUMNS):
            return d
    return ","


def parse(text: str) -> tuple[str, list[ParsedRow]]:
    lines = _data_lines(text)
    if not lines:
        raise _file_error("The file contains no header line")
    delimiter = detect_delimiter(lines)
    header = [c.strip().lower() for c in _split(lines[0][1], delimiter)]
    unknown = [c for c in header if c not in COLUMNS]
    if unknown:
        raise _file_error(f"Unknown column(s): {', '.join(sanitize_output(c, 40) for c in unknown)}. "
                          f"Allowed: {', '.join(COLUMNS)}")
    dup = {c for c in header if header.count(c) > 1}
    if dup:
        raise _file_error(f"Duplicate column(s): {', '.join(sorted(dup))}")
    missing = [c for c in REQUIRED if c not in header]
    if missing:
        raise _file_error(f"Missing required column(s): {', '.join(missing)}")
    body = lines[1:]
    if len(body) > MAX_ROWS:
        raise _file_error(f"The file has {len(body)} data rows; the maximum is {MAX_ROWS}", 422, "IMPORT_TOO_MANY_ROWS")
    rows: list[ParsedRow] = []
    for n, line in body:
        cells = [c.strip() for c in _split(line, delimiter)]
        if not any(cells):
            continue
        values = {h: (cells[i] if i < len(cells) else "") for i, h in enumerate(header)}
        extra = cells[len(header):]
        if any(extra):
            values["__extra__"] = "1"
        rows.append(ParsedRow(n, values))
    return delimiter, rows


# ------------------------------------------------------------------------------------------------ validation
def _tags(raw: str) -> list[str]:
    return [t.strip() for t in re.split(r"[;|]", raw) if t.strip()]


def _validate(db: Session, parsed: list[ParsedRow], on_conflict: str) -> list[_Row]:
    envs = {e.name.lower(): e.name for e in db.scalars(select(Environment))}
    creds = {c.name.lower(): c.id for c in db.scalars(select(Credential))}
    existing = {s.name.lower(): s for s in db.scalars(select(Server))}
    ssh = settings_service.get_section_data(db, "ssh")
    default_cred = None
    dc = ssh.get("default_credential")
    if dc:
        default_cred = creds.get(str(dc).lower())
    rows = [_Row(p.line, p.values) for p in parsed]
    seen: dict[str, int] = {}
    for r in rows:
        v = r.values
        if v.get("__extra__"):
            r.err("row", "more values than header columns (quote values containing the delimiter)")
        fields: dict[str, Any] = {
            "name": v.get("name", ""), "hostname": v.get("hostname", ""), "address": v.get("address") or None,
            "ssh_username": v.get("ssh_username", ""), "environment": v.get("environment", ""),
            "privilege_mode": v.get("privilege_mode") or "helper-sudo", "tags": _tags(v.get("tags", "")),
            "description": v.get("description") or None,
        }
        port_raw = v.get("ssh_port", "")
        if port_raw:
            if re.fullmatch(r"\d{1,6}", port_raw):
                fields["ssh_port"] = int(port_raw)
            else:
                r.err("ssh_port", "must be an integer between 1 and 65535")
        for req in REQUIRED:
            if not v.get(req):
                r.err(req, "is required")
        try:
            r.data = ServerCreate(**fields)
        except ValidationError as exc:
            for e in exc.errors():
                loc = str(e["loc"][0]) if e["loc"] else "row"
                if not any(x.field == loc for x in r.errors):
                    r.err(loc, str(e["msg"]).removeprefix("Value error, "))
        # environment
        envname = v.get("environment", "")
        canonical = envs.get(envname.lower())
        if envname and canonical is None:
            if not any(e.field == "environment" for e in r.errors):
                r.err("environment", f"environment '{sanitize_output(envname, 64)}' does not exist")
        elif canonical and r.data is not None:
            r.data.environment = canonical
        # credential
        cname = v.get("credential", "")
        if cname:
            r.credential_id = creds.get(cname.lower())
            if r.credential_id is None:
                r.err("credential", f"credential '{sanitize_output(cname, 128)}' does not exist")
        elif default_cred is not None:
            r.credential_id = default_cred
        r.bastion_name = v.get("bastion") or None
        # host key fingerprint
        fp = v.get("host_key_fingerprint", "")
        if fp:
            r.host_key.fingerprint_expected = fp
            if not _FP.match(fp):
                r.err("host_key_fingerprint", "must look like SHA256:<43 base64 characters>")
        # duplicates
        name = (v.get("name") or "").lower()
        if name and not any(e.field == "name" for e in r.errors):
            if name in seen:
                r.err("name", f"duplicate of row {seen[name]} in this file")
            else:
                seen[name] = r.line
                if name in existing:
                    if on_conflict == "skip":
                        r.status = "skipped"
                    else:
                        r.err("name", "a server with this name already exists")
    _resolve_bastions(rows, existing)
    for r in rows:
        if r.errors:
            r.status = "error"
        if r.status in ("error", "skipped"):
            r.host_key = ImportHostKey(fingerprint_expected=r.host_key.fingerprint_expected)
    return rows


def _resolve_bastions(rows: list[_Row], existing: dict[str, Server]) -> None:
    by_name = {(r.name or "").lower(): r for r in rows if r.name}
    for r in rows:
        if not r.bastion_name:
            continue
        key = r.bastion_name.lower()
        me = (r.name or "").lower()
        if key == me:
            r.err("bastion", "a server cannot be its own bastion")
            continue
        target = by_name.get(key)
        if target is not None and target.status != "skipped":
            if target.bastion_name:
                chain = target.bastion_name.lower() == me or (by_name.get(target.bastion_name.lower()) is r)
                r.err("bastion", "bastion cycle detected" if chain
                      else f"bastion '{target.name}' itself uses a bastion; chained bastions are not supported")
        elif key in existing:
            if existing[key].bastion_server_id is not None:
                r.err("bastion", f"bastion '{existing[key].name}' itself uses a bastion; chained bastions are not supported")
        else:
            r.err("bastion", f"bastion '{sanitize_output(r.bastion_name, 128)}' is neither an existing server nor defined in the file")


def _result(rows: list[_Row], *, dry_run: bool, delimiter: str) -> ImportResultOut:
    out = [ImportRowOut(row=r.line, name=r.name, status=r.status, errors=r.errors,  # type: ignore[arg-type]
                        server_id=r.server_id, host_key=r.host_key) for r in rows]
    return ImportResultOut(
        dry_run=dry_run, delimiter=delimiter, total=len(rows),
        valid=sum(r.status in ("valid", "created") for r in rows), invalid=sum(r.status == "error" for r in rows),
        skipped=sum(r.status == "skipped" for r in rows), created=sum(r.status == "created" for r in rows), rows=out)


def _safe_filename(name: str | None) -> str:
    base = (name or "upload.csv").replace("\\", "/").rsplit("/", 1)[-1]
    return re.sub(r"[^A-Za-z0-9._ -]", "_", sanitize_output(base, 120))[:120] or "upload.csv"


# ------------------------------------------------------------------------------------------------ entry point
def run_import(db: Session, actor: User, raw: bytes, *, filename: str | None, dry_run: bool,
               on_conflict: str) -> ImportResultOut:
    delimiter, parsed = parse(decode(raw))
    rows = _validate(db, parsed, on_conflict)
    if dry_run:
        for r in rows:
            if r.status == "valid":
                r.host_key.status = "pending" if r.host_key.fingerprint_expected else "not_provided"
        return _result(rows, dry_run=True, delimiter=delimiter)
    if any(r.status == "error" for r in rows):
        raise AppError("IMPORT_HAS_ERRORS", "The file has invalid rows; nothing was imported", 422,
                       _result(rows, dry_run=False, delimiter=delimiter).model_dump(mode="json"))
    _create_all(db, actor, rows, filename)
    _pin_host_keys(db, actor, rows)
    return _result(rows, dry_run=False, delimiter=delimiter)


def _create_all(db: Session, actor: User, rows: list[_Row], filename: str | None) -> None:
    default_port = settings_service.get_section_data(db, "ssh")["default_port"]
    created: dict[str, Server] = {}
    todo = [r for r in rows if r.status == "valid"]
    try:
        for r in todo:
            d = r.data
            assert d is not None
            s = Server(name=d.name, hostname=d.hostname, address=d.address, ssh_port=d.ssh_port or default_port,
                       ssh_username=d.ssh_username, credential_id=r.credential_id, privilege_mode=d.privilege_mode,
                       environment=d.environment, tags=d.tags, description=d.description, enabled=True)
            db.add(s)
            created[d.name.lower()] = s
        db.flush()
        existing_by_name = {n.lower(): i for n, i in db.execute(select(Server.name, Server.id))}
        for r in todo:
            if r.bastion_name:
                key = r.bastion_name.lower()
                created[(r.name or "").lower()].bastion_server_id = (
                    created[key].id if key in created else existing_by_name[key])
        db.flush()
        for r in todo:
            s = created[(r.name or "").lower()]
            r.server_id, r.status = s.id, "created"
            audit.record(db, action="SERVER_CREATED", resource_type="server", resource_id=s.id, actor=actor,
                         after={**servers_service._snapshot(s), "source": "csv_import"})
        audit.record(db, action="SERVERS_IMPORTED", resource_type="server", actor=actor,
                     after={"filename": _safe_filename(filename), "created": len(todo),
                            "skipped": sum(r.status == "skipped" for r in rows), "total": len(rows)})
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        for r in todo:
            r.status, r.server_id = "valid", None
        raise conflict("SERVER_EXISTS", "A server with one of these names already exists") from exc
    except Exception:
        db.rollback()
        raise


def _pin_host_keys(db: Session, actor: User, rows: list[_Row]) -> None:
    created = [r for r in rows if r.status == "created"]
    for r in created:
        r.host_key.status = "pending"
    pinned = [r for r in created if r.host_key.fingerprint_expected]
    if not pinned:
        return
    servers = {r.server_id: db.get(Server, r.server_id) for r in pinned}
    timeout = float(settings_service.get_section_data(db, "ssh")["connect_timeout"])
    try:
        scans = connectivity.scan_many([(sid, s.address or s.hostname, s.ssh_port) for sid, s in servers.items() if s],
                                       timeout, SCAN_CONCURRENCY)
    except AppError as exc:
        for r in pinned:
            r.host_key.status, r.host_key.error = "unreachable", exc.message
        return
    for r in pinned:
        s = servers[r.server_id]
        info, err = scans.get(r.server_id, (None, {"code": "UNKNOWN", "message": "not scanned"}))
        if info is None:
            r.host_key.status = "unreachable"
            r.host_key.error = f"{(err or {}).get('code', 'UNKNOWN')}: {(err or {}).get('message', '')}"[:200]
            continue
        r.host_key.fingerprint_seen = info.fingerprint_sha256
        if info.fingerprint_sha256 != r.host_key.fingerprint_expected:
            r.host_key.status = "mismatch"
            r.host_key.error = "the server presented a different host key than the pinned fingerprint; not enrolled"
            audit.record(db, action="HOST_KEY_ENROLL", resource_type="server", resource_id=s.id, actor=actor,
                         outcome="failure", error="pinned fingerprint does not match the presented key",
                         after={"expected": r.host_key.fingerprint_expected, "presented": info.fingerprint_sha256})
            db.commit()
            continue
        try:
            connectivity.enroll_host_key(db, actor, s.id, info.public_key_openssh, info.fingerprint_sha256, False,
                                         fresh=info, note="pinned via CSV import")
            r.host_key.status = "enrolled"
        except AppError as exc:
            db.rollback()
            r.host_key.status, r.host_key.error = "unreachable", exc.message


def template_csv() -> str:
    return TEMPLATE

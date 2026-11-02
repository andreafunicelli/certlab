from __future__ import annotations

from typing import Any

from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.errors import AppError, not_found
from app.models import AppSetting, User
from app.repositories import settings as repo
from app.schemas.settings import SECTION_MODELS, SettingsSectionOut
from app.services import audit


def defaults(section: str) -> dict[str, Any]:
    return SECTION_MODELS[section]().model_dump()


def _ensure(db: Session, section: str) -> AppSetting:
    row = repo.get(db, section)
    if row is None:  # migration seeds these; recreate defensively (e.g. after manual deletion)
        row = AppSetting(section=section, data=defaults(section), version=1)
        db.add(row)
        db.commit()
    return row


def _out(row: AppSetting) -> SettingsSectionOut:
    merged = {**defaults(row.section), **(row.data or {})}
    return SettingsSectionOut(section=row.section, version=row.version, data=merged,
                              updated_at=row.updated_at, updated_by=row.updated_by)


def get_all(db: Session) -> dict[str, SettingsSectionOut]:
    return {s: _out(_ensure(db, s)) for s in SECTION_MODELS}


def get_section_data(db: Session, section: str) -> dict[str, Any]:
    """Validated effective values for a section (used by services and workers)."""
    if section not in SECTION_MODELS:
        raise KeyError(section)
    row = repo.get(db, section)
    data = {**defaults(section), **((row.data if row else None) or {})}
    try:
        return SECTION_MODELS[section](**data).model_dump()
    except ValidationError:
        return defaults(section)


def _deep_merge(base: dict, patch: dict) -> dict:
    out = dict(base)
    for k, v in patch.items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def update_section(db: Session, actor: User, section: str, version: int, patch: dict[str, Any]) -> SettingsSectionOut:
    if section not in SECTION_MODELS:
        raise not_found("SETTINGS_SECTION_NOT_FOUND", f"Unknown settings section '{section}'")
    row = _ensure(db, section)
    before = _out(row)
    if version != row.version:
        raise AppError("SETTINGS_VERSION_CONFLICT",
                       "Settings were modified by someone else; reload and retry", 409,
                       {"current_version": row.version})
    merged = _deep_merge(before.data, patch)
    try:
        validated = SECTION_MODELS[section](**merged).model_dump()
    except ValidationError as exc:
        errs = [{"loc": [str(p) for p in e["loc"]], "msg": e["msg"]} for e in exc.errors()]
        raise AppError("VALIDATION_ERROR", "Invalid settings", 422, {"errors": errs}) from exc
    if not repo.compare_and_set(db, section, version, validated, actor.id):
        db.rollback()
        raise AppError("SETTINGS_VERSION_CONFLICT", "Settings were modified by someone else; reload and retry", 409)
    audit.record(db, action="SETTINGS_UPDATED", resource_type="settings", resource_id=section, actor=actor,
                 before=before.data, after=validated)
    db.commit()
    db.expire_all()
    return _out(repo.get(db, section))  # type: ignore[arg-type]

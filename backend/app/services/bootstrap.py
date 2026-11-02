from __future__ import annotations

from app.core.config import Settings
from app.core.db import SessionLocal
from app.core.logging import get_logger
from app.schemas.user import UserCreate  # noqa: F401
from app.services import users

log = get_logger(__name__)


def bootstrap_admin_if_needed(settings: Settings) -> bool:
    """Create the initial admin from CDP_BOOTSTRAP_ADMIN_* only when the users table is empty."""
    if not (settings.bootstrap_admin_username and settings.bootstrap_admin_password):
        return False
    password = settings.bootstrap_admin_password.get_secret_value()
    if len(password) < 12:
        log.error("bootstrap_admin_skipped", reason="password shorter than 12 characters")
        return False
    db = SessionLocal()
    try:
        user = users.bootstrap_admin(db, settings.bootstrap_admin_username, password,
                                     settings.bootstrap_admin_email)
        if user:
            log.info("bootstrap_admin_created", username=user.username)
        return user is not None
    finally:
        db.close()

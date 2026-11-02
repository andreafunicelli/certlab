"""Synchronous SQLAlchemy 2 engine / session factory."""
from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.base import Base  # noqa: F401  (re-exported)


@lru_cache
def get_engine() -> Engine:
    return create_engine(get_settings().database_url, pool_pre_ping=True, pool_size=10, max_overflow=10)


class _SessionFactory:
    """Lazy proxy so the engine is created on first use (after env is configured)."""

    _factory: sessionmaker[Session] | None = None

    def __call__(self) -> Session:
        if self._factory is None:
            self._factory = sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)
        return self._factory()

    def reset(self) -> None:
        self._factory = None


SessionLocal = _SessionFactory()


def reset_engine() -> None:
    get_engine.cache_clear()
    SessionLocal.reset()


def get_db() -> Iterator[Session]:
    """FastAPI dependency. Services commit explicitly; anything uncommitted is rolled back."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()

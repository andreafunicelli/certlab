"""Application settings (environment prefix ``CDP_``)."""
from __future__ import annotations

import base64
import binascii
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class ConfigError(RuntimeError):
    """Raised when mandatory configuration is missing or invalid (the app refuses to start)."""


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CDP_", env_file=None, extra="ignore")

    env: Literal["dev", "prod", "test"] = "prod"
    database_url: str = "postgresql+psycopg://cdp:cdp-dev-only@127.0.0.1:5432/cdp"
    redis_url: str = "redis://127.0.0.1:6379/0"

    # envelope encryption
    master_key: SecretStr | None = None            # base64 of 32 random bytes
    master_key_file: Path | None = None
    artifact_dir: Path = Path("/var/lib/cdp/artifacts")

    # sessions / cookies
    session_ttl: int = 8 * 3600                    # seconds; upper bound, security.session_minutes may shorten
    cookie_secure: bool = True
    cookie_domain: str | None = None
    cors_origins: Annotated[list[str], NoDecode] = []
    trust_proxy_headers: bool = False              # honour X-Forwarded-For (only behind our own proxy)
    public_base_url: str | None = None             # used to build OIDC redirect URI

    # one-time bootstrap
    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: SecretStr | None = None
    bootstrap_admin_email: str | None = None

    # OIDC (authorization code + PKCE)
    oidc_issuer: str | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: SecretStr | None = None
    oidc_scopes: str = "openid profile email groups"
    oidc_groups_claim: str = "groups"
    oidc_admin_groups: Annotated[list[str], NoDecode] = []
    oidc_operator_groups: Annotated[list[str], NoDecode] = []
    oidc_auto_provision: bool = True

    # rate limiting
    rate_limit_backend: Literal["redis", "memory"] = "redis"
    rate_limit_login_per_minute: int = 10
    rate_limit_api_per_minute: int = 600

    log_level: str = "INFO"

    @field_validator("cors_origins", "oidc_admin_groups", "oidc_operator_groups", mode="before")
    @classmethod
    def _split_csv(cls, v):
        if isinstance(v, str):
            s = v.strip()
            if s.startswith("["):
                import json

                return json.loads(s)
            return [p.strip() for p in s.split(",") if p.strip()]
        return v

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer and self.oidc_client_id and self.oidc_client_secret)

    def resolve_master_key(self) -> bytes:
        """Return the 32-byte KEK or raise ConfigError. Never logs the key."""
        raw: str | None = None
        if self.master_key is not None and self.master_key.get_secret_value().strip():
            raw = self.master_key.get_secret_value().strip()
        elif self.master_key_file is not None:
            try:
                raw = self.master_key_file.read_text().strip()
            except OSError as exc:
                raise ConfigError(f"CDP_MASTER_KEY_FILE is not readable: {exc.strerror}") from exc
        if not raw:
            raise ConfigError("CDP_MASTER_KEY or CDP_MASTER_KEY_FILE must be set (base64 of 32 random bytes)")
        try:
            key = base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=False)
        except (binascii.Error, ValueError) as exc:
            raise ConfigError("master key is not valid base64") from exc
        if len(key) != 32:
            raise ConfigError("master key must decode to exactly 32 bytes")
        return key


@lru_cache
def get_settings() -> Settings:
    return Settings()


def reset_settings_cache() -> None:
    get_settings.cache_clear()

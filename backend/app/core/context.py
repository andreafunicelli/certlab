"""Per-request context carried in contextvars (correlation id, client ip, user agent)."""
from __future__ import annotations

from contextvars import ContextVar

correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)
client_ip_var: ContextVar[str | None] = ContextVar("client_ip", default=None)
user_agent_var: ContextVar[str | None] = ContextVar("user_agent", default=None)


def get_correlation_id() -> str | None:
    return correlation_id_var.get()

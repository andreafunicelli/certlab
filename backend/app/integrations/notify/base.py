from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class ChannelError(Exception):
    """Delivery failure. ``message`` is safe to store/show (never contains secrets)."""

    def __init__(self, message: str, *, retryable: bool = True):
        super().__init__(message)
        self.message = message
        self.retryable = retryable


@dataclass(frozen=True)
class Message:
    event_type: str
    severity: str
    subject: str
    text: str
    payload: dict[str, Any] = field(default_factory=dict)
    event_id: str = ""
    created_at: str = ""

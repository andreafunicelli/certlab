from __future__ import annotations

from datetime import datetime


def compute_status(not_after: datetime, now: datetime, warn_days: int = 30, critical_days: int = 7) -> str:
    """valid | expiring (<=30d) | critical (<=7d) | expired."""
    if not_after <= now:
        return "expired"
    days = (not_after - now).total_seconds() / 86400
    if days <= critical_days:
        return "critical"
    if days <= warn_days:
        return "expiring"
    return "valid"

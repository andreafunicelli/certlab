from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from app.schemas.common import ORMModel


class AuditEventOut(ORMModel):
    id: uuid.UUID
    ts: datetime
    actor_user_id: uuid.UUID | None
    actor_name: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    before: Any | None
    after: Any | None
    ip: str | None
    user_agent: str | None
    correlation_id: str | None
    outcome: str
    error: str | None


_ = (Any,)

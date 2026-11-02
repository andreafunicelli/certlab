from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.db import get_db
from app.schemas.common import Page, PageParams
from app.schemas.inventory import ChannelCreate, ChannelUpdate, RuleCreate, RuleUpdate
from app.services import notifications as service
from app.services.auth import AuthContext

router = APIRouter(prefix="/notifications", tags=["notifications"])
READ, WRITE = "notifications:read", "notifications:write"


@router.get("/event-types")
def event_types(_: AuthContext = Depends(require_permission(READ))) -> dict[str, Any]:
    return {"event_types": list(service.EVENT_TYPES), "severities": list(service.SEVERITY_ORDER)}


@router.get("/channels")
def list_channels(_: AuthContext = Depends(require_permission(READ)), db: Session = Depends(get_db)):
    return service.list_channels(db)


@router.post("/channels", status_code=201)
def create_channel(body: ChannelCreate, ctx: AuthContext = Depends(require_permission(WRITE)),
                   db: Session = Depends(get_db)):
    return service.create_channel(db, ctx.user, name=body.name, type=body.type, config=body.config,
                                  secret=body.secret, enabled=body.enabled)


@router.get("/channels/{channel_id}")
def get_channel(channel_id: uuid.UUID, _: AuthContext = Depends(require_permission(READ)), db: Session = Depends(get_db)):
    return service.get_channel(db, channel_id)


@router.patch("/channels/{channel_id}")
def update_channel(channel_id: uuid.UUID, body: ChannelUpdate, ctx: AuthContext = Depends(require_permission(WRITE)),
                   db: Session = Depends(get_db)):
    return service.update_channel(db, ctx.user, channel_id, fields=set(body.model_fields_set), name=body.name,
                                  config=body.config, secret=body.secret, clear_secret=body.clear_secret,
                                  enabled=body.enabled)


@router.delete("/channels/{channel_id}", status_code=204)
def delete_channel(channel_id: uuid.UUID, ctx: AuthContext = Depends(require_permission(WRITE)),
                   db: Session = Depends(get_db)):
    service.delete_channel(db, ctx.user, channel_id)
    return Response(status_code=204)


@router.post("/channels/{channel_id}/test")
def test_channel(channel_id: uuid.UUID, ctx: AuthContext = Depends(require_permission(WRITE)),
                 db: Session = Depends(get_db)):
    return service.test_channel(db, ctx.user, channel_id)


@router.get("/rules")
def list_rules(_: AuthContext = Depends(require_permission(READ)), db: Session = Depends(get_db)):
    return service.list_rules(db)


@router.post("/rules", status_code=201)
def create_rule(body: RuleCreate, ctx: AuthContext = Depends(require_permission(WRITE)), db: Session = Depends(get_db)):
    return service.create_rule(db, ctx.user, **body.model_dump())


@router.patch("/rules/{rule_id}")
def update_rule(rule_id: uuid.UUID, body: RuleUpdate, ctx: AuthContext = Depends(require_permission(WRITE)),
                db: Session = Depends(get_db)):
    return service.update_rule(db, ctx.user, rule_id, body.model_dump(include=body.model_fields_set))


@router.delete("/rules/{rule_id}", status_code=204)
def delete_rule(rule_id: uuid.UUID, ctx: AuthContext = Depends(require_permission(WRITE)), db: Session = Depends(get_db)):
    service.delete_rule(db, ctx.user, rule_id)
    return Response(status_code=204)


@router.get("/deliveries", response_model=Page[dict[str, Any]])
def list_deliveries(status: str | None = None, event_type: str | None = None, channel_id: uuid.UUID | None = None,
                    p: PageParams = Depends(), _: AuthContext = Depends(require_permission(READ)),
                    db: Session = Depends(get_db)):
    items, total = service.list_deliveries(db, offset=p.offset, limit=p.page_size, status=status,
                                           event_type=event_type, channel_id=channel_id)
    return Page(items=items, total=total, page=p.page, page_size=p.page_size)

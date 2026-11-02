from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy.orm import Session

from app.api.deps import require_permission
from app.core.db import get_db
from app.repositories import users as repo
from app.schemas.common import Page, PageParams
from app.schemas.user import RolesUpdate, UserCreate, UserOut, UserUpdate
from app.services import users as service
from app.services.auth import AuthContext

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=Page[UserOut])
def list_users(q: str | None = Query(None, max_length=100), p: PageParams = Depends(),
               _: AuthContext = Depends(require_permission("users:read")), db: Session = Depends(get_db)):
    rows, total = repo.list_page(db, q, p.offset, p.page_size)
    return Page(items=[UserOut.model_validate(u) for u in rows], total=total, page=p.page, page_size=p.page_size)


@router.post("", response_model=UserOut, status_code=201)
def create_user(body: UserCreate, ctx: AuthContext = Depends(require_permission("users:write")),
                db: Session = Depends(get_db)):
    return UserOut.model_validate(service.create(db, ctx.user, body))


@router.get("/{user_id}", response_model=UserOut)
def get_user(user_id: uuid.UUID, _: AuthContext = Depends(require_permission("users:read")),
             db: Session = Depends(get_db)):
    return UserOut.model_validate(service.get(db, user_id))


@router.patch("/{user_id}", response_model=UserOut)
def update_user(user_id: uuid.UUID, body: UserUpdate, ctx: AuthContext = Depends(require_permission("users:write")),
                db: Session = Depends(get_db)):
    return UserOut.model_validate(service.update(db, ctx.user, user_id, body))


@router.patch("/{user_id}/roles", response_model=UserOut)
def update_roles(user_id: uuid.UUID, body: RolesUpdate, ctx: AuthContext = Depends(require_permission("users:roles")),
                 db: Session = Depends(get_db)):
    return UserOut.model_validate(service.set_roles(db, ctx.user, user_id, body))


@router.delete("/{user_id}", status_code=204)
def delete_user(user_id: uuid.UUID, ctx: AuthContext = Depends(require_permission("users:write")),
                db: Session = Depends(get_db)):
    service.delete(db, ctx.user, user_id)
    return Response(status_code=204)

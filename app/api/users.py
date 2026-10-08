import logging
from typing import List
from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from app.core.exceptions import ForbiddenException, NotFoundException
from app.db import crud
from app.db.database import get_db
from app.db.models import User
from app.middleware.auth import get_current_user
from app.schemas import AuditLogResponse, UserResponse

logger = logging.getLogger("secureshare.users_api")

router = APIRouter(prefix="/users", tags=["Users Management"])


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Get Current User Profile",
    description="Returns the profile information of the currently authenticated user."
)
def get_current_user_profile(
    current_user: User = Depends(get_current_user)
):
    return current_user


@router.get(
    "/me/audit-logs",
    response_model=List[AuditLogResponse],
    summary="Get User Audit Logs",
    description="Returns the security audit activity logs for the authenticated user."
)
def get_user_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    logs = crud.get_audit_logs_for_user(db, user_id=current_user.id, skip=skip, limit=limit)
    return [AuditLogResponse.model_validate(log) for log in logs]


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    summary="Get User By ID",
    description="Retrieve public profile for a user ID (restricted to self or administrators)."
)
def get_user_by_id(
    user_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.id != user_id:
        raise ForbiddenException("You can only inspect your own user profile.")

    user = crud.get_user_by_id(db, user_id)
    if not user:
        raise NotFoundException("User not found.")
    return user

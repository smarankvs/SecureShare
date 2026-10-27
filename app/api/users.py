import logging
from typing import List
from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from app.core.exceptions import BadRequestException, ForbiddenException, NotFoundException
from app.db import crud
from app.db.database import get_db
from app.db.models import User
from app.middleware.auth import get_current_user
from app.schemas import AuditLogResponse, RoleUpdateRequest, UserResponse

logger = logging.getLogger("secureshare.users_api")

router = APIRouter(prefix="/users", tags=["Users Management"])


def _extract_request_context(request: Request):
    return {
        "ip_address": getattr(request.state, "client_ip", "unknown") or "unknown",
        "user_agent": getattr(request.state, "user_agent", "unknown") or "unknown",
        "request_id": getattr(request.state, "request_id", "unknown") or "unknown",
    }


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
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ctx = _extract_request_context(request)

    if current_user.id != user_id and getattr(current_user, "role", "user") != "admin":
        crud.create_audit_log(
            db,
            action="PERMISSION_DENIED",
            user_id=current_user.id,
            username=current_user.email,
            resource=f"users/{user_id}",
            ip_address=ctx["ip_address"],
            user_agent=ctx["user_agent"],
            request_id=ctx["request_id"],
            status="ALERT",
            details=f"User {current_user.email} attempted unauthorized profile read of user {user_id}"
        )
        raise ForbiddenException("You can only inspect your own user profile.")

    user = crud.get_user_by_id(db, user_id)
    if not user:
        raise NotFoundException("User not found.")
    return user


@router.patch(
    "/{user_id}/role",
    response_model=UserResponse,
    summary="Update User Role",
    description="Assigns a new role ('admin' or 'user') to a target user. Restricted to administrators."
)
def update_user_role(
    user_id: str,
    role_in: RoleUpdateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ctx = _extract_request_context(request)
    target_role = role_in.role.lower().strip()

    if target_role not in ("admin", "user"):
        raise BadRequestException("Role must be either 'admin' or 'user'.")

    # Access control: only existing administrators may assign roles
    if getattr(current_user, "role", "user") != "admin":
        crud.create_audit_log(
            db,
            action="PERMISSION_DENIED",
            user_id=current_user.id,
            username=current_user.email,
            resource=f"users/{user_id}/role",
            ip_address=ctx["ip_address"],
            user_agent=ctx["user_agent"],
            request_id=ctx["request_id"],
            status="ALERT",
            details=f"Non-admin user {current_user.email} attempted to change role for user {user_id}"
        )
        raise ForbiddenException("Only administrators can modify user roles.")

    target_user = crud.get_user_by_id(db, user_id)
    if not target_user:
        raise NotFoundException("Target user not found.")

    old_role = target_user.role
    updated_user = crud.update_user_role(db, user_id, target_role)

    crud.create_audit_log(
        db,
        action="ROLE_CHANGE",
        user_id=current_user.id,
        username=current_user.email,
        resource=f"users/{user_id}/role",
        ip_address=ctx["ip_address"],
        user_agent=ctx["user_agent"],
        request_id=ctx["request_id"],
        status="SUCCESS",
        details=f"Admin {current_user.email} changed role of user {target_user.email} from '{old_role}' to '{target_role}'"
    )

    return updated_user

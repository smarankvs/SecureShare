import logging
from datetime import timedelta
from typing import Optional
import jwt
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import (
    BadRequestException,
    ConflictException,
    UnauthorizedException
)
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_password,
    validate_password_strength,
    verify_password
)
from app.db import crud
from app.db.database import get_db
from app.db.models import User
from app.middleware.auth import get_current_user
from app.schemas import (
    ChangePasswordRequest,
    LoginRequest,
    MessageResponse,
    RefreshTokenRequest,
    TokenResponse,
    UserCreate,
    UserResponse
)

logger = logging.getLogger("secureshare.auth_api")

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _extract_request_context(request: Request):
    """Helper to extract correlation ID, real client IP, and User-Agent."""
    return {
        "ip_address": getattr(request.state, "client_ip", "unknown") or "unknown",
        "user_agent": getattr(request.state, "user_agent", "unknown") or "unknown",
        "request_id": getattr(request.state, "request_id", "unknown") or "unknown",
    }


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
    description="Registers a new user with bcrypt password hashing and input validation."
)
def register_user(
    request: Request,
    user_in: UserCreate,
    db: Session = Depends(get_db)
):
    ctx = _extract_request_context(request)

    # 1. Enforce enterprise password complexity policy
    if not validate_password_strength(user_in.password):
        crud.create_audit_log(
            db,
            action="REGISTRATION_FAILED",
            username=user_in.email,
            resource="auth/register",
            ip_address=ctx["ip_address"],
            user_agent=ctx["user_agent"],
            request_id=ctx["request_id"],
            status="FAILED",
            details="Password did not meet minimum complexity rules."
        )
        raise BadRequestException(
            "Password must be 8-72 characters long and include at least one uppercase letter, "
            "one lowercase letter, one digit, and one special character (@$!%*?&#^_-)."
        )

    # 2. Check for duplicate email
    existing_user = crud.get_user_by_email(db, user_in.email)
    if existing_user:
        logger.warning(f"Registration conflict: email '{user_in.email}' already registered.")
        crud.create_audit_log(
            db,
            action="REGISTRATION_FAILED",
            username=user_in.email,
            resource="auth/register",
            ip_address=ctx["ip_address"],
            user_agent=ctx["user_agent"],
            request_id=ctx["request_id"],
            status="FAILED",
            details=f"Email conflict: {user_in.email}"
        )
        raise ConflictException("A user with this email address already exists.")

    # 3. Create user record
    new_user = crud.create_user(db, user_in)
    logger.info(f"User registered successfully: {new_user.email} (ID: {new_user.id})")

    # 4. Audit Log (Registration)
    crud.create_audit_log(
        db,
        action="REGISTRATION",
        user_id=new_user.id,
        username=new_user.email,
        resource="auth/register",
        ip_address=ctx["ip_address"],
        user_agent=ctx["user_agent"],
        request_id=ctx["request_id"],
        status="SUCCESS",
        details=f"Registered account: {new_user.email}"
    )

    return new_user


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="User Login",
    description="Authenticates user credentials and issues cryptographic JWT Access and Refresh tokens."
)
def login(
    request: Request,
    login_data: LoginRequest,
    db: Session = Depends(get_db)
):
    ctx = _extract_request_context(request)
    user = crud.get_user_by_email(db, login_data.email)

    if not user or not verify_password(login_data.password, user.password_hash):
        logger.warning(f"Failed login attempt for email: {login_data.email} from IP: {ctx['ip_address']}")
        crud.create_audit_log(
            db,
            action="FAILED_LOGIN",
            user_id=user.id if user else None,
            username=login_data.email,
            resource="auth/login",
            ip_address=ctx["ip_address"],
            user_agent=ctx["user_agent"],
            request_id=ctx["request_id"],
            status="FAILED",
            details=f"Failed login attempt for {login_data.email}"
        )
        raise UnauthorizedException("Invalid email or password.")

    if not user.is_active:
        crud.create_audit_log(
            db,
            action="LOGIN_BLOCKED",
            user_id=user.id,
            username=user.email,
            resource="auth/login",
            ip_address=ctx["ip_address"],
            user_agent=ctx["user_agent"],
            request_id=ctx["request_id"],
            status="FAILED",
            details="Account is inactive."
        )
        raise UnauthorizedException("Account has been deactivated. Please contact support.")

    # Generate Access and Refresh Tokens
    access_token = create_access_token(
        subject=user.id,
        extra_claims={"email": user.email, "name": user.name, "role": user.role}
    )
    refresh_token = create_refresh_token(subject=user.id)

    # Audit Log (Login)
    crud.create_audit_log(
        db,
        action="LOGIN",
        user_id=user.id,
        username=user.email,
        resource="auth/login",
        ip_address=ctx["ip_address"],
        user_agent=ctx["user_agent"],
        request_id=ctx["request_id"],
        status="SUCCESS",
        details=f"User authenticated: {user.email}"
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post(
    "/logout",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="User Logout",
    description="Logs out the authenticated user and records an audit log event."
)
def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ctx = _extract_request_context(request)

    # Audit Log (Logout)
    crud.create_audit_log(
        db,
        action="LOGOUT",
        user_id=current_user.id,
        username=current_user.email,
        resource="auth/logout",
        ip_address=ctx["ip_address"],
        user_agent=ctx["user_agent"],
        request_id=ctx["request_id"],
        status="SUCCESS",
        details=f"User {current_user.email} signed out successfully."
    )

    return MessageResponse(message="Successfully logged out.")


@router.post(
    "/change-password",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Change Password",
    description="Changes password for currently authenticated user with strength validation."
)
def change_password(
    request: Request,
    payload: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ctx = _extract_request_context(request)

    # 1. Verify current password
    if not current_user.password_hash or not verify_password(payload.current_password, current_user.password_hash):
        crud.create_audit_log(
            db,
            action="PASSWORD_CHANGE_FAILED",
            user_id=current_user.id,
            username=current_user.email,
            resource="auth/change-password",
            ip_address=ctx["ip_address"],
            user_agent=ctx["user_agent"],
            request_id=ctx["request_id"],
            status="FAILED",
            details="Invalid current password provided."
        )
        raise UnauthorizedException("Current password verification failed.")

    # 2. Validate new password strength
    if not validate_password_strength(payload.new_password):
        crud.create_audit_log(
            db,
            action="PASSWORD_CHANGE_FAILED",
            user_id=current_user.id,
            username=current_user.email,
            resource="auth/change-password",
            ip_address=ctx["ip_address"],
            user_agent=ctx["user_agent"],
            request_id=ctx["request_id"],
            status="FAILED",
            details="New password failed complexity validation."
        )
        raise BadRequestException(
            "New password must be 8-72 characters long and include at least one uppercase letter, "
            "one lowercase letter, one digit, and one special character (@$!%*?&#^_-)."
        )

    # 3. Hash and persist new password
    hashed_pwd = hash_password(payload.new_password)
    crud.update_user_password(db, current_user.id, hashed_pwd)

    # 4. Audit Log (Password change)
    crud.create_audit_log(
        db,
        action="PASSWORD_CHANGE",
        user_id=current_user.id,
        username=current_user.email,
        resource="auth/change-password",
        ip_address=ctx["ip_address"],
        user_agent=ctx["user_agent"],
        request_id=ctx["request_id"],
        status="SUCCESS",
        details="User password updated successfully."
    )

    return MessageResponse(message="Password changed successfully.")


@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh Access Token",
    description="Issues a fresh JWT Access and Refresh token pair using a valid refresh token."
)
def refresh_token(
    request: Request,
    refresh_in: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    ctx = _extract_request_context(request)

    try:
        payload = decode_token(refresh_in.refresh_token)
    except jwt.ExpiredSignatureError:
        raise UnauthorizedException("Refresh token has expired. Please log in again.")
    except jwt.PyJWTError:
        raise UnauthorizedException("Invalid refresh token.")

    token_type = payload.get("type")
    if token_type != "refresh":
        raise UnauthorizedException("Invalid token type. Refresh token required.")

    user_id = payload.get("sub")
    user = crud.get_user_by_id(db, user_id)
    if not user or not user.is_active:
        raise UnauthorizedException("User no longer exists or account is inactive.")

    new_access_token = create_access_token(
        subject=user.id,
        extra_claims={"email": user.email, "name": user.name, "role": user.role}
    )
    new_refresh_token = create_refresh_token(subject=user.id)

    # Audit Log (Token refresh)
    crud.create_audit_log(
        db,
        action="TOKEN_REFRESH",
        user_id=user.id,
        username=user.email,
        resource="auth/refresh",
        ip_address=ctx["ip_address"],
        user_agent=ctx["user_agent"],
        request_id=ctx["request_id"],
        status="SUCCESS",
        details="Refreshed session tokens"
    )

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

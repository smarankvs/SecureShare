import logging
from datetime import timedelta
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
    validate_password_strength,
    verify_password
)
from app.db import crud
from app.db.database import get_db
from app.schemas import (
    LoginRequest,
    RefreshTokenRequest,
    TokenResponse,
    UserCreate,
    UserResponse
)

logger = logging.getLogger("secureshare.auth_api")

router = APIRouter(prefix="/auth", tags=["Authentication"])


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
    client_ip = getattr(request.state, "client_ip", "unknown")

    # 1. Enforce enterprise password complexity policy
    if not validate_password_strength(user_in.password):
        crud.create_audit_log(
            db,
            action="USER_REGISTRATION_FAILED",
            ip_address=client_ip,
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
            action="USER_REGISTRATION_FAILED",
            ip_address=client_ip,
            status="FAILED",
            details=f"Email conflict: {user_in.email}"
        )
        raise ConflictException("A user with this email address already exists.")

    # 3. Create user record
    new_user = crud.create_user(db, user_in)
    logger.info(f"User registered successfully: {new_user.email} (ID: {new_user.id})")

    # 4. Audit Log
    crud.create_audit_log(
        db,
        action="USER_REGISTERED",
        user_id=new_user.id,
        ip_address=client_ip,
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
    client_ip = getattr(request.state, "client_ip", "unknown")
    user = crud.get_user_by_email(db, login_data.email)

    if not user or not verify_password(login_data.password, user.password_hash):
        logger.warning(f"Failed login attempt for email: {login_data.email} from IP: {client_ip}")
        crud.create_audit_log(
            db,
            action="LOGIN_FAILED",
            user_id=user.id if user else None,
            ip_address=client_ip,
            status="FAILED",
            details=f"Failed login attempt for {login_data.email}"
        )
        raise UnauthorizedException("Invalid email or password.")

    if not user.is_active:
        crud.create_audit_log(
            db,
            action="LOGIN_BLOCKED",
            user_id=user.id,
            ip_address=client_ip,
            status="FAILED",
            details="Account is inactive."
        )
        raise UnauthorizedException("Account has been deactivated. Please contact support.")

    # Generate Access and Refresh Tokens
    access_token = create_access_token(
        subject=user.id,
        extra_claims={"email": user.email, "name": user.name}
    )
    refresh_token = create_refresh_token(subject=user.id)

    crud.create_audit_log(
        db,
        action="LOGIN_SUCCESS",
        user_id=user.id,
        ip_address=client_ip,
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
    client_ip = getattr(request.state, "client_ip", "unknown")

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
        extra_claims={"email": user.email, "name": user.name}
    )
    new_refresh_token = create_refresh_token(subject=user.id)

    crud.create_audit_log(
        db,
        action="TOKEN_REFRESH",
        user_id=user.id,
        ip_address=client_ip,
        status="SUCCESS",
        details="Refreshed session tokens"
    )

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )

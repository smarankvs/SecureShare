import logging
from typing import Optional
import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from app.core.config import settings
from app.core.exceptions import UnauthorizedException
from app.core.security import decode_token
from app.db.database import get_db
from app.db.models import User
from app.db import crud

logger = logging.getLogger("secureshare.auth")

security_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db)
) -> User:
    """
    FastAPI dependency to extract and validate the JWT Bearer access token.
    Enforces expiration check, signature validation, and active user verification.
    """
    if not credentials:
        raise UnauthorizedException("Authentication token is missing.")

    token = credentials.credentials
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise UnauthorizedException("Access token has expired. Please refresh your session.")
    except jwt.PyJWTError as exc:
        logger.warning(f"Failed JWT verification attempt: {exc}")
        raise UnauthorizedException("Invalid authentication token.")

    token_type = payload.get("type")
    if token_type != "access":
        raise UnauthorizedException("Invalid token type. Access token required.")

    user_id = payload.get("sub")
    if not user_id:
        raise UnauthorizedException("Token missing subject identifier.")

    user = crud.get_user_by_id(db, user_id)
    if not user:
        raise UnauthorizedException("User associated with this token does not exist.")

    if not user.is_active:
        raise UnauthorizedException("User account is disabled.")

    return user


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """
    ASGI Middleware that extracts JWT credentials and attaches authenticated user
    context to request.state for downstream audit logging and request tracking.
    Does not reject unauthenticated requests so public endpoints remain accessible.
    """
    async def dispatch(self, request: Request, call_next):
        auth_header = request.headers.get("Authorization")
        request.state.user = None

        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            try:
                payload = decode_token(token)
                if payload.get("type") == "access":
                    request.state.user_id = payload.get("sub")
            except Exception:
                # Middleware attaches None on error; endpoint security dependencies enforce 401
                pass

        response = await call_next(request)
        return response

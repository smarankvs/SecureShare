import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union
import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash
import jwt

from app.core.config import settings

# Initialize Argon2id password hasher (RFC 9106 recommended parameters)
_password_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)

# Password complexity policy
PASSWORD_REGEX = re.compile(
    r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#^_\-])[A-Za-z\d@$!%*?&#^_\-]{8,72}$"
)


def validate_password_strength(password: str) -> bool:
    """
    Validate that password meets enterprise cybersecurity guidelines:
    - Between 8 and 72 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special symbol
    """
    return bool(PASSWORD_REGEX.match(password))


def hash_password(password: str) -> str:
    """
    Hash a plain password using Argon2id with cryptographically secure salt.
    """
    return _password_hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against the stored Argon2id hash (with legacy bcrypt fallback).
    """
    if not hashed_password or not plain_password:
        return False
    try:
        if hashed_password.startswith("$argon2"):
            return _password_hasher.verify(hashed_password, plain_password)
        elif hashed_password.startswith("$2b$") or hashed_password.startswith("$2a$"):
            return bcrypt.checkpw(
                plain_password.encode("utf-8"),
                hashed_password.encode("utf-8")
            )
        return False
    except (VerifyMismatchError, VerificationError, InvalidHash, Exception):
        return False


def create_access_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None
) -> str:
    """
    Generate a cryptographically signed JWT Access Token.
    Includes standard claims (sub, exp, iat, jti, type).
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": str(subject),
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4())
    }

    if extra_claims:
        payload.update(extra_claims)

    encoded_jwt = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def create_refresh_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Generate a long-lived JWT Refresh Token for session renewal.
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    payload: Dict[str, Any] = {
        "sub": str(subject),
        "type": "refresh",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": str(uuid.uuid4())
    }

    encoded_jwt = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    return encoded_jwt


def decode_token(token: str) -> Dict[str, Any]:
    """
    Decode and verify JWT signature and expiration.
    Raises jwt.PyJWTError on invalid or expired token.
    """
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM]
    )

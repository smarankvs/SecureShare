"""
Shared API dependencies.

Authentication (Microsoft Entra ID token validation) belongs to the auth
module. That module is expected to set ``request.state.principal`` to an
object/dict exposing ``oid`` (Entra object id) and ``email``. Until it is
merged, **development/test only** callers may pass ``X-Dev-Entra-OID`` and
``X-Dev-Email`` headers; these are ignored in production.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import User, UserStatus
from app.db.session import get_db


@dataclass(frozen=True)
class Principal:
    oid: str
    email: str


def get_principal(request: Request) -> Principal:
    p = getattr(request.state, "principal", None)
    if p is not None:
        get = p.get if isinstance(p, dict) else lambda k: getattr(p, k, None)
        oid, email = get("oid"), get("email") or get("preferred_username")
        if oid and email:
            return Principal(oid=str(oid), email=str(email).lower())

    if not settings.is_production:
        oid = request.headers.get("X-Dev-Entra-OID")
        email = request.headers.get("X-Dev-Email")
        if oid and email:
            return Principal(oid=oid, email=email.lower())

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


def get_current_user(principal: Principal = Depends(get_principal), db: Session = Depends(get_db)) -> User:
    """Resolve (or just-in-time provision) the local user row for the Entra principal."""
    user = db.scalar(select(User).where(User.entra_object_id == principal.oid))
    if user is None:
        user = User(entra_object_id=principal.oid, email=principal.email, status=UserStatus.ACTIVE)
        db.add(user)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            user = db.scalar(select(User).where(User.entra_object_id == principal.oid))
            if user is None:
                raise HTTPException(status.HTTP_409_CONFLICT, "User provisioning conflict")
    if user.status != UserStatus.ACTIVE:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account disabled")
    return user


def client_ip(request: Request) -> str | None:
    """Return the peer IP if it is a valid IPv4/IPv6 address, else None."""
    host = request.client.host if request.client else None
    try:
        return str(ipaddress.ip_address(host)) if host else None
    except ValueError:
        return None

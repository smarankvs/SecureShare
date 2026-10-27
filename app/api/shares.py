"""Sharing, revocation and download-gatekeeper endpoints (Member 2 module)."""
import logging

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from app.core import authz
from app.db import crud
from app.db.database import get_db
from app.db.models import User
from app.middleware.auth import get_current_user
from app.schemas import (
    ShareCreate,
    ShareCreatedResponse,
    ShareDownloadRequest,
    ShareDownloadResponse,
    ShareListResponse,
    ShareResponse,
    ShareRevokeResponse,
)
from app.services import share_service

logger = logging.getLogger("secureshare.shares_api")

router = APIRouter(prefix="/shares", tags=["Sharing & Access Control"])


def _client_ip(request: Request) -> str:
    return getattr(request.state, "client_ip", "unknown") or "unknown"


@router.post(
    "",
    response_model=ShareCreatedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a share grant",
    description=(
        "Creates a recipient-bound, time-limited, quota-limited share. "
        "Generates a 256-bit token via secrets.token_urlsafe(32) and persists only "
        "its SHA-256 hash. The raw token is returned exactly once, in this response."
    ),
)
def create_share(
    payload: ShareCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Deny-by-default: ownership is validated before any share state is written.
    file_record = authz.get_owned_file(
        db,
        payload.file_id,
        current_user,
        ip_address=_client_ip(request),
        audit_action="UNAUTHORIZED_SHARE_CREATE_ATTEMPT",
    )

    share, raw_token = share_service.create_share(
        db=db,
        file_record=file_record,
        owner=current_user,
        recipient_email=str(payload.recipient_email),
        expires_at=payload.expires_at,
        max_downloads=payload.max_downloads,
        ip_address=_client_ip(request),
    )

    return ShareCreatedResponse(
        share_id=share.id,
        file_id=share.file_id,
        recipient_email=share.recipient_email,
        token=raw_token,
        token_prefix=share.token_prefix,
        share_url=share_service.build_share_url(raw_token),
        expires_at=share.expires_at,
        max_downloads=share.max_downloads,
        status=share.status,
    )


@router.get(
    "",
    response_model=ShareListResponse,
    summary="List share grants",
    description="Lists shares created by, or covering files owned by, the caller. Token material is never returned.",
)
def list_shares(
    file_id: str | None = Query(None, description="Filter by file ID"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    shares, total = crud.list_shares_for_user(
        db, user_id=current_user.id, file_id=file_id, skip=skip, limit=limit
    )
    return ShareListResponse(
        total=total,
        shares=[ShareResponse.model_validate(s) for s in shares],
    )


@router.post(
    "/{share_id}/revoke",
    response_model=ShareRevokeResponse,
    summary="Revoke a share grant",
    description=(
        "Validates caller ownership, then sets status=REVOKED and revoked_at=now(). "
        "Revocation takes effect immediately for all subsequent download attempts."
    ),
)
def revoke_share(
    share_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    share = authz.get_owned_share(db, share_id, current_user, ip_address=_client_ip(request))
    revoked = share_service.revoke_share(
        db, share, current_user, ip_address=_client_ip(request)
    )
    return ShareRevokeResponse(
        id=revoked.id,
        status=revoked.status,
        revoked_at=revoked.revoked_at,
    )


@router.post(
    "/download",
    response_model=ShareDownloadResponse,
    summary="Download through a share link (gatekeeper)",
    description=(
        "Accepts the bearer token in the request body so it never enters URL logs. "
        "Evaluates the four policy gates atomically (ACTIVE, unexpired, quota remaining, "
        "correct recipient), then issues a short-lived SAS URL via the storage service "
        "and records an access event."
    ),
)
def download_shared_file(
    payload: ShareDownloadRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    share, file_record, download_url, remaining = share_service.open_share(
        db=db,
        token=payload.token,
        user=current_user,
        ip_address=_client_ip(request),
    )

    return ShareDownloadResponse(
        share_id=share.id,
        file_name=file_record.original_name,
        content_type=file_record.content_type,
        size=file_record.size,
        sha256_hash=file_record.sha256_hash,
        download_url=download_url,
        expires_in_seconds=share_service.settings.SHARE_SAS_EXPIRY_MINUTES * 60,
        remaining_downloads=remaining,
    )


@router.post(
    "/{token}/download",
    response_model=ShareDownloadResponse,
    include_in_schema=False,
    deprecated=True,
    summary="Legacy path-based download (token in URL)",
    description=(
        "Kept only for compatibility with the original specification. Prefer "
        "POST /shares/download with the token in the JSON body: a bearer secret in "
        "the URL path leaks into access logs, proxies and referrers."
    ),
)
def download_shared_file_legacy_path(
    token: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    share, file_record, download_url, remaining = share_service.open_share(
        db=db,
        token=token,
        user=current_user,
        ip_address=_client_ip(request),
    )

    return ShareDownloadResponse(
        share_id=share.id,
        file_name=file_record.original_name,
        content_type=file_record.content_type,
        size=file_record.size,
        sha256_hash=file_record.sha256_hash,
        download_url=download_url,
        expires_in_seconds=share_service.settings.SHARE_SAS_EXPIRY_MINUTES * 60,
        remaining_downloads=remaining,
    )

"""Sharing policy engine: token lifecycle and the download gatekeeper.

Implements the deny-by-default sharing model described in the SecureShare
specification:

1. `create_share`  - 256-bit token, persisted only as a SHA-256 hash.
2. `revoke_share`  - ownership-checked soft revocation.
3. `open_share`    - four-gate download gatekeeper (status, expiry, quota,
   recipient identity), evaluated atomically, followed by SAS issuance via
   Member 3's blob service and an audit event.
"""
import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional, Tuple
from urllib.parse import quote

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import BadRequestException, ForbiddenException, NotFoundException
from app.db import crud
from app.db.models import FileRecord, Share, User
from app.services.blob_service import blob_service

logger = logging.getLogger("secureshare.shares")

SHARE_DENIED_MESSAGE = (
    "This share link is invalid, expired, revoked, out of downloads, "
    "or not addressed to you."
)


# ---------------------------------------------------------------------------
# Token primitives
# ---------------------------------------------------------------------------
def generate_share_token() -> str:
    """Generate a 256-bit entropy, URL-safe bearer token."""
    return secrets.token_urlsafe(32)


def hash_share_token(token: str) -> str:
    """One-way digest stored in place of the raw token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def build_share_url(token: str) -> str:
    """
    Recipient-facing URL. The token is URL-encoded and handed to the SPA route,
    which submits it to the download endpoint in a request body.
    """
    return f"/share/{quote(token, safe='')}"


# ---------------------------------------------------------------------------
# Creation / revocation
# ---------------------------------------------------------------------------
def create_share(
    db: Session,
    file_record: FileRecord,
    owner: User,
    recipient_email: str,
    expires_at: datetime,
    max_downloads: int,
    ip_address: Optional[str] = None,
) -> Tuple[Share, str]:
    """
    Create a share grant and return `(share, raw_token)`.

    The raw token is returned to the caller exactly once; only its hash is
    persisted, so it is unrecoverable from the database afterwards.
    """
    normalized_email = recipient_email.lower().strip()
    if file_record.owner_id != owner.id:
        # Defence in depth: callers must use the ownership validator first.
        raise ForbiddenException("You can only share files you own.")

    token = generate_share_token()
    token_hash = hash_share_token(token)

    share = crud.create_share(
        db=db,
        file_id=file_record.id,
        created_by=owner.id,
        recipient_email=normalized_email,
        token_hash=token_hash,
        token_prefix=token[:8],
        expires_at=expires_at,
        max_downloads=max_downloads,
    )

    # Opportunistically bind an existing account so gate 4 works by immutable ID
    # from the very first download attempt.
    recipient = crud.get_user_by_email(db, normalized_email)
    if recipient:
        crud.link_share_recipient(db, share, recipient.id)

    crud.create_audit_log(
        db,
        action="SHARE_CREATED",
        user_id=owner.id,
        ip_address=ip_address,
        status="SUCCESS",
        details=(
            f"Share {share.id} created for file {file_record.id} "
            f"to {normalized_email} (expires {expires_at.isoformat()}, "
            f"max_downloads={max_downloads})"
        ),
    )

    return share, token


def revoke_share(
    db: Session,
    share: Share,
    owner: User,
    ip_address: Optional[str] = None,
) -> Share:
    """Revoke a share grant. Raises 400 if it is already revoked."""
    if share.status == Share.STATUS_REVOKED:
        raise BadRequestException("This share has already been revoked.")

    revoked = crud.revoke_share(db, share, revoked_by=owner.id)

    crud.create_audit_log(
        db,
        action="SHARE_REVOKED",
        user_id=owner.id,
        ip_address=ip_address,
        status="SUCCESS",
        details=f"Share {share.id} for file {share.file_id} revoked",
    )
    return revoked


# ---------------------------------------------------------------------------
# Download gatekeeper
# ---------------------------------------------------------------------------
def open_share(
    db: Session,
    token: str,
    user: User,
    ip_address: Optional[str] = None,
) -> Tuple[Share, FileRecord, str, int]:
    """
    Validate every policy gate and issue a short-lived download URL.

    Gates (evaluated atomically by a single conditional UPDATE):
        1. share.status == ACTIVE
        2. now < share.expires_at
        3. share.download_count < share.max_downloads
        4. caller is the addressed recipient (by immutable id or verified email)

    Returns `(share, file_record, download_url, remaining_downloads)`.

    Failures raise a generic 404. The precise reason is written only to the
    audit log, so the endpoint cannot be used to probe for valid tokens.
    """
    token_hash = hash_share_token(token)

    reservation = crud.reserve_share_download(
        db=db,
        token_hash=token_hash,
        user_id=user.id,
        email=user.email,
    )

    if reservation is None:
        reason = crud.describe_share_denial(db, token_hash)
        crud.create_audit_log(
            db,
            action="SHARE_DOWNLOAD_DENIED",
            user_id=user.id,
            ip_address=ip_address,
            status="ALERT",
            details=f"Share download denied: reason={reason}, token_prefix={token[:8]}",
        )
        logger.warning(
            "Share download denied for user %s (reason=%s)", user.id, reason
        )
        raise NotFoundException(SHARE_DENIED_MESSAGE)

    download_count, max_downloads, share_id = reservation
    share = crud.get_share_by_id(db, share_id)
    if share is None:  # pragma: no cover - defensive, cascade would delete it
        raise NotFoundException(SHARE_DENIED_MESSAGE)

    file_record = crud.get_file_by_id(db, share.file_id)
    if file_record is None:
        _release_reservation(db, share_id)
        crud.create_audit_log(
            db,
            action="SHARE_DOWNLOAD_FAILED",
            user_id=user.id,
            ip_address=ip_address,
            status="ERROR",
            details=f"Share {share_id} references a missing file record; reservation released.",
        )
        raise NotFoundException(SHARE_DENIED_MESSAGE)

    # First successful access binds the immutable recipient id.
    crud.link_share_recipient(db, share, user.id)

    try:
        download_url = blob_service.generate_download_url(
            file_record.blob_name,
            expiry_minutes=settings.SHARE_SAS_EXPIRY_MINUTES,
        )
    except Exception as exc:
        _release_reservation(db, share_id)
        logger.error("SAS issuance failed for share %s: %s", share_id, exc)
        crud.create_audit_log(
            db,
            action="SHARE_DOWNLOAD_FAILED",
            user_id=user.id,
            ip_address=ip_address,
            status="ERROR",
            details=f"SAS issuance failed for share {share_id}; reservation released.",
        )
        raise BadRequestException("Unable to issue a download link. Please retry.")

    remaining = max(max_downloads - download_count, 0)

    crud.create_audit_log(
        db,
        action="SHARE_DOWNLOAD_SUCCESS",
        user_id=user.id,
        ip_address=ip_address,
        status="SUCCESS",
        details=(
            f"Share {share_id} downloaded file {file_record.id} "
            f"({download_count}/{max_downloads}); SAS TTL={settings.SHARE_SAS_EXPIRY_MINUTES}m"
        ),
    )

    return share, file_record, download_url, remaining


def _release_reservation(db: Session, share_id: str) -> None:
    """
    Compensating action if SAS issuance fails after the quota was reserved.

    Prevents a transient storage error from consuming a recipient's download.
    """
    share = crud.get_share_by_id(db, share_id)
    if not share:
        return
    share.download_count = max(share.download_count - 1, 0)
    if share.status == Share.STATUS_EXHAUSTED and share.download_count < share.max_downloads:
        share.status = Share.STATUS_ACTIVE
    db.add(share)
    db.commit()


def expire_stale_shares(db: Session) -> int:
    """
    Mark ACTIVE shares whose expiry has passed as EXPIRED.

    Optional housekeeping helper; the gatekeeper already rejects expired shares
    without relying on this job.
    """
    now = datetime.now(timezone.utc)
    count = (
        db.query(Share)
        .filter(Share.status == Share.STATUS_ACTIVE, Share.expires_at <= now)
        .update({Share.status: Share.STATUS_EXPIRED}, synchronize_session=False)
    )
    db.commit()
    return int(count)

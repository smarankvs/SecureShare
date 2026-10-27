import logging
from datetime import datetime, timezone
from typing import Optional, List, Tuple
from sqlalchemy import select, func, update, or_, case
from sqlalchemy.orm import Session
from app.core.security import hash_password
from app.db.models import User, FileRecord, AuditLog, Share
from app.schemas import UserCreate
from app.utils.logger import log_audit_event

logger = logging.getLogger("secureshare.crud")


# =========================================================
# USER OPERATIONS (Parameterized queries, zero SQL injection)
# =========================================================

def get_user_by_email(db: Session, email: str) -> Optional[User]:
    """Retrieve a user by their unique email using parameterized query."""
    stmt = select(User).where(User.email == email.lower().strip())
    return db.execute(stmt).scalar_one_or_none()


def get_user_by_id(db: Session, user_id: str) -> Optional[User]:
    """Retrieve a user by their unique primary key ID."""
    stmt = select(User).where(User.id == user_id)
    return db.execute(stmt).scalar_one_or_none()


def create_user(db: Session, user_in: UserCreate) -> User:
    """Create a new user with securely hashed password."""
    hashed_pwd = hash_password(user_in.password)
    user = User(
        name=user_in.name.strip(),
        email=user_in.email.lower().strip(),
        password_hash=hashed_pwd,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def get_user_by_entra_oid(db: Session, entra_oid: str) -> Optional[User]:
    """Retrieve a shadow user by the immutable Entra ID object id (oid claim)."""
    stmt = select(User).where(User.entra_oid == entra_oid)
    return db.execute(stmt).scalar_one_or_none()


def provision_entra_user(db: Session, entra_oid: str, email: str, name: str) -> User:
    """
    Resolve the application user for a verified Entra identity, creating it on
    first login.

    If a local account already exists with the same verified email, it is linked
    to the Entra identity (auth_source="entra") instead of creating a duplicate.
    This keeps historic file ownership and audit records intact.
    """
    existing = get_user_by_entra_oid(db, entra_oid)
    if existing:
        # Keep display data fresh without changing the primary key.
        if email and existing.email != email:
            existing.email = email
            db.commit()
            db.refresh(existing)
        return existing

    by_email = get_user_by_email(db, email)
    if by_email:
        by_email.entra_oid = entra_oid
        by_email.auth_source = "entra"
        db.commit()
        db.refresh(by_email)
        logger.info("Linked existing local account %s to Entra oid %s", by_email.id, entra_oid)
        return by_email

    user = User(
        name=(name or email.split("@")[0])[:100],
        email=email,
        password_hash=None,
        entra_oid=entra_oid,
        auth_source="entra",
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    logger.info("Provisioned Entra shadow user %s (%s)", user.id, email)
    return user


def update_user_role(db: Session, user_id: str, new_role: str) -> Optional[User]:
    """Update role for a user (e.g., 'admin', 'user')."""
    user = get_user_by_id(db, user_id)
    if not user:
        return None
    user.role = new_role.lower().strip()
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def update_user_password(db: Session, user_id: str, new_hashed_pwd: str) -> Optional[User]:
    """Update password hash for a user."""
    user = get_user_by_id(db, user_id)
    if not user:
        return None
    user.password_hash = new_hashed_pwd
    db.add(user)
    db.commit()
    db.refresh(user)
    return user



# =========================================================
# FILE OPERATIONS
# =========================================================

def create_file_record(
    db: Session,
    blob_name: str,
    original_name: str,
    blob_url: str,
    owner_id: str,
    content_type: str,
    size: int,
    sha256_hash: Optional[str] = None,
) -> FileRecord:
    """Persist file metadata record in PostgreSQL."""
    file_record = FileRecord(
        blob_name=blob_name,
        original_name=original_name,
        blob_url=blob_url,
        owner_id=owner_id,
        content_type=content_type,
        size=size,
        sha256_hash=sha256_hash,
    )
    db.add(file_record)
    db.commit()
    db.refresh(file_record)
    return file_record


def get_file_by_id(db: Session, file_id: str) -> Optional[FileRecord]:
    """Retrieve a file metadata record by ID."""
    stmt = select(FileRecord).where(FileRecord.id == file_id)
    return db.execute(stmt).scalar_one_or_none()


def get_file_by_blob_name(db: Session, blob_name: str) -> Optional[FileRecord]:
    """Retrieve a file metadata record by blob UUID name."""
    stmt = select(FileRecord).where(FileRecord.blob_name == blob_name)
    return db.execute(stmt).scalar_one_or_none()


def get_user_files(
    db: Session,
    owner_id: str,
    skip: int = 0,
    limit: int = 50
) -> Tuple[List[FileRecord], int]:
    """Retrieve paginated file list owned by a specific user with total count."""
    count_stmt = select(func.count(FileRecord.id)).where(FileRecord.owner_id == owner_id)
    total = db.execute(count_stmt).scalar() or 0

    stmt = (
        select(FileRecord)
        .where(FileRecord.owner_id == owner_id)
        .order_by(FileRecord.upload_time.desc())
        .offset(skip)
        .limit(limit)
    )
    files = list(db.execute(stmt).scalars().all())
    return files, total


def delete_file_record(db: Session, file_id: str) -> bool:
    """Delete a file metadata record from the database."""
    file_record = get_file_by_id(db, file_id)
    if not file_record:
        return False
    db.delete(file_record)
    db.commit()
    return True


# =========================================================
# AUDIT LOG OPERATIONS
# =========================================================

def create_audit_log(
    db: Session,
    action: str,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    resource: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    status: str = "SUCCESS",
    details: Optional[str] = None,
) -> AuditLog:
    """
    Record a security audit log event both in PostgreSQL database
    and emit structured JSON log to stdout for Microsoft Sentinel ingestion.
    """
    # 1. Resolve username from user_id if not explicitly passed
    if user_id and not username:
        try:
            user = get_user_by_id(db, user_id)
            if user:
                username = user.email
        except Exception:
            pass

    # 2. Persist to PostgreSQL database
    log_entry = AuditLog(
        action=action,
        user_id=user_id,
        username=username,
        resource=resource,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        status=status,
        details=details,
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)

    # 3. Emit structured JSON audit log for SIEM (Microsoft Sentinel)
    log_audit_event(
        action=action,
        user_id=user_id,
        username=username,
        resource=resource,
        status=status,
        ip_address=ip_address,
        user_agent=user_agent,
        request_id=request_id,
        details=details,
    )

    return log_entry


def get_audit_logs_for_user(
    db: Session,
    user_id: str,
    skip: int = 0,
    limit: int = 50
) -> List[AuditLog]:
    """Retrieve security audit logs for a specific user."""
    stmt = (
        select(AuditLog)
        .where(AuditLog.user_id == user_id)
        .order_by(AuditLog.timestamp.desc())
        .offset(skip)
        .limit(limit)
    )
    return list(db.execute(stmt).scalars().all())


# =========================================================
# SHARE OPERATIONS (recipient-bound, quota-limited grants)
# =========================================================

def create_share(
    db: Session,
    file_id: str,
    created_by: str,
    recipient_email: str,
    token_hash: str,
    token_prefix: str,
    expires_at: datetime,
    max_downloads: int,
    recipient_user_id: Optional[str] = None,
) -> Share:
    """Persist a share grant. Only the SHA-256 hash of the token is stored."""
    share = Share(
        file_id=file_id,
        created_by=created_by,
        recipient_email=recipient_email.lower().strip(),
        recipient_user_id=recipient_user_id,
        token_hash=token_hash,
        token_prefix=token_prefix,
        status=Share.STATUS_ACTIVE,
        expires_at=expires_at,
        max_downloads=max_downloads,
        download_count=0,
    )
    db.add(share)
    db.commit()
    db.refresh(share)
    return share


def get_share_by_id(db: Session, share_id: str) -> Optional[Share]:
    """Retrieve a share grant by its primary key."""
    stmt = select(Share).where(Share.id == share_id)
    return db.execute(stmt).scalar_one_or_none()


def get_share_by_token_hash(db: Session, token_hash: str) -> Optional[Share]:
    """Retrieve a share grant by the SHA-256 hash of its bearer token."""
    stmt = select(Share).where(Share.token_hash == token_hash)
    return db.execute(stmt).scalar_one_or_none()


def list_shares_for_user(
    db: Session,
    user_id: str,
    file_id: Optional[str] = None,
    skip: int = 0,
    limit: int = 50,
) -> Tuple[List[Share], int]:
    """
    List shares administrable by `user_id` (creator, or owner of the file).
    Never returns token material.
    """
    base = select(Share).join(FileRecord, Share.file_id == FileRecord.id).where(
        or_(Share.created_by == user_id, FileRecord.owner_id == user_id)
    )
    if file_id:
        base = base.where(Share.file_id == file_id)

    count_stmt = select(func.count()).select_from(base.subquery())
    total = db.execute(count_stmt).scalar() or 0

    stmt = base.order_by(Share.created_at.desc()).offset(skip).limit(limit)
    shares = list(db.execute(stmt).scalars().all())
    return shares, total


def revoke_share(db: Session, share: Share, revoked_by: str) -> Share:
    """Soft-revoke a share grant, preserving the audit trail."""
    share.status = Share.STATUS_REVOKED
    share.revoked_at = datetime.now(timezone.utc)
    share.revoked_by = revoked_by
    db.add(share)
    db.commit()
    db.refresh(share)
    return share


def reserve_share_download(
    db: Session,
    token_hash: str,
    user_id: str,
    email: str,
) -> Optional[Tuple[int, int, str]]:
    """
    Atomically validate every download policy gate and reserve one download.

    A single conditional UPDATE is used instead of read-then-write so that
    concurrent requests cannot exceed `max_downloads` (TOCTOU safe). All four
    gates — ACTIVE status, not expired, quota remaining, correct recipient —
    are evaluated by the database in one statement.

    Returns `(download_count, max_downloads, share_id)` on success, or `None`
    if any gate failed.
    """
    exhausted_status = case(
        (Share.download_count + 1 >= Share.max_downloads, Share.STATUS_EXHAUSTED),
        else_=Share.status,
    )

    stmt = (
        update(Share)
        .where(
            Share.token_hash == token_hash,
            Share.status == Share.STATUS_ACTIVE,
            Share.expires_at > func.now(),
            Share.download_count < Share.max_downloads,
            or_(
                Share.recipient_user_id == user_id,
                func.lower(Share.recipient_email) == email.lower().strip(),
            ),
        )
        .values(
            download_count=Share.download_count + 1,
            last_downloaded_at=func.now(),
            status=exhausted_status,
        )
        .returning(Share.id, Share.download_count, Share.max_downloads)
    )

    row = db.execute(stmt).first()
    if row is None:
        # No rollback: the UPDATE affected zero rows and the surrounding
        # request-scoped transaction must stay usable for audit logging.
        return None

    db.commit()
    return int(row[1]), int(row[2]), str(row[0])


def describe_share_denial(db: Session, token_hash: str) -> str:
    """
    Internal-only reason for a failed gate, used for audit logging.

    Must never be returned to the caller: external responses are uniform 404s
    to prevent the endpoint from becoming a token-existence oracle.
    """
    share = get_share_by_token_hash(db, token_hash)
    if not share:
        return "UNKNOWN_TOKEN"
    if share.status == Share.STATUS_REVOKED:
        return "REVOKED"
    if share.status == Share.STATUS_EXHAUSTED:
        return "EXHAUSTED"
    expires_at = share.expires_at
    if expires_at is not None and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at is not None and expires_at <= datetime.now(timezone.utc):
        return "EXPIRED"
    if share.download_count >= share.max_downloads:
        return "EXHAUSTED"
    return "RECIPIENT_MISMATCH"


def link_share_recipient(db: Session, share: Share, user_id: str) -> None:
    """Lazily bind `recipient_user_id` the first time the recipient downloads."""
    if share.recipient_user_id is None:
        share.recipient_user_id = user_id
        db.add(share)
        db.commit()
        db.refresh(share)


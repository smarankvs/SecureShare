import logging
from typing import Optional, List, Tuple
from sqlalchemy import select, func
from sqlalchemy.orm import Session
from app.core.security import hash_password
from app.db.models import User, FileRecord, AuditLog
from app.schemas import UserCreate

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
    ip_address: Optional[str] = None,
    status: str = "SUCCESS",
    details: Optional[str] = None,
) -> AuditLog:
    """Record a security audit log event."""
    log_entry = AuditLog(
        action=action,
        user_id=user_id,
        ip_address=ip_address,
        status=status,
        details=details,
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
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

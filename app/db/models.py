import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, BigInteger, DateTime, ForeignKey, Boolean, Text, Integer
from sqlalchemy.orm import relationship
from app.db.database import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    """
    Users entity representing registered platform users.
    Stores cryptographic hashes of passwords; plain passwords are never stored.
    """
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=True)
    # Immutable Microsoft Entra ID Object ID (oid claim). Null for local-only users.
    entra_oid = Column(String(64), unique=True, index=True, nullable=True)
    auth_source = Column(String(20), default="local", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    files = relationship("FileRecord", back_populates="owner", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")
    shares_created = relationship("Share", back_populates="creator", foreign_keys="Share.created_by")


    def __repr__(self) -> str:
        return f"<User(id={self.id}, email={self.email})>"


class FileRecord(Base):
    """
    Files entity representing uploaded documents and media securely stored in Azure Blob Storage.
    Original user filenames are segregated; only randomized UUIDs are used as blob keys.
    """
    __tablename__ = "files"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    blob_name = Column(String(255), unique=True, index=True, nullable=False)
    original_name = Column(String(255), nullable=False)
    blob_url = Column(Text, nullable=False)
    owner_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    upload_time = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    content_type = Column(String(100), nullable=False)
    size = Column(BigInteger, nullable=False)
    sha256_hash = Column(String(64), nullable=True)

    # Relationships
    owner = relationship("User", back_populates="files")
    shares = relationship("Share", back_populates="file", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<FileRecord(id={self.id}, blob_name={self.blob_name}, original_name={self.original_name})>"


class Share(Base):
    """
    Shares entity implementing recipient-bound, time-limited, quota-limited access
    to a single file.

    Security properties:
    - Only the SHA-256 hash of the 256-bit share token is persisted. The raw token
      is returned to the creator exactly once and is never recoverable from the DB.
    - Access is deny-by-default: status, expiry, download quota and recipient
      identity are all evaluated atomically in a single conditional UPDATE, which
      removes the check-then-increment race on `download_count`.
    - Revocation is soft (status = REVOKED) so the audit trail is preserved.
    """
    __tablename__ = "shares"

    STATUS_ACTIVE = "ACTIVE"
    STATUS_REVOKED = "REVOKED"
    STATUS_EXHAUSTED = "EXHAUSTED"
    STATUS_EXPIRED = "EXPIRED"
    VALID_STATUSES = (STATUS_ACTIVE, STATUS_REVOKED, STATUS_EXHAUSTED, STATUS_EXPIRED)

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    file_id = Column(
        String(36),
        ForeignKey("files.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by = Column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Recipient binding. Email is the source of truth (lower-cased) so a share can
    # be created before the recipient has ever signed in; recipient_user_id is
    # resolved lazily on first successful access.
    recipient_email = Column(String(255), nullable=False, index=True)
    recipient_user_id = Column(
        String(36),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    token_hash = Column(String(64), unique=True, index=True, nullable=False)
    token_prefix = Column(String(12), nullable=False)

    status = Column(String(20), default=STATUS_ACTIVE, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    max_downloads = Column(Integer, nullable=False, default=1)
    download_count = Column(Integer, nullable=False, default=0)

    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    last_downloaded_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    revoked_by = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Relationships
    file = relationship("FileRecord", back_populates="shares")
    creator = relationship("User", back_populates="shares_created", foreign_keys=[created_by])

    def __repr__(self) -> str:
        return f"<Share(id={self.id}, file_id={self.file_id}, status={self.status})>"



class AuditLog(Base):
    """
    AuditLogs entity recording critical security events:
    - User registration
    - Authentication successes and failures
    - File upload, access, and deletion events
    """
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    ip_address = Column(String(45), nullable=True)
    status = Column(String(20), default="SUCCESS", nullable=False)
    details = Column(Text, nullable=True)

    # Relationships
    user = relationship("User", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, action={self.action}, timestamp={self.timestamp})>"

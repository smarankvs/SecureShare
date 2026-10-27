import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, BigInteger, DateTime, ForeignKey, Boolean, Text
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
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    files = relationship("FileRecord", back_populates="owner", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user")

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

    def __repr__(self) -> str:
        return f"<FileRecord(id={self.id}, blob_name={self.blob_name}, original_name={self.original_name})>"


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

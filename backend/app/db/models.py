"""
Core SecureShare schema (PostgreSQL).

Tables: users, documents, shares, access_events.

Notes
-----
* Primary keys are UUIDs (native ``uuid`` type on PostgreSQL).
* ``documents.blob_name`` is a server-generated random UUID; user-supplied
  filenames are only kept as metadata in ``original_filename`` and are never
  used as a path on disk or as a blob key.
* ``shares.token_hash`` stores a SHA-256 hash of the share token, never the
  raw token.
* Envelope-encryption material (wrapped DEK, nonce, KEK id) is stored as
  metadata on the encrypted blob itself (same model as the Azure SDK's
  client-side encryption), keeping this schema minimal.
"""
from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# Deterministic constraint names → clean, reviewable Alembic migrations.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# PostgreSQL INET, portable String fallback for the SQLite test-suite.
IPAddress = String(45).with_variant(INET(), "postgresql")


def _enum(cls: type[enum.Enum], name: str) -> Enum:
    return Enum(cls, name=name, values_callable=lambda e: [m.value for m in e], validate_strings=True)


# ── Enumerations ───────────────────────────────────────────────────────────
class UserStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    CLEAN = "CLEAN"
    INFECTED = "INFECTED"
    ERROR = "ERROR"


class ShareStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    EXHAUSTED = "EXHAUSTED"


class AccessEventType(str, enum.Enum):
    UPLOAD = "UPLOAD"
    UPLOAD_REJECTED = "UPLOAD_REJECTED"
    MALWARE_DETECTED = "MALWARE_DETECTED"
    SHARE_CREATED = "SHARE_CREATED"
    SHARE_REVOKED = "SHARE_REVOKED"
    SAS_ISSUED = "SAS_ISSUED"
    DOWNLOAD = "DOWNLOAD"
    ACCESS_DENIED = "ACCESS_DENIED"


class AccessResult(str, enum.Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    BLOCKED = "BLOCKED"


# ── Tables ─────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    entra_object_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    status: Mapped[UserStatus] = mapped_column(
        _enum(UserStatus, "user_status"), nullable=False, default=UserStatus.ACTIVE,
        server_default=UserStatus.ACTIVE.value,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    documents: Mapped[list[Document]] = relationship(back_populates="owner")

    def __repr__(self) -> str:
        return f"<User id={self.id} oid={self.entra_object_id}>"


class Document(Base):
    __tablename__ = "documents"
    __table_args__ = (
        CheckConstraint("file_size >= 0", name="file_size_non_negative"),
        CheckConstraint("length(sha256) = 64", name="sha256_length"),
        Index("ix_documents_owner_created", "owner_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    blob_name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(127), nullable=False)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    scan_status: Mapped[ScanStatus] = mapped_column(
        _enum(ScanStatus, "scan_status"), nullable=False, default=ScanStatus.PENDING,
        server_default=ScanStatus.PENDING.value,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    owner: Mapped[User] = relationship(back_populates="documents")
    shares: Mapped[list[Share]] = relationship(back_populates="document")


class Share(Base):
    __tablename__ = "shares"
    __table_args__ = (
        CheckConstraint("download_count >= 0", name="download_count_non_negative"),
        CheckConstraint("max_downloads IS NULL OR max_downloads > 0", name="max_downloads_positive"),
        CheckConstraint(
            "max_downloads IS NULL OR download_count <= max_downloads", name="download_count_within_max"
        ),
        Index("ix_shares_recipient_status", "recipient_user_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    document_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("documents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    owner_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True
    )
    recipient_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="CASCADE"), nullable=True
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    max_downloads: Mapped[int | None] = mapped_column(Integer, nullable=True)
    download_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    status: Mapped[ShareStatus] = mapped_column(
        _enum(ShareStatus, "share_status"), nullable=False, default=ShareStatus.ACTIVE,
        server_default=ShareStatus.ACTIVE.value,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    document: Mapped[Document] = relationship(back_populates="shares")


class AccessEvent(Base):
    """Append-only audit trail. Rows are never updated or deleted by the app."""

    __tablename__ = "access_events"
    __table_args__ = (
        Index("ix_access_events_document_ts", "document_id", "timestamp"),
        Index("ix_access_events_user_ts", "user_id", "timestamp"),
        Index("ix_access_events_type_ts", "event_type", "timestamp"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # SET NULL keeps the audit trail intact if the parent row is removed.
    document_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("documents.id", ondelete="SET NULL"), nullable=True
    )
    share_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("shares.id", ondelete="SET NULL"), nullable=True, index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    event_type: Mapped[AccessEventType] = mapped_column(_enum(AccessEventType, "access_event_type"), nullable=False)
    result: Mapped[AccessResult] = mapped_column(_enum(AccessResult, "access_result"), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    ip_address: Mapped[str | None] = mapped_column(IPAddress, nullable=True)

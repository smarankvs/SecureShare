"""Pydantic contracts for the sharing policy engine (Member 2)."""
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.core.config import settings


class ShareCreate(BaseModel):
    """Payload for creating a recipient-bound share grant."""

    file_id: str = Field(..., min_length=1, description="ID of the file to share")
    recipient_email: EmailStr = Field(..., description="Explicit recipient identity")
    expires_at: datetime = Field(..., description="Absolute UTC expiry timestamp")
    max_downloads: int = Field(
        1,
        ge=1,
        description="Maximum number of successful downloads permitted",
    )

    @field_validator("expires_at")
    @classmethod
    def _validate_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        if value <= now:
            raise ValueError("expires_at must be in the future.")
        if (value - now).days > settings.SHARE_MAX_EXPIRY_DAYS:
            raise ValueError(
                f"expires_at must be within {settings.SHARE_MAX_EXPIRY_DAYS} days."
            )
        return value

    @field_validator("max_downloads")
    @classmethod
    def _validate_quota(cls, value: int) -> int:
        if value > settings.SHARE_MAX_DOWNLOADS_CAP:
            raise ValueError(
                f"max_downloads cannot exceed {settings.SHARE_MAX_DOWNLOADS_CAP}."
            )
        return value


class ShareCreatedResponse(BaseModel):
    """
    Returned exactly once, at creation time. Contains the raw bearer token; the
    server only ever persists its SHA-256 hash afterwards.
    """

    share_id: str
    file_id: str
    recipient_email: str
    token: str
    token_prefix: str
    share_url: str
    expires_at: datetime
    max_downloads: int
    status: str


class ShareResponse(BaseModel):
    """Share metadata safe to return on subsequent reads (no token material)."""

    id: str
    file_id: str
    file_name: Optional[str] = None
    recipient_email: str
    token_prefix: str
    status: str
    expires_at: datetime
    max_downloads: int
    download_count: int
    created_at: datetime
    last_downloaded_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class ShareListResponse(BaseModel):
    total: int
    shares: list[ShareResponse]


class ShareRevokeResponse(BaseModel):
    id: str
    status: str
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None


class ShareDownloadRequest(BaseModel):
    """
    Bearer token is supplied in the request body rather than the URL path so it
    never lands in access logs, proxy logs or browser referrers.
    """

    token: str = Field(..., min_length=16, max_length=256)


class ShareDownloadResponse(BaseModel):
    share_id: str
    file_name: str
    content_type: str
    size: int
    sha256_hash: Optional[str] = None
    download_url: str
    expires_in_seconds: int
    remaining_downloads: int


class SharedWithMeItem(BaseModel):
    share_id: str
    file_id: str
    file_name: str
    size: int
    content_type: str
    sender_name: str
    sender_email: str
    shared_at: datetime
    expires_at: datetime
    status: str
    max_downloads: int
    download_count: int
    remaining_downloads: int
    can_download: bool

    model_config = ConfigDict(from_attributes=True)


class SharedWithMeResponse(BaseModel):
    total: int
    documents: list[SharedWithMeItem]


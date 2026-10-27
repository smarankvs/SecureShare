from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr, Field, ConfigDict


# User Schemas
class UserBase(BaseModel):
    name: str = Field(..., min_length=2, max_length=100, description="Full name of user")
    email: EmailStr = Field(..., description="Unique email address")


class UserCreate(UserBase):
    password: str = Field(
        ...,
        min_length=8,
        max_length=72,
        description="Password meeting complexity requirements (uppercase, lowercase, number, special char)"
    )


class UserResponse(UserBase):
    id: str
    role: str = "user"
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# Auth Schemas
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(..., min_length=1, description="Current existing password")
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=72,
        description="New password meeting complexity requirements"
    )


class RoleUpdateRequest(BaseModel):
    role: str = Field(..., description="Target role ('admin' or 'user')")


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class TokenData(BaseModel):
    user_id: Optional[str] = None
    token_type: Optional[str] = None


# File Schemas
class FileUploadResponse(BaseModel):
    id: str
    blob_name: str
    original_name: str
    content_type: str
    size: int
    upload_time: datetime
    blob_url: str
    sha256_hash: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class FileDetailResponse(BaseModel):
    id: str
    blob_name: str
    original_name: str
    content_type: str
    size: int
    upload_time: datetime
    download_url: str
    sha256_hash: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class FileListResponse(BaseModel):
    total: int
    files: List[FileUploadResponse]


# Audit Log Schemas
class AuditLogResponse(BaseModel):
    id: str
    user_id: Optional[str] = None
    username: Optional[str] = None
    action: str
    resource: Optional[str] = None
    timestamp: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    status: str
    details: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


# Standard API Response wrapper
class MessageResponse(BaseModel):
    message: str


# Sharing schemas (Member 2: Authorization & Sharing Logic)
from app.schemas.shares import (  # noqa: E402,F401
    ShareCreate,
    ShareCreatedResponse,
    ShareDownloadRequest,
    ShareDownloadResponse,
    ShareListResponse,
    ShareResponse,
    ShareRevokeResponse,
)


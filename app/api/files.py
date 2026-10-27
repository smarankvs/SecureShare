import io
import logging
from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core import authz
from app.core.exceptions import NotFoundException
from app.db import crud
from app.db.database import get_db
from app.db.models import User
from app.middleware.auth import get_current_user
from app.schemas import (
    FileDetailResponse,
    FileListResponse,
    FileUploadResponse,
    MessageResponse
)
from app.services.blob_service import blob_service

logger = logging.getLogger("secureshare.files_api")

router = APIRouter(prefix="/files", tags=["Files Management"])


def _extract_request_context(request: Request):
    return {
        "ip_address": getattr(request.state, "client_ip", "unknown") or "unknown",
        "user_agent": getattr(request.state, "user_agent", "unknown") or "unknown",
        "request_id": getattr(request.state, "request_id", "unknown") or "unknown",
    }


@router.get(
    "",
    response_model=FileListResponse,
    summary="List User Files",
    description="Retrieve all files owned by the authenticated user with pagination."
)
def list_files(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    files, total = crud.get_user_files(db, owner_id=current_user.id, skip=skip, limit=limit)
    return FileListResponse(
        total=total,
        files=[FileUploadResponse.model_validate(f) for f in files]
    )


@router.get(
    "/{file_id}",
    response_model=FileDetailResponse,
    summary="Get File Details and Secure Download URL",
    description="Fetches file metadata and generates a short-lived, time-limited Azure Blob SAS URL."
)
def get_file_details(
    file_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ctx = _extract_request_context(request)

    # Deny-by-default object-level authorization (IDOR/BOLA mitigation)
    file_record = authz.get_owned_file(
        db,
        file_id,
        current_user,
        ip_address=ctx["ip_address"],
        audit_action="UNAUTHORIZED_FILE_ACCESS",
    )

    # Generate short-lived SAS download URL (15 minutes expiry)
    download_url = blob_service.generate_download_url(file_record.blob_name, expiry_minutes=15)

    crud.create_audit_log(
        db,
        action="FILE_METADATA_ACCESSED",
        user_id=current_user.id,
        username=current_user.email,
        resource=f"files/{file_record.id}",
        ip_address=ctx["ip_address"],
        user_agent=ctx["user_agent"],
        request_id=ctx["request_id"],
        status="SUCCESS",
        details=f"Accessed metadata for {file_record.blob_name}"
    )

    return FileDetailResponse(
        id=file_record.id,
        blob_name=file_record.blob_name,
        original_name=file_record.original_name,
        content_type=file_record.content_type,
        size=file_record.size,
        upload_time=file_record.upload_time,
        download_url=download_url,
        sha256_hash=file_record.sha256_hash
    )


@router.get(
    "/download/{blob_name}",
    summary="Secure Download Stream",
    description="Stream file contents directly from secure storage."
)
def download_file_stream(
    blob_name: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ctx = _extract_request_context(request)
    resolved = crud.get_file_by_blob_name(db, blob_name)

    if not resolved:
        raise NotFoundException("Requested file does not exist.")

    file_record = authz.verify_document_owner(
        db,
        resolved.id,
        current_user.id,
        ip_address=ctx["ip_address"],
        audit_action="UNAUTHORIZED_DOWNLOAD_ATTEMPT",
    )

    try:
        content_bytes, content_type = blob_service.download_file(blob_name)
    except FileNotFoundError:
        raise NotFoundException("File content missing from storage backend.")

    # Audit Log (FILE_DOWNLOAD)
    crud.create_audit_log(
        db,
        action="FILE_DOWNLOAD",
        user_id=current_user.id,
        username=current_user.email,
        resource=f"files/{file_record.id}",
        ip_address=ctx["ip_address"],
        user_agent=ctx["user_agent"],
        request_id=ctx["request_id"],
        status="SUCCESS",
        details=f"Downloaded {file_record.original_name} ({blob_name})"
    )

    return StreamingResponse(
        io.BytesIO(content_bytes),
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{file_record.original_name}"',
            "Content-Length": str(len(content_bytes)),
            "X-Content-Type-Options": "nosniff"
        }
    )


@router.delete(
    "/{file_id}",
    response_model=MessageResponse,
    summary="Delete File",
    description="Permanently deletes the file from Azure Blob Storage and database."
)
def delete_file(
    file_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    ctx = _extract_request_context(request)

    file_record = authz.get_owned_file(
        db,
        file_id,
        current_user,
        ip_address=ctx["ip_address"],
        audit_action="UNAUTHORIZED_DELETE_ATTEMPT",
    )

    # Remove blob from storage
    blob_deleted = blob_service.delete_file(file_record.blob_name)
    blob_name = file_record.blob_name
    original_name = file_record.original_name

    # Remove record from database
    crud.delete_file_record(db, file_id)

    # Audit Log (FILE_DELETION)
    crud.create_audit_log(
        db,
        action="FILE_DELETION",
        user_id=current_user.id,
        username=current_user.email,
        resource=f"files/{file_id}",
        ip_address=ctx["ip_address"],
        user_agent=ctx["user_agent"],
        request_id=ctx["request_id"],
        status="SUCCESS",
        details=f"Deleted '{original_name}' (Blob: {blob_name}, StorageRemoved: {blob_deleted})"
    )

    return MessageResponse(message=f"File '{original_name}' deleted successfully.")

import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, File, Request, UploadFile, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.exceptions import BadRequestException, FileTooLargeException
from app.db import crud
from app.db.database import get_db
from app.db.models import User
from app.middleware.auth import get_current_user
from app.schemas import FileUploadResponse
from app.services.blob_service import blob_service
from app.services.encryption import calculate_sha256
from app.services.validation import validate_and_prepare_file
from app.services.virus_scan import virus_scanner

logger = logging.getLogger("secureshare.upload_api")

router = APIRouter(tags=["File Upload"])


@router.post(
    "/upload",
    response_model=FileUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Secure File Upload",
    description=(
        "Upload a document or image up to 25MB. "
        "Strictly validates file extension, magic byte MIME signature, and scans for malware. "
        "Stores the file under a random UUID in Azure Blob Storage private container 'secure-files' "
        "with original filename stored safely as metadata."
    )
)
async def upload_file(
    request: Request,
    file: UploadFile = File(..., description="Binary file upload (PDF, PNG, JPEG, DOCX up to 25MB)"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    client_ip = getattr(request.state, "client_ip", "unknown")

    if not file.filename:
        raise BadRequestException("Uploaded file must have a filename.")

    # 1. Stream file content in chunks to safely enforce max file size limit
    chunk_size = 1024 * 1024  # 1 MB chunk
    file_bytes = bytearray()
    total_size = 0

    while chunk := await file.read(chunk_size):
        total_size += len(chunk)
        if total_size > settings.MAX_FILE_SIZE_BYTES:
            crud.create_audit_log(
                db,
                action="FILE_UPLOAD_REJECTED",
                user_id=current_user.id,
                ip_address=client_ip,
                status="FAILED",
                details=f"File '{file.filename}' exceeded 25MB limit ({total_size} bytes)."
            )
            raise FileTooLargeException("Uploaded file exceeds the maximum allowed limit of 25MB.")
        file_bytes.extend(chunk)

    raw_data = bytes(file_bytes)

    # 2. Strict Security Validation:
    # - Filename sanitization
    # - Extension validation (PDF, PNG, JPEG, DOCX)
    # - Magic byte MIME verification
    # - Unpredictable UUID filename generation
    try:
        sanitized_name, extension, validated_mime, uuid_blob_name, file_size = validate_and_prepare_file(
            filename=file.filename,
            file_content=raw_data
        )
    except Exception as exc:
        crud.create_audit_log(
            db,
            action="FILE_UPLOAD_REJECTED",
            user_id=current_user.id,
            ip_address=client_ip,
            status="FAILED",
            details=f"Validation failed for '{file.filename}': {str(exc)}"
        )
        raise

    # 3. Antivirus & Malicious Signature Scan
    try:
        virus_scanner.assert_clean(raw_data)
    except Exception as exc:
        crud.create_audit_log(
            db,
            action="MALWARE_DETECTED",
            user_id=current_user.id,
            ip_address=client_ip,
            status="ALERT",
            details=f"Malware detection triggered for '{file.filename}': {str(exc)}"
        )
        raise

    # 4. Compute cryptographic SHA-256 for tamper detection and auditing
    sha256_hash = calculate_sha256(raw_data)

    # 5. Prepare Azure Blob Storage Metadata
    now_iso = datetime.now(timezone.utc).isoformat()
    blob_metadata = {
        "original_filename": sanitized_name,
        "uploaded_by": current_user.email,
        "upload_time": now_iso
    }

    # 6. Upload to Azure Blob Storage private container 'secure-files'
    try:
        blob_url = blob_service.upload_file(
            file_content=raw_data,
            blob_name=uuid_blob_name,
            content_type=validated_mime,
            metadata=blob_metadata
        )
    except Exception as exc:
        logger.error(f"Failed to persist blob in Azure Storage: {exc}")
        crud.create_audit_log(
            db,
            action="STORAGE_FAILURE",
            user_id=current_user.id,
            ip_address=client_ip,
            status="ERROR",
            details=f"Storage failure for '{uuid_blob_name}': {str(exc)}"
        )
        raise BadRequestException("Failed to store file securely in cloud storage.")

    # 7. Persist record in PostgreSQL Files table
    file_record = crud.create_file_record(
        db=db,
        blob_name=uuid_blob_name,
        original_name=sanitized_name,
        blob_url=blob_url,
        owner_id=current_user.id,
        content_type=validated_mime,
        size=file_size,
        sha256_hash=sha256_hash
    )

    # 8. Record successful audit log
    crud.create_audit_log(
        db,
        action="FILE_UPLOAD_SUCCESS",
        user_id=current_user.id,
        ip_address=client_ip,
        status="SUCCESS",
        details=f"Uploaded '{sanitized_name}' as '{uuid_blob_name}' ({file_size} bytes)"
    )

    logger.info(
        f"File upload successful: User {current_user.email} -> Blob {uuid_blob_name} ({sanitized_name})"
    )

    return file_record

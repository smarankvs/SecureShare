"""
POST /api/v1/documents/upload — ephemeral quarantine upload pipeline.

    size gate (≤ 25 MB) ─► magic-byte check ─► UUID quarantine write
        ─► ClamAV scan_stream ─┬─ INFECTED → purge, INFECTED, 400, alert
                               └─ CLEAN    → AES-256-GCM envelope encrypt
                                             ─► private Azure Blob upload
"""
from __future__ import annotations

import logging
import re
import unicodedata
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.api.deps import client_ip, get_current_user
from app.core.config import settings
from app.db.models import AccessEventType, AccessResult, Document, ScanStatus, User
from app.db.session import get_db
from app.services import encryption
from app.services.antivirus import ClamAVScanner, ScannerUnavailableError, Verdict, get_scanner
from app.services.audit import record_event
from app.services.blob_storage import BlobStorageService, get_blob_storage
from app.services.file_inspection import UnsupportedFileTypeError, resolve_final_mime, verify_header
from app.services.key_wrapping import KeyWrapClient, get_key_wrap_client
from app.services.quarantine import FileTooLargeError, purge, quarantine_file, write_stream
from app.services.security_alerts import trigger_security_alert

logger = logging.getLogger("secureshare.documents")
router = APIRouter(prefix="/documents", tags=["Documents"])

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class DocumentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    original_filename: str
    mime_type: str
    file_size: int
    sha256: str
    scan_status: ScanStatus
    created_at: datetime | None = None


def sanitize_display_name(name: str | None) -> str:
    """Display-only metadata: strip paths/control chars, NFC-normalise, cap length."""
    name = unicodedata.normalize("NFC", name or "")
    name = re.split(r"[\\/]", name)[-1]
    name = _CONTROL_CHARS.sub("", name).strip().lstrip(".")
    return name[:255] or "unnamed"


def _too_large() -> HTTPException:
    return HTTPException(413, "File exceeds the 25 MB upload limit")


@router.post("/upload", response_model=DocumentOut, status_code=status.HTTP_201_CREATED)
def upload_document(
    request: Request,
    file: UploadFile = File(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    scanner: ClamAVScanner = Depends(get_scanner),
    storage: BlobStorageService = Depends(get_blob_storage),
    key_wrapper: KeyWrapClient = Depends(get_key_wrap_client),
):
    ip = client_ip(request)
    limit = settings.MAX_UPLOAD_BYTES

    def reject(code: int, detail: str, document_id: uuid.UUID | None = None) -> HTTPException:
        record_event(AccessEventType.UPLOAD_REJECTED, AccessResult.BLOCKED,
                     user_id=user.id, document_id=document_id, ip_address=ip)
        return HTTPException(code, detail)

    # 1) Size gate — reject immediately (middleware already caps the raw body).
    if file.size is not None and file.size > limit:
        raise reject(413, _too_large().detail)

    # 2) Magic-byte inspection of the leading bytes (extension/Content-Type ignored).
    head = file.file.read(settings.MAGIC_SNIFF_BYTES)
    if not head:
        raise reject(400, "Empty file")
    try:
        provisional_mime = verify_header(head)
    except UnsupportedFileTypeError as exc:
        raise reject(415, f"Unsupported file type: {exc.detected}")

    # 3) Write to isolated quarantine under a random UUID name.
    with quarantine_file() as qf:
        try:
            write_stream(qf, head, iter(lambda: file.file.read(settings.UPLOAD_CHUNK_BYTES), b""), limit)
        except FileTooLargeError:
            raise reject(413, _too_large().detail)

        try:
            mime_type = resolve_final_mime(qf.path, provisional_mime)
        except UnsupportedFileTypeError as exc:
            raise reject(415, f"Unsupported file type: {exc.detected}")

        doc = Document(
            id=uuid.uuid4(),
            owner_id=user.id,
            original_filename=sanitize_display_name(file.filename),
            blob_name=uuid.uuid4().hex,  # never derived from user input
            mime_type=mime_type,
            file_size=qf.size,
            sha256=qf.sha256,
            scan_status=ScanStatus.PENDING,
        )
        db.add(doc)
        db.flush()

        # 4) ClamAV: pipe the quarantined stream into clamd.
        try:
            with open(qf.path, "rb") as fh:
                scan = scanner.scan_stream(fh)
        except ScannerUnavailableError as exc:
            logger.error("Antivirus unavailable, failing closed: %s", exc)
            doc.scan_status = ScanStatus.ERROR
            db.commit()
            record_event(AccessEventType.UPLOAD_REJECTED, AccessResult.FAILURE,
                         user_id=user.id, document_id=doc.id, ip_address=ip)
            raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Malware scanning unavailable; try again later")

        if scan.verdict is Verdict.INFECTED:
            purge(qf.path)  # immediate purge (context manager is a second safety net)
            doc.scan_status = ScanStatus.INFECTED
            record_event(AccessEventType.MALWARE_DETECTED, AccessResult.BLOCKED,
                         user_id=user.id, document_id=doc.id, ip_address=ip, db=db)
            db.commit()
            trigger_security_alert(
                "MALWARE_UPLOAD_BLOCKED", severity="HIGH",
                signature=scan.signature, document_id=doc.id, user_id=user.id,
                entra_object_id=user.entra_object_id, sha256=doc.sha256, ip_address=ip,
            )
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "File rejected: malware detected")

        doc.scan_status = ScanStatus.CLEAN

        # 5) Envelope encryption + upload to the private container.
        try:
            payload = encryption.encrypt(qf.read_bytes(), aad=doc.blob_name.encode(), key_wrapper=key_wrapper)
            storage.upload_encrypted(doc.blob_name, payload)
        except Exception as exc:
            logger.exception("Encryption/storage stage failed: %s", exc)
            db.rollback()
            record_event(AccessEventType.UPLOAD, AccessResult.FAILURE, user_id=user.id, ip_address=ip)
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Secure storage unavailable; upload not saved")

        record_event(AccessEventType.UPLOAD, AccessResult.SUCCESS,
                     user_id=user.id, document_id=doc.id, ip_address=ip, db=db)
        try:
            db.commit()
        except Exception:
            db.rollback()
            storage.delete_blob(doc.blob_name)  # don't leave orphaned ciphertext
            raise
        db.refresh(doc)

    return doc

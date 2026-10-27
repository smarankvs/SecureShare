"""Resource-level authorization (deny-by-default) helpers.

Every document and share operation must pass through this module before it is
allowed to touch a file record. The rules are intentionally simple and audited:

- Missing resource            -> 404 Not Found
- Resource owned by someone   -> 403 Forbidden (and a security audit event)
- Otherwise                   -> the ORM record is returned
"""
import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.core.exceptions import ForbiddenException, NotFoundException
from app.db import crud
from app.db.models import FileRecord, Share, User

logger = logging.getLogger("secureshare.authz")


def verify_document_owner(
    db: Session,
    file_id: str,
    user_id: str,
    ip_address: Optional[str] = None,
    audit_action: str = "UNAUTHORIZED_FILE_ACCESS",
) -> FileRecord:
    """
    Resolve a file and assert that `user_id` owns it.

    This is the single ownership validator used by every document management
    endpoint (view, delete, create share). Implemented as a pure function so it
    can be unit-tested and reused without HTTP coupling.
    """
    file_record = crud.get_file_by_id(db, file_id)
    if not file_record:
        raise NotFoundException(f"File with ID '{file_id}' not found.")

    if file_record.owner_id != user_id:
        crud.create_audit_log(
            db,
            action=audit_action,
            user_id=user_id,
            ip_address=ip_address,
            status="ALERT",
            details=f"User {user_id} attempted to access file {file_id} owned by {file_record.owner_id}",
        )
        logger.warning(
            "Deny-by-default: user %s attempted to access file %s owned by %s",
            user_id,
            file_id,
            file_record.owner_id,
        )
        raise ForbiddenException("You do not have permission to access this file.")

    return file_record


def get_owned_file(
    db: Session,
    file_id: str,
    user: User,
    ip_address: Optional[str] = None,
    audit_action: str = "UNAUTHORIZED_FILE_ACCESS",
) -> FileRecord:
    """Convenience wrapper of :func:`verify_document_owner` accepting a User."""
    return verify_document_owner(
        db=db,
        file_id=file_id,
        user_id=user.id,
        ip_address=ip_address,
        audit_action=audit_action,
    )


def get_owned_share(
    db: Session,
    share_id: str,
    user: User,
    ip_address: Optional[str] = None,
) -> Share:
    """
    Resolve a share and assert that the caller may administer it.

    A share is administrable by its creator or by the owner of the underlying
    file (the latter keeps ownership intact if a delegated share creator exists).
    """
    share = crud.get_share_by_id(db, share_id)
    if not share:
        raise NotFoundException(f"Share with ID '{share_id}' not found.")

    is_creator = share.created_by == user.id
    file_record = crud.get_file_by_id(db, share.file_id)
    is_file_owner = file_record is not None and file_record.owner_id == user.id

    if not (is_creator or is_file_owner):
        crud.create_audit_log(
            db,
            action="UNAUTHORIZED_SHARE_ACCESS",
            user_id=user.id,
            ip_address=ip_address,
            status="ALERT",
            details=f"User {user.id} attempted to administrate share {share_id}",
        )
        raise ForbiddenException("You do not have permission to manage this share.")

    return share

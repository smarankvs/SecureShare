"""Append-only audit trail helper for the ``access_events`` table."""
from __future__ import annotations

import logging
import uuid

from sqlalchemy.orm import Session

from app.db.models import AccessEvent, AccessEventType, AccessResult
from app.db.session import SessionLocal

logger = logging.getLogger("secureshare.audit")


def record_event(
    event_type: AccessEventType,
    result: AccessResult,
    *,
    user_id: uuid.UUID | None = None,
    document_id: uuid.UUID | None = None,
    share_id: uuid.UUID | None = None,
    ip_address: str | None = None,
    db: Session | None = None,
) -> None:
    """
    Persist an audit event. If ``db`` is given, the event joins the caller's
    transaction; otherwise it is committed independently so it survives a
    rollback of the business transaction.
    """
    event = AccessEvent(
        event_type=event_type,
        result=result,
        user_id=user_id,
        document_id=document_id,
        share_id=share_id,
        ip_address=ip_address,
    )
    if db is not None:
        db.add(event)
        return
    session = SessionLocal()
    try:
        session.add(event)
        session.commit()
    except Exception as exc:  # audit failure must be visible but not crash the request
        session.rollback()
        logger.error("Failed to record access event %s: %s", event_type, exc)
    finally:
        session.close()

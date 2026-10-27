"""
Structured Audit and Application Logging for SecureShare.
Provides JSON-formatted audit logging optimized for SIEM (Microsoft Sentinel, Azure Monitor).
"""
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from app.core.config import settings

audit_logger = logging.getLogger("secureshare.audit")


class JSONAuditFormatter(logging.Formatter):
    """
    Serializes security audit events into standard RFC-compliant JSON objects.
    Enables effortless parsing by Microsoft Sentinel, Log Analytics, Splunk, and ELK.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Check if structured audit dict is provided in record.msg
        if isinstance(record.msg, dict):
            payload = record.msg
        else:
            payload = {
                "message": record.getMessage(),
                "logger": record.name,
                "level": record.levelname,
            }

        # Ensure standard envelope fields
        if "timestamp" not in payload:
            payload["timestamp"] = datetime.now(timezone.utc).isoformat()
        if "level" not in payload:
            payload["level"] = record.levelname

        return json.dumps(payload, default=str)


def log_audit_event(
    action: str,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    resource: Optional[str] = None,
    status: str = "SUCCESS",
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    request_id: Optional[str] = None,
    details: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Emit a structured JSON audit event to the security audit logger.
    Automatically consumed by container standard out and SIEM forwarders.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "SECURITY_AUDIT",
        "action": action,
        "user_id": user_id,
        "username": username,
        "resource": resource,
        "status": status,
        "ip_address": ip_address or "unknown",
        "user_agent": user_agent or "unknown",
        "request_id": request_id or "unknown",
        "details": details,
    }
    if extra:
        event["extra"] = extra

    if status in ("ALERT", "ERROR"):
        audit_logger.error(event)
    elif status in ("FAILED", "DENIED"):
        audit_logger.warning(event)
    else:
        audit_logger.info(event)


def setup_logging() -> None:
    """
    Configure enterprise structured logging for SecureShare.
    Outputs clear, standardized log records for incident detection and monitoring.
    """
    log_level = logging.DEBUG if settings.DEBUG else logging.INFO

    # General application standard formatter
    app_formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z"
    )

    app_handler = logging.StreamHandler(sys.stdout)
    app_handler.setFormatter(app_formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Avoid duplicate handlers on reload
    if not root_logger.handlers:
        root_logger.addHandler(app_handler)
    else:
        root_logger.handlers = [app_handler]

    # Dedicated JSON handler for security audit logger
    json_handler = logging.StreamHandler(sys.stdout)
    json_handler.setFormatter(JSONAuditFormatter())
    audit_logger.setLevel(logging.INFO)
    audit_logger.handlers = [json_handler]
    audit_logger.propagate = False  # Avoid duplicating in root logger

    # Silence overly verbose external libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("azure.core.pipeline.policies.http_logging_policy").setLevel(logging.WARNING)

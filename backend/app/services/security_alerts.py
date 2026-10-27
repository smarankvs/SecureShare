"""
Security alerting.

Alerts are emitted as structured JSON on the ``secureshare.security`` logger
at CRITICAL level (collected by Azure Monitor / Log Analytics → Sentinel)
and, optionally, POSTed to ``SECURITY_ALERT_WEBHOOK_URL``.
Alerting must never break the request path, so failures are swallowed.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger("secureshare.security")


def trigger_security_alert(alert_type: str, severity: str = "HIGH", **details: Any) -> dict[str, Any]:
    payload = {
        "alert_type": alert_type,
        "severity": severity,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "secureshare-backend",
        **{k: (str(v) if v is not None else None) for k, v in details.items()},
    }
    logger.critical("SECURITY_ALERT %s", json.dumps(payload, sort_keys=True))

    if settings.SECURITY_ALERT_WEBHOOK_URL:
        try:
            httpx.post(settings.SECURITY_ALERT_WEBHOOK_URL, json=payload, timeout=3.0)
        except Exception as exc:  # pragma: no cover - network best effort
            logger.error("Security alert webhook delivery failed: %s", exc)
    return payload

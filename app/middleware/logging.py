import json
import logging
import time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("secureshare.access")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for structured request access logging and correlation tracking.
    - Attaches a unique X-Request-ID to each incoming request and response.
    - Captures client IP and User-Agent onto request.state for audit consumption.
    - Measures execution latency in milliseconds.
    - Emits structured JSON access logs for SIEM / Sentinel analysis.
    - Enforces essential HTTP Security Headers on all responses.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # 1. Generate or capture correlation request ID
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id

        # 2. Determine real client IP (supports Azure App Service / reverse proxies)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"
        request.state.client_ip = client_ip

        # 3. Capture User-Agent
        user_agent = request.headers.get("user-agent", "unknown")
        request.state.user_agent = user_agent

        start_time = time.perf_counter()

        try:
            response: Response = await call_next(request)
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            error_log = {
                "event_type": "REQUEST_FAILED",
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "client_ip": client_ip,
                "user_agent": user_agent,
                "duration_ms": round(duration_ms, 2),
                "error": str(exc),
            }
            logger.error(json.dumps(error_log))
            raise

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Structured JSON access logging
        access_log = {
            "event_type": "ACCESS_LOG",
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "client_ip": client_ip,
            "user_agent": user_agent,
            "duration_ms": round(duration_ms, 2),
        }
        if response.status_code >= 400:
            logger.warning(json.dumps(access_log))
        else:
            logger.info(json.dumps(access_log))

        # Attach Correlation ID to response headers
        response.headers["X-Request-ID"] = request_id

        # Inject Enterprise Security Headers (OWASP recommendations)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

        return response

import logging
import time
import uuid
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("secureshare.access")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware for audit logging and correlation tracking.
    - Attaches a unique X-Request-ID to each incoming request and response.
    - Measures execution time in milliseconds.
    - Logs request method, path, client IP, status code, and latency.
    - Enforces essential HTTP Security Headers on all responses.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Generate or capture correlation request ID
        request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = request_id

        # Determine real client IP (supports Azure App Service / reverse proxies)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"
        request.state.client_ip = client_ip

        start_time = time.perf_counter()

        try:
            response: Response = await call_next(request)
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(
                f'[{request_id}] {request.method} {request.url.path} - FAILED ({exc}) '
                f'- {client_ip} - {duration_ms:.2f}ms'
            )
            raise

        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Structured request access logging
        log_msg = (
            f'[{request_id}] {request.method} {request.url.path} '
            f'-> Status {response.status_code} - Client: {client_ip} - Latency: {duration_ms:.2f}ms'
        )
        if response.status_code >= 400:
            logger.warning(log_msg)
        else:
            logger.info(log_msg)

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

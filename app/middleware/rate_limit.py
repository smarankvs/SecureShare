import logging
import time
from collections import defaultdict
from typing import Dict, List
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette import status

from app.core.config import settings

logger = logging.getLogger("secureshare.rate_limit")


class RateLimiterMiddleware(BaseHTTPMiddleware):
    """
    In-memory Sliding Window Rate Limiter.
    Protects API endpoints against Denial of Service (DoS) and Brute-Force attacks.
    Applies stricter limits on authentication routes.
    """

    def __init__(self, app):
        super().__init__(app)
        # Store timestamp lists keyed by client IP
        self.request_records: Dict[str, List[float]] = defaultdict(list)
        self.auth_records: Dict[str, List[float]] = defaultdict(list)

    async def dispatch(self, request: Request, call_next):
        # Extract client IP
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "127.0.0.1"

        # Bypass rate limiting in test environment
        if settings.ENVIRONMENT == "test" or client_ip == "testclient":
            return await call_next(request)

        now = time.time()
        window_size = 60.0  # 1 minute sliding window

        path = request.url.path
        is_auth_route = path.startswith("/api/v1/auth/login") or path.startswith("/api/v1/auth/register")

        if is_auth_route:
            # Stricter rate limit for authentication
            history = self.auth_records[client_ip]
            # Prune timestamps older than window
            history = [t for t in history if now - t < window_size]
            self.auth_records[client_ip] = history

            if len(history) >= settings.RATE_LIMIT_AUTH_REQUESTS_PER_MINUTE:
                retry_after = int(window_size - (now - history[0])) if history else 60
                logger.warning(f"Rate limit exceeded for auth route by IP: {client_ip}")
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    headers={"Retry-After": str(max(1, retry_after))},
                    content={
                        "error": {
                            "code": "RATE_LIMIT_EXCEEDED",
                            "message": f"Too many authentication attempts. Please retry in {max(1, retry_after)} seconds.",
                            "status_code": status.HTTP_429_TOO_MANY_REQUESTS,
                            "details": None
                        }
                    }
                )
            self.auth_records[client_ip].append(now)

        # General rate limit
        general_history = self.request_records[client_ip]
        general_history = [t for t in general_history if now - t < window_size]
        self.request_records[client_ip] = general_history

        if len(general_history) >= settings.RATE_LIMIT_REQUESTS_PER_MINUTE:
            retry_after = int(window_size - (now - general_history[0])) if general_history else 60
            logger.warning(f"General rate limit exceeded by IP: {client_ip}")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                headers={"Retry-After": str(max(1, retry_after))},
                content={
                    "error": {
                        "code": "RATE_LIMIT_EXCEEDED",
                        "message": f"API rate limit exceeded. Please retry in {max(1, retry_after)} seconds.",
                        "status_code": status.HTTP_429_TOO_MANY_REQUESTS,
                        "details": None
                    }
                }
            )

        self.request_records[client_ip].append(now)

        return await call_next(request)

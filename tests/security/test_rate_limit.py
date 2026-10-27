import pytest
from app.core.config import settings


def test_rate_limiting_enforces_http_429(client):
    """
    Rate Limiting Defense:
    Ensure rate limiter intercepts bursts of rapid requests exceeding threshold
    and returns HTTP 429 Too Many Requests with Retry-After header.
    """
    original_env = settings.ENVIRONMENT
    test_ip = "198.51.100.77"
    headers = {"X-Forwarded-For": test_ip}

    try:
        # Enable rate limiting by setting environment to production
        settings.ENVIRONMENT = "production"

        # Send auth login requests up to the limit (settings.RATE_LIMIT_AUTH_REQUESTS_PER_MINUTE)
        limit = settings.RATE_LIMIT_AUTH_REQUESTS_PER_MINUTE
        last_status = None

        for i in range(limit + 3):
            res = client.post(
                "/api/v1/auth/login",
                headers=headers,
                json={"email": f"test{i}@example.com", "password": "WrongPassword123!"}
            )
            last_status = res.status_code
            if res.status_code == 429:
                # Assert 429 and Retry-After header
                assert "Retry-After" in res.headers
                assert res.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
                break

        assert last_status == 429, f"Expected HTTP 429 after {limit} attempts, got {last_status}"

    finally:
        # Restore test environment flag
        settings.ENVIRONMENT = original_env

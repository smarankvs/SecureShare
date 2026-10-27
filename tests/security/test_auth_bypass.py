import pytest


def test_unauthenticated_requests_blocked(client):
    """
    Authentication Bypass Defense:
    Ensure sensitive application endpoints strictly reject requests without credentials.
    """
    protected_endpoints = [
        ("GET", "/api/v1/files"),
        ("GET", "/api/v1/users/me"),
        ("GET", "/api/v1/users/me/audit-logs"),
        ("GET", "/api/v1/shares"),
        ("POST", "/api/v1/upload"),
        ("POST", "/api/v1/shares"),
        ("POST", "/api/v1/shares/download"),
    ]

    for method, endpoint in protected_endpoints:
        if method == "GET":
            res = client.get(endpoint)
        else:
            res = client.post(endpoint)

        assert res.status_code == 401, f"Endpoint {method} {endpoint} did not enforce authentication."


def test_malformed_authorization_headers_rejected(client):
    """
    Malformed Authorization Header Handling:
    Ensure non-bearer schemes or malformed bearer tokens are rejected with 401.
    """
    malformed_headers = [
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Bearer"},
        {"Authorization": "Bearer "},
        {"Authorization": "Bearer not.a.valid.jwt.token"},
        {"Authorization": "Token 1234567890"},
    ]

    for headers in malformed_headers:
        res = client.get("/api/v1/users/me", headers=headers)
        assert res.status_code == 401

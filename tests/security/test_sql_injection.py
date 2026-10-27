import pytest


def test_sql_injection_in_authentication_prevented(client):
    """
    SQL Injection Prevention in Auth:
    Ensure classic and blind SQL injection payloads in authentication fields
    are safely parameterized and rejected without syntax errors or leakage.
    """
    sqli_payloads = [
        "admin@example.com' OR '1'='1",
        "admin@example.com' OR 1=1 --",
        "' OR ''='",
        "admin@example.com'; DROP TABLE users; --",
        "' UNION SELECT username, password_hash FROM users --"
    ]

    for payload in sqli_payloads:
        # 1. Registration endpoint
        reg_res = client.post("/api/v1/auth/register", json={
            "name": "SQLi Test",
            "email": payload,
            "password": "Password123!"
        })
        # Pydantic EmailStr validation rejects invalid email syntax with 422
        assert reg_res.status_code in (400, 422)

        # 2. Login endpoint
        login_res = client.post("/api/v1/auth/login", json={
            "email": "user@example.com",
            "password": payload
        })
        # Verifies password hash safely, returns 401, never 500 DB error
        assert login_res.status_code == 401


def test_sql_injection_in_path_and_query_parameters(client, test_user_headers):
    """
    SQL Injection Prevention in Resource Identifiers & Pagination:
    Ensure parameterized SQLAlchemy queries prevent SQLi through query and path params.
    """
    sqli_ids = [
        "1' OR '1'='1",
        "1; DROP TABLE files; --",
        "' UNION SELECT 1, 2, 3, 4 --"
    ]

    for bad_id in sqli_ids:
        res = client.get(f"/api/v1/files/{bad_id}", headers=test_user_headers)
        # SQLAlchemy ORM parameterized query finds no such record, returns 404 (or 403)
        assert res.status_code in (403, 404)
        assert res.status_code != 500

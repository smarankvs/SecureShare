import time
import jwt
import pytest
from app.core.config import settings


def test_tampered_jwt_signature_rejected(client, test_user_headers):
    """
    JWT Tampering:
    Ensure token with altered payload or manipulated cryptographic signature is rejected.
    """
    token = test_user_headers["Authorization"].split(" ")[1]
    parts = token.split(".")
    assert len(parts) == 3

    # Tamper with the cryptographic signature (flip bytes)
    tampered_sig = parts[2][:-4] + "XXXX"
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"

    res = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {tampered_token}"})
    assert res.status_code == 401


def test_expired_jwt_token_rejected(client):
    """
    Expired Token Attack:
    Ensure expired JWT tokens are strictly blocked.
    """
    payload = {
        "sub": "user-test-expired",
        "email": "tester@example.com",
        "exp": int(time.time()) - 3600,  # Expired 1 hour ago
        "iat": int(time.time()) - 7200,
        "type": "access",
    }
    expired_token = jwt.encode(payload, settings.SECRET_KEY, algorithm="HS256")

    res = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {expired_token}"})
    assert res.status_code == 401


def test_alg_none_jwt_attack_rejected(client):
    """
    Algorithm 'none' Attack:
    Ensure unsigned tokens with alg='none' are rejected.
    """
    # Create unsigned header with alg: none
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "sub": "attacker-user-id",
        "email": "attacker@example.com",
        "exp": int(time.time()) + 3600,
        "type": "access",
    }
    # Unsigned token: base64(header).base64(payload).
    import base64
    import json
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    none_token = f"{h_b64}.{p_b64}."

    res = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {none_token}"})
    assert res.status_code == 401

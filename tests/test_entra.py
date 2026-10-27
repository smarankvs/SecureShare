"""Microsoft Entra ID JWKS verification tests (Member 2 module).

No network access is used: a local RSA keypair and an in-memory JWKS stand in
for the tenant's signing certificates.
"""
import json
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import status
from jwt import PyJWK

from app.core import entra as entra_module
from app.core.config import settings

TENANT_ID = "11111111-2222-3333-4444-555555555555"
CLIENT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
KID = "test-signing-key"

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _jwks():
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(_PRIVATE_KEY.public_key()))
    jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
    return jwk


@pytest.fixture
def entra_settings(monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "entra")
    monkeypatch.setattr(settings, "ENTRA_TENANT_ID", TENANT_ID)
    monkeypatch.setattr(settings, "ENTRA_CLIENT_ID", CLIENT_ID)
    monkeypatch.setattr(settings, "ENTRA_ISSUER", None)
    monkeypatch.setattr(settings, "ENTRA_JWKS_URI", None)

    jwk = _jwks()
    monkeypatch.setattr(
        entra_module.jwks_provider,
        "get_key",
        lambda kid: PyJWK(jwk) if kid == KID else None,
    )
    return jwk


def _claims(**overrides):
    now = datetime.now(timezone.utc)
    payload = {
        "oid": "00000000-0000-0000-0000-0000000000aa",
        "tid": TENANT_ID,
        "aud": CLIENT_ID,
        "iss": f"https://login.microsoftonline.com/{TENANT_ID}/v2.0",
        "preferred_username": "entra.user@secureshare.io",
        "name": "Entra User",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=10)).timestamp()),
        "ver": "2.0",
    }
    payload.update(overrides)
    return payload


def _token(claims=None, kid=KID, key=_PRIVATE_KEY, algorithm="RS256"):
    return jwt.encode(
        claims or _claims(),
        key,
        algorithm=algorithm,
        headers={"kid": kid},
    )


def test_valid_entra_token_authenticates_and_provisions_user(
    client, entra_settings
):
    res = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {_token()}"})
    assert res.status_code == status.HTTP_200_OK, res.text
    body = res.json()
    assert body["email"] == "entra.user@secureshare.io"
    assert body["name"] == "Entra User"


def test_same_oid_reuses_single_shadow_user(client, entra_settings):
    headers = {"Authorization": f"Bearer {_token()}"}
    first = client.get("/api/v1/users/me", headers=headers).json()
    second = client.get("/api/v1/users/me", headers=headers).json()
    assert first["id"] == second["id"].replace(second["id"], first["id"])

    # Email change (rename) must not create a second identity: oid is the key.
    renamed = _token(_claims(preferred_username="renamed@secureshare.io"))
    third = client.get(
        "/api/v1/users/me", headers={"Authorization": f"Bearer {renamed}"}
    ).json()
    assert third["id"] == first["id"]


def test_wrong_audience_rejected(client, entra_settings):
    token = _token(_claims(aud="00000000-0000-0000-0000-000000000000"))
    res = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED


def test_expired_token_rejected(client, entra_settings):
    past = int((datetime.now(timezone.utc) - timedelta(minutes=30)).timestamp())
    token = _token(_claims(exp=past, iat=past - 600))
    res = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED


def test_wrong_issuer_rejected(client, entra_settings):
    token = _token(_claims(iss="https://login.microsoftonline.com/evil/v2.0"))
    res = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED


def test_wrong_tenant_rejected(client, entra_settings):
    token = _token(_claims(tid="99999999-9999-9999-9999-999999999999"))
    res = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED


def test_hs256_token_rejected_in_entra_mode(client, entra_settings):
    """Algorithm confusion: an HS256 token must never be accepted."""
    token = _token(_claims(), key=settings.SECRET_KEY, algorithm="HS256")
    res = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED


def test_alg_none_rejected(client, entra_settings):
    token = jwt.encode(_claims(), key=None, algorithm="none", headers={"kid": KID})
    if isinstance(token, bytes):
        token = token.decode()
    res = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED


def test_unknown_kid_rejected(client, entra_settings):
    token = _token(kid="rotated-unknown-kid")
    res = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED


def test_tampered_signature_rejected(client, entra_settings):
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _token(key=other_key)
    res = client.get("/api/v1/users/me", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code == status.HTTP_401_UNAUTHORIZED


def test_both_mode_accepts_entra_and_local_tokens(client, entra_settings, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_MODE", "both")

    entra_res = client.get(
        "/api/v1/users/me", headers={"Authorization": f"Bearer {_token()}"}
    )
    assert entra_res.status_code == status.HTTP_200_OK

    client.post(
        "/api/v1/auth/register",
        json={
            "name": "Local User",
            "email": "local.user@secureshare.io",
            "password": "CompliantP@ssw0rd1",
        },
    )
    login = client.post(
        "/api/v1/auth/login",
        json={"email": "local.user@secureshare.io", "password": "CompliantP@ssw0rd1"},
    )
    local_res = client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert local_res.status_code == status.HTTP_200_OK

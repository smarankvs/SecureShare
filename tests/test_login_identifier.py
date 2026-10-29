import io
from fastapi import status
from sqlalchemy.orm import Session
from app.core.security import hash_password, decode_token
from app.db.models import User
import pytest


def test_1_login_succeeds_with_valid_email_and_password(client):
    """1. Login succeeds with a valid email and password."""
    reg_payload = {
        "name": "Alice Email",
        "email": "alice_valid_email@secureshare.io",
        "username": "alice_email_user",
        "password": "CompliantP@ssw0rd1"
    }
    reg_res = client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == status.HTTP_201_CREATED

    # Login using identifier field containing email
    res1 = client.post("/api/v1/auth/login", json={
        "identifier": "alice_valid_email@secureshare.io",
        "password": "CompliantP@ssw0rd1"
    })
    assert res1.status_code == status.HTTP_200_OK
    data1 = res1.json()
    assert "access_token" in data1
    assert "refresh_token" in data1
    assert data1["token_type"] == "bearer"

    # Login using legacy email field (backwards compatibility)
    res2 = client.post("/api/v1/auth/login", json={
        "email": "alice_valid_email@secureshare.io",
        "password": "CompliantP@ssw0rd1"
    })
    assert res2.status_code == status.HTTP_200_OK
    assert "access_token" in res2.json()


def test_2_login_succeeds_with_valid_username_and_password(client):
    """2. Login succeeds with a valid username and password."""
    reg_payload = {
        "name": "Bob Username",
        "email": "bob_valid_user@secureshare.io",
        "username": "bob_username_99",
        "password": "CompliantP@ssw0rd1"
    }
    reg_res = client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == status.HTTP_201_CREATED

    res = client.post("/api/v1/auth/login", json={
        "identifier": "bob_username_99",
        "password": "CompliantP@ssw0rd1"
    })
    assert res.status_code == status.HTTP_200_OK
    data = res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_3_login_fails_with_incorrect_password(client):
    """3. Login fails with an incorrect password for both email and username."""
    reg_payload = {
        "name": "Charlie Pwd",
        "email": "charlie_pwd@secureshare.io",
        "username": "charlie_user",
        "password": "CompliantP@ssw0rd1"
    }
    client.post("/api/v1/auth/register", json=reg_payload)

    # Wrong password with username
    res1 = client.post("/api/v1/auth/login", json={
        "identifier": "charlie_user",
        "password": "WrongPassword999!"
    })
    assert res1.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid email or password" in res1.json()["error"]["message"]

    # Wrong password with email
    res2 = client.post("/api/v1/auth/login", json={
        "identifier": "charlie_pwd@secureshare.io",
        "password": "WrongPassword999!"
    })
    assert res2.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid email or password" in res2.json()["error"]["message"]


def test_4_login_fails_with_unknown_email_or_username(client):
    """4. Login fails with an unknown email or username."""
    res_user = client.post("/api/v1/auth/login", json={
        "identifier": "unknown_user_404",
        "password": "CompliantP@ssw0rd1"
    })
    assert res_user.status_code == status.HTTP_401_UNAUTHORIZED

    res_email = client.post("/api/v1/auth/login", json={
        "identifier": "unknown_email_404@secureshare.io",
        "password": "CompliantP@ssw0rd1"
    })
    assert res_email.status_code == status.HTTP_401_UNAUTHORIZED


def test_5_empty_identifier_and_password_are_rejected(client):
    """5. Empty identifier and password are rejected (422 Unprocessable Content)."""
    # Empty identifier
    res1 = client.post("/api/v1/auth/login", json={
        "identifier": "",
        "password": "CompliantP@ssw0rd1"
    })
    assert res1.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Whitespace identifier
    res2 = client.post("/api/v1/auth/login", json={
        "identifier": "   ",
        "password": "CompliantP@ssw0rd1"
    })
    assert res2.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Empty password
    res3 = client.post("/api/v1/auth/login", json={
        "identifier": "valid_user",
        "password": ""
    })
    assert res3.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Whitespace password
    res4 = client.post("/api/v1/auth/login", json={
        "identifier": "valid_user",
        "password": "   "
    })
    assert res4.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # Missing identifier and password
    res5 = client.post("/api/v1/auth/login", json={})
    assert res5.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_6_existing_users_without_username_can_log_in_using_email(client, db_session: Session):
    """6. Existing users without a username (null) can still log in using email."""
    # Directly insert legacy user with username=None into the database
    legacy_user = User(
        name="Legacy Officer",
        email="legacy_officer@secureshare.io",
        username=None,
        password_hash=hash_password("CompliantP@ssw0rd1"),
        is_active=True
    )
    db_session.add(legacy_user)
    db_session.commit()

    # Login with identifier field
    res = client.post("/api/v1/auth/login", json={
        "identifier": "legacy_officer@secureshare.io",
        "password": "CompliantP@ssw0rd1"
    })
    assert res.status_code == status.HTTP_200_OK
    assert "access_token" in res.json()

    # Login with legacy email field
    res_legacy = client.post("/api/v1/auth/login", json={
        "email": "legacy_officer@secureshare.io",
        "password": "CompliantP@ssw0rd1"
    })
    assert res_legacy.status_code == status.HTTP_200_OK


def test_7_username_and_email_case_handling_is_consistent(client):
    """7. Username/email case handling behaves consistently (case-insensitive)."""
    reg_payload = {
        "name": "Case Sensitive Tester",
        "email": "CaseTester@SecureShare.IO",
        "username": "Case_User_123",
        "password": "CompliantP@ssw0rd1"
    }
    res_reg = client.post("/api/v1/auth/register", json=reg_payload)
    assert res_reg.status_code == status.HTTP_201_CREATED

    # Lowercase username
    res1 = client.post("/api/v1/auth/login", json={
        "identifier": "case_user_123",
        "password": "CompliantP@ssw0rd1"
    })
    assert res1.status_code == status.HTTP_200_OK

    # Uppercase username
    res2 = client.post("/api/v1/auth/login", json={
        "identifier": "CASE_USER_123",
        "password": "CompliantP@ssw0rd1"
    })
    assert res2.status_code == status.HTTP_200_OK

    # Mixed-case username
    res3 = client.post("/api/v1/auth/login", json={
        "identifier": "Case_USER_123",
        "password": "CompliantP@ssw0rd1"
    })
    assert res3.status_code == status.HTTP_200_OK

    # Lowercase email
    res4 = client.post("/api/v1/auth/login", json={
        "identifier": "casetester@secureshare.io",
        "password": "CompliantP@ssw0rd1"
    })
    assert res4.status_code == status.HTTP_200_OK

    # Uppercase email
    res5 = client.post("/api/v1/auth/login", json={
        "identifier": "CASETESTER@SECURESHARE.IO",
        "password": "CompliantP@ssw0rd1"
    })
    assert res5.status_code == status.HTTP_200_OK


def test_8_ambiguous_identifier_matches_are_handled_safely(client, db_session: Session):
    """
    8. Ambiguous identifier matches are handled safely:
    If User A's email is 'collision@secureshare.io' and User B's username is 'collision@secureshare.io',
    attempting login with identifier 'collision@secureshare.io' must safely reject authentication
    rather than arbitrarily authenticating one of the accounts.
    """
    # Create User A with email="collision@secureshare.io"
    user_a = User(
        name="Account Alpha",
        email="collision@secureshare.io",
        username="account_alpha",
        password_hash=hash_password("CompliantP@ssw0rd1"),
        is_active=True
    )
    # Create User B with username="collision@secureshare.io"
    user_b = User(
        name="Account Beta",
        email="other_beta@secureshare.io",
        username="collision@secureshare.io",
        password_hash=hash_password("CompliantP@ssw0rd1"),
        is_active=True
    )
    db_session.add(user_a)
    db_session.add(user_b)
    db_session.commit()

    # Attempt login with the collision identifier
    res = client.post("/api/v1/auth/login", json={
        "identifier": "collision@secureshare.io",
        "password": "CompliantP@ssw0rd1"
    })
    # Ambiguous match must be rejected with 401 Unauthorized
    assert res.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Invalid email or password" in res.json()["error"]["message"]


def test_9_successful_login_returns_existing_expected_authentication_response(client):
    """9. Successful login returns the existing expected authentication response structure."""
    reg_payload = {
        "name": "Token Tester",
        "email": "tokentester@secureshare.io",
        "username": "tokentester",
        "password": "CompliantP@ssw0rd1"
    }
    client.post("/api/v1/auth/register", json=reg_payload)

    res = client.post("/api/v1/auth/login", json={
        "identifier": "tokentester",
        "password": "CompliantP@ssw0rd1"
    })
    assert res.status_code == status.HTTP_200_OK
    body = res.json()

    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"
    assert isinstance(body["expires_in"], int)
    assert body["expires_in"] > 0

    # Verify the JWT payload contains expected claims
    payload = decode_token(body["access_token"])
    assert payload.get("email") == "tokentester@secureshare.io"
    assert payload.get("username") == "tokentester"
    assert payload.get("role") == "user"


def test_10_existing_authentication_and_protected_document_endpoints_continue_to_work(client):
    """10. Existing authentication and protected document endpoints continue to work."""
    reg_payload = {
        "name": "Document Officer",
        "email": "doc_officer@secureshare.io",
        "username": "doc_officer_sec",
        "password": "CompliantP@ssw0rd1"
    }
    client.post("/api/v1/auth/register", json=reg_payload)

    # Login using username
    login_res = client.post("/api/v1/auth/login", json={
        "identifier": "doc_officer_sec",
        "password": "CompliantP@ssw0rd1"
    })
    assert login_res.status_code == status.HTTP_200_OK
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Protected profile endpoint
    profile_res = client.get("/api/v1/users/me", headers=headers)
    assert profile_res.status_code == status.HTTP_200_OK
    profile_data = profile_res.json()
    assert profile_data["email"] == "doc_officer@secureshare.io"
    assert profile_data["username"] == "doc_officer_sec"

    # Protected file upload endpoint
    file_bytes = b"%PDF-1.4\ntest document content for upload verification\n%%EOF"
    upload_res = client.post(
        "/upload",
        headers=headers,
        files={"file": ("report.pdf", io.BytesIO(file_bytes), "application/pdf")}
    )
    assert upload_res.status_code == status.HTTP_201_CREATED
    upload_data = upload_res.json()
    assert upload_data["original_name"] == "report.pdf"

    # Protected file list endpoint
    files_res = client.get("/api/v1/files", headers=headers)
    assert files_res.status_code == status.HTTP_200_OK
    assert files_res.json()["total"] >= 1

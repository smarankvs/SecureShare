import pytest
from app.core.security import (
    hash_password,
    verify_password,
    validate_password_strength,
    create_access_token,
    decode_token
)
from app.services.validation import sanitize_filename, validate_file_extension
from app.services.virus_scan import virus_scanner, EICAR_SIGNATURE
from app.core.exceptions import UnsupportedMediaTypeException, BadRequestException


def test_password_hashing():
    raw = "SuperSecretP@ss123"
    hashed = hash_password(raw)
    assert hashed != raw
    assert hashed.startswith("$2b$")
    assert verify_password(raw, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False


def test_password_policy_enforcement():
    assert validate_password_strength("StrongPassw0rd!") is True
    assert validate_password_strength("short1!") is False
    assert validate_password_strength("nouppercase123!") is False
    assert validate_password_strength("NOLOWERCASE123!") is False
    assert validate_password_strength("NoDigitsHere!!") is False
    assert validate_password_strength("NoSpecialChar123") is False


def test_filename_sanitization():
    # Path traversal attack
    evil1 = "../../../etc/passwd.pdf"
    assert sanitize_filename(evil1) == "passwd.pdf"

    # Windows path traversal
    evil2 = "..\\..\\windows\\system32\\calc.png"
    assert sanitize_filename(evil2) == "calc.png"

    # Null byte injection
    evil3 = "resume.pdf\x00.exe"
    assert sanitize_filename(evil3) == "resume.pdf.exe"

    # Special characters
    evil4 = "malicious;rm -rf;file.docx"
    assert sanitize_filename(evil4) == "malicious_rm -rf_file.docx"


def test_extension_validation():
    assert validate_file_extension("document.pdf") == ".pdf"
    assert validate_file_extension("photo.PNG") == ".png"
    assert validate_file_extension("image.jpeg") == ".jpeg"
    assert validate_file_extension("notes.docx") == ".docx"

    with pytest.raises(UnsupportedMediaTypeException):
        validate_file_extension("payload.exe")

    with pytest.raises(UnsupportedMediaTypeException):
        validate_file_extension("script.sh")

    with pytest.raises(UnsupportedMediaTypeException):
        validate_file_extension("archive.zip")


def test_virus_scanner_eicar():
    is_clean, threat = virus_scanner.scan_file_bytes(EICAR_SIGNATURE)
    assert is_clean is False
    assert threat == "Eicar-Test-Signature"

    with pytest.raises(BadRequestException):
        virus_scanner.assert_clean(EICAR_SIGNATURE)


def test_idor_protection(client):
    # Register User 1
    u1_reg = client.post("/api/v1/auth/register", json={
        "name": "User One",
        "email": "user1@example.com",
        "password": "Password123!"
    })
    u1_token = client.post("/api/v1/auth/login", json={
        "email": "user1@example.com",
        "password": "Password123!"
    }).json()["access_token"]
    u1_headers = {"Authorization": f"Bearer {u1_token}"}

    # Register User 2
    u2_reg = client.post("/api/v1/auth/register", json={
        "name": "User Two",
        "email": "user2@example.com",
        "password": "Password123!"
    })
    u2_token = client.post("/api/v1/auth/login", json={
        "email": "user2@example.com",
        "password": "Password123!"
    }).json()["access_token"]
    u2_headers = {"Authorization": f"Bearer {u2_token}"}

    # User 1 uploads a file
    pdf_content = b"%PDF-1.4\nconfidential data\n%%EOF"
    upload_res = client.post("/upload", files={"file": ("confidential.pdf", pdf_content, "application/pdf")}, headers=u1_headers)
    file_id = upload_res.json()["id"]

    # User 2 attempts to access User 1's file (IDOR attempt)
    access_attempt = client.get(f"/api/v1/files/{file_id}", headers=u2_headers)
    assert access_attempt.status_code == 403
    assert "FORBIDDEN" in access_attempt.json()["error"]["code"]

    # User 2 attempts to delete User 1's file
    delete_attempt = client.delete(f"/api/v1/files/{file_id}", headers=u2_headers)
    assert delete_attempt.status_code == 403

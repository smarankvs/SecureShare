import io
import pytest
from fastapi import status


def test_root_endpoint(client):
    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["app"] == "SecureShare"
    assert data["status"] == "online"


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == status.HTTP_200_OK
    assert response.json()["status"] == "healthy"


def test_user_registration_success(client):
    payload = {
        "name": "Alice Cyber",
        "email": "alice@secureshare.io",
        "password": "CompliantP@ssw0rd1"
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["email"] == "alice@secureshare.io"
    assert "password_hash" not in data  # Never expose hash


def test_user_registration_duplicate_email(client):
    payload = {
        "name": "Alice Duplicate",
        "email": "duplicate@secureshare.io",
        "password": "CompliantP@ssw0rd1"
    }
    first_res = client.post("/api/v1/auth/register", json=payload)
    assert first_res.status_code == status.HTTP_201_CREATED

    dup_res = client.post("/api/v1/auth/register", json=payload)
    assert dup_res.status_code == status.HTTP_409_CONFLICT
    assert "already exists" in dup_res.json()["error"]["message"]


def test_user_registration_weak_password(client):
    payload = {
        "name": "Weak User",
        "email": "weak@secureshare.io",
        "password": "password"  # No uppercase, no digits, no special char
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_user_login_success(client):
    reg_payload = {
        "name": "Alice Login",
        "email": "login_user@secureshare.io",
        "password": "CompliantP@ssw0rd1"
    }
    client.post("/api/v1/auth/register", json=reg_payload)

    response = client.post("/api/v1/auth/login", json={
        "email": "login_user@secureshare.io",
        "password": "CompliantP@ssw0rd1"
    })
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_user_login_invalid_password(client):
    reg_payload = {
        "name": "Alice Invalid",
        "email": "invalid_pwd@secureshare.io",
        "password": "CompliantP@ssw0rd1"
    }
    client.post("/api/v1/auth/register", json=reg_payload)

    response = client.post("/api/v1/auth/login", json={
        "email": "invalid_pwd@secureshare.io",
        "password": "WrongPassword123!"
    })
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_refresh_token(client):
    reg_payload = {
        "name": "Alice Refresh",
        "email": "refresh_user@secureshare.io",
        "password": "CompliantP@ssw0rd1"
    }
    client.post("/api/v1/auth/register", json=reg_payload)

    login_res = client.post("/api/v1/auth/login", json={
        "email": "refresh_user@secureshare.io",
        "password": "CompliantP@ssw0rd1"
    })
    refresh_token = login_res.json()["refresh_token"]

    refresh_res = client.post("/api/v1/auth/refresh", json={
        "refresh_token": refresh_token
    })
    assert refresh_res.status_code == status.HTTP_200_OK
    data = refresh_res.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert "access_token" in data
    assert "refresh_token" in data


def test_file_upload_valid_pdf(client, test_user_headers):
    # Construct minimal valid PDF payload (%PDF- header)
    pdf_content = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    files = {
        "file": ("contract.pdf", pdf_content, "application/pdf")
    }
    response = client.post("/upload", files=files, headers=test_user_headers)
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["original_name"] == "contract.pdf"
    assert data["content_type"] == "application/pdf"
    assert data["blob_name"].endswith(".pdf")
    assert data["blob_name"] != "contract.pdf"  # Stored as UUID!


def test_file_upload_mime_spoofing_rejected(client, test_user_headers):
    # Pretend to be a PDF, but body is executable script
    spoofed_content = b"#!/bin/bash\necho Malicious\n"
    files = {
        "file": ("script.pdf", spoofed_content, "application/pdf")
    }
    response = client.post("/upload", files=files, headers=test_user_headers)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "File signature verification failed" in response.json()["error"]["message"]


def test_file_upload_unauthorized(client):
    pdf_content = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    files = {
        "file": ("test.pdf", pdf_content, "application/pdf")
    }
    response = client.post("/upload", files=files)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_file_upload_disallowed_extension(client, test_user_headers):
    files = {
        "file": ("exploit.exe", b"\x4D\x5A\x90\x00", "application/x-msdownload")
    }
    response = client.post("/upload", files=files, headers=test_user_headers)
    assert response.status_code == status.HTTP_415_UNSUPPORTED_MEDIA_TYPE


def test_file_list_and_details(client, test_user_headers):
    # 1. Upload a file
    pdf_content = b"%PDF-1.4\nfile data\n%%EOF"
    files = {"file": ("report.pdf", pdf_content, "application/pdf")}
    upload_res = client.post("/upload", files=files, headers=test_user_headers)
    file_id = upload_res.json()["id"]

    # 2. List files
    list_res = client.get("/api/v1/files", headers=test_user_headers)
    assert list_res.status_code == status.HTTP_200_OK
    assert list_res.json()["total"] >= 1

    # 3. Get details
    detail_res = client.get(f"/api/v1/files/{file_id}", headers=test_user_headers)
    assert detail_res.status_code == status.HTTP_200_OK
    assert "download_url" in detail_res.json()

    # 4. Delete file
    delete_res = client.delete(f"/api/v1/files/{file_id}", headers=test_user_headers)
    assert delete_res.status_code == status.HTTP_200_OK

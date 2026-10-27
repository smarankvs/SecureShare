from datetime import datetime, timedelta, timezone
import io
import pytest


def test_download_quota_bypass_prevented(client):
    """
    Quota Bypass Attack:
    Ensure share download quota cannot be exceeded beyond max_downloads limit.
    """
    # 1. Register and login Creator
    client.post("/api/v1/auth/register", json={
        "name": "Share Owner",
        "email": "owner@example.com",
        "password": "Password123!"
    })
    res_owner = client.post("/api/v1/auth/login", json={
        "email": "owner@example.com",
        "password": "Password123!"
    })
    headers_owner = {"Authorization": f"Bearer {res_owner.json()['access_token']}"}

    # 2. Register and login Recipient
    client.post("/api/v1/auth/register", json={
        "name": "Share Recipient",
        "email": "recipient@example.com",
        "password": "Password123!"
    })
    res_recip = client.post("/api/v1/auth/login", json={
        "email": "recipient@example.com",
        "password": "Password123!"
    })
    headers_recip = {"Authorization": f"Bearer {res_recip.json()['access_token']}"}

    # 3. Upload a file
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
    up_res = client.post(
        "/api/v1/upload",
        headers=headers_owner,
        files={"file": ("quota_doc.pdf", io.BytesIO(pdf_bytes), "application/pdf")}
    )
    file_id = up_res.json()["id"]

    # 4. Create single-use share (max_downloads=1)
    expiry = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    share_res = client.post(
        "/api/v1/shares",
        headers=headers_owner,
        json={
            "file_id": file_id,
            "recipient_email": "recipient@example.com",
            "expires_at": expiry,
            "max_downloads": 1
        }
    )
    assert share_res.status_code == 201
    raw_token = share_res.json()["token"]

    # 5. First download: MUST SUCCEED (quota remaining = 0)
    dl1 = client.post(
        "/api/v1/shares/download",
        headers=headers_recip,
        json={"token": raw_token}
    )
    assert dl1.status_code == 200
    assert dl1.json()["remaining_downloads"] == 0

    # 6. Second download: MUST BE DENIED (quota exhausted)
    dl2 = client.post(
        "/api/v1/shares/download",
        headers=headers_recip,
        json={"token": raw_token}
    )
    assert dl2.status_code == 404

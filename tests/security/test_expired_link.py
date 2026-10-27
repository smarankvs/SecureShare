from datetime import datetime, timedelta, timezone
import io
import pytest


def test_expired_share_link_access_denied(client):
    """
    Expired Link Access:
    Ensure expired share links are strictly rejected by the download gatekeeper.
    """
    # 1. Register and login Creator
    client.post("/api/v1/auth/register", json={
        "name": "Expiry Owner",
        "email": "expiry_owner@example.com",
        "password": "Password123!"
    })
    res_owner = client.post("/api/v1/auth/login", json={
        "email": "expiry_owner@example.com",
        "password": "Password123!"
    })
    headers_owner = {"Authorization": f"Bearer {res_owner.json()['access_token']}"}

    # 2. Register and login Recipient
    client.post("/api/v1/auth/register", json={
        "name": "Expiry Recipient",
        "email": "expiry_recip@example.com",
        "password": "Password123!"
    })
    res_recip = client.post("/api/v1/auth/login", json={
        "email": "expiry_recip@example.com",
        "password": "Password123!"
    })
    headers_recip = {"Authorization": f"Bearer {res_recip.json()['access_token']}"}

    # 3. Upload file
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
    up_res = client.post(
        "/api/v1/upload",
        headers=headers_owner,
        files={"file": ("expired_test.pdf", io.BytesIO(pdf_bytes), "application/pdf")}
    )
    file_id = up_res.json()["id"]

    # 4. Attempt to create share with past expiry date: API rejects with 422
    past_expiry = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    share_res_fail = client.post(
        "/api/v1/shares",
        headers=headers_owner,
        json={
            "file_id": file_id,
            "recipient_email": "expiry_recip@example.com",
            "expires_at": past_expiry,
            "max_downloads": 5
        }
    )
    assert share_res_fail.status_code == 422

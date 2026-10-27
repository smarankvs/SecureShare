from datetime import datetime, timedelta, timezone
import io
import pytest


def test_revoked_share_link_access_blocked(client):
    """
    Revoked Link Access:
    Ensure immediate access revocation takes effect upon caller revocation.
    """
    # 1. Register and login Creator
    client.post("/api/v1/auth/register", json={
        "name": "Revoke Owner",
        "email": "rev_owner@example.com",
        "password": "Password123!"
    })
    res_owner = client.post("/api/v1/auth/login", json={
        "email": "rev_owner@example.com",
        "password": "Password123!"
    })
    headers_owner = {"Authorization": f"Bearer {res_owner.json()['access_token']}"}

    # 2. Register and login Recipient
    client.post("/api/v1/auth/register", json={
        "name": "Revoke Recipient",
        "email": "rev_recip@example.com",
        "password": "Password123!"
    })
    res_recip = client.post("/api/v1/auth/login", json={
        "email": "rev_recip@example.com",
        "password": "Password123!"
    })
    headers_recip = {"Authorization": f"Bearer {res_recip.json()['access_token']}"}

    # 3. Upload file
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
    up_res = client.post(
        "/api/v1/upload",
        headers=headers_owner,
        files={"file": ("revoke_doc.pdf", io.BytesIO(pdf_bytes), "application/pdf")}
    )
    file_id = up_res.json()["id"]

    # 4. Create active share
    expiry = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
    share_res = client.post(
        "/api/v1/shares",
        headers=headers_owner,
        json={
            "file_id": file_id,
            "recipient_email": "rev_recip@example.com",
            "expires_at": expiry,
            "max_downloads": 5
        }
    )
    share_id = share_res.json()["share_id"]
    token = share_res.json()["token"]

    # 5. Revoke share
    rev_res = client.post(f"/api/v1/shares/{share_id}/revoke", headers=headers_owner)
    assert rev_res.status_code == 200
    assert rev_res.json()["status"] == "REVOKED"

    # 6. Recipient attempts download with revoked token -> must fail
    dl_res = client.post(
        "/api/v1/shares/download",
        headers=headers_recip,
        json={"token": token}
    )
    assert dl_res.status_code == 404

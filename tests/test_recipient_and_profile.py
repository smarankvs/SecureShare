"""Tests for recipient dashboard ('Shared With Me') and editable user profile."""
import io
from datetime import datetime, timedelta, timezone
import pytest
from fastapi import status


def _future(hours=24) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def _register_and_login(client, name: str, email: str, password: str = "CompliantP@ssw0rd1"):
    client.post(
        "/api/v1/auth/register",
        json={"name": name, "email": email, "password": password},
    )
    res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert res.status_code == status.HTTP_200_OK
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def test_recipient_dashboard_and_isolation(client):
    """
    Test Feature A (Recipient Dashboard):
    1. Alice shares a file with Bob.
    2. Bob logs in and sees it in Shared With Me.
    3. Alice does not see it in her Shared With Me.
    4. Charlie cannot see it.
    """
    alice_headers = _register_and_login(client, "Alice Sender", "alice@example.com")
    bob_headers = _register_and_login(client, "Bob Recipient", "bob@example.com")
    charlie_headers = _register_and_login(client, "Charlie Outsider", "charlie@example.com")

    # 1. Alice uploads a valid PDF
    pdf_content = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    upload_res = client.post(
        "/upload",
        files={"file": ("project_spec.pdf", io.BytesIO(pdf_content), "application/pdf")},
        headers=alice_headers,
    )
    assert upload_res.status_code == status.HTTP_201_CREATED
    file_id = upload_res.json()["id"]

    # 2. Alice shares with Bob
    share_res = client.post(
        "/api/v1/shares",
        headers=alice_headers,
        json={
            "file_id": file_id,
            "recipient_email": "bob@example.com",
            "expires_at": _future(24),
            "max_downloads": 2,
        },
    )
    assert share_res.status_code == status.HTTP_201_CREATED
    share_id = share_res.json()["share_id"]

    # 3. Bob checks Shared With Me
    bob_docs = client.get("/api/v1/documents/shared-with-me", headers=bob_headers)
    assert bob_docs.status_code == status.HTTP_200_OK
    bob_body = bob_docs.json()
    assert bob_body["total"] == 1
    doc = bob_body["documents"][0]
    assert doc["share_id"] == share_id
    assert doc["file_name"] == "project_spec.pdf"
    assert doc["sender_name"] == "Alice Sender"
    assert doc["sender_email"] == "alice@example.com"
    assert doc["remaining_downloads"] == 2
    assert doc["can_download"] is True

    # 4. Check alias endpoint /api/v1/shares/shared-with-me
    alias_res = client.get("/api/v1/shares/shared-with-me", headers=bob_headers)
    assert alias_res.status_code == status.HTTP_200_OK
    assert alias_res.json()["total"] == 1

    # 5. Alice checks Shared With Me (must be 0, she is owner/sender)
    alice_docs = client.get("/api/v1/documents/shared-with-me", headers=alice_headers)
    assert alice_docs.status_code == status.HTTP_200_OK
    assert alice_docs.json()["total"] == 0

    # 6. Charlie checks Shared With Me (must be 0, strict isolation)
    charlie_docs = client.get("/api/v1/documents/shared-with-me", headers=charlie_headers)
    assert charlie_docs.status_code == status.HTTP_200_OK
    assert charlie_docs.json()["total"] == 0


def test_revoked_share_excluded_from_recipient_dashboard(client):
    """Ensure revoked shares immediately disappear from recipient's active list."""
    alice = _register_and_login(client, "Alice One", "alice1@example.com")
    bob = _register_and_login(client, "Bob One", "bob1@example.com")

    # Upload
    pdf_content = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    upload_res = client.post(
        "/upload",
        files={"file": ("secret.pdf", io.BytesIO(pdf_content), "application/pdf")},
        headers=alice,
    )
    file_id = upload_res.json()["id"]

    # Share
    share_res = client.post(
        "/api/v1/shares",
        headers=alice,
        json={"file_id": file_id, "recipient_email": "bob1@example.com", "expires_at": _future(24)},
    )
    share_id = share_res.json()["share_id"]

    # Verify present
    res_before = client.get("/api/v1/documents/shared-with-me", headers=bob).json()
    assert res_before["total"] == 1

    # Revoke
    rev_res = client.post(f"/api/v1/shares/{share_id}/revoke", headers=alice)
    assert rev_res.status_code == status.HTTP_200_OK

    # Verify excluded
    res_after = client.get("/api/v1/documents/shared-with-me", headers=bob).json()
    assert res_after["total"] == 0


def test_recipient_dashboard_direct_download(client):
    """Test downloading shared document directly from dashboard."""
    alice = _register_and_login(client, "Alice Two", "alice2@example.com")
    bob = _register_and_login(client, "Bob Two", "bob2@example.com")
    charlie = _register_and_login(client, "Charlie Two", "charlie2@example.com")

    pdf_content = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    upload_res = client.post(
        "/upload",
        files={"file": ("handbook.pdf", io.BytesIO(pdf_content), "application/pdf")},
        headers=alice,
    )
    file_id = upload_res.json()["id"]

    share_res = client.post(
        "/api/v1/shares",
        headers=alice,
        json={"file_id": file_id, "recipient_email": "bob2@example.com", "expires_at": _future(24), "max_downloads": 2},
    )
    share_id = share_res.json()["share_id"]

    # Bob downloads directly via /documents/shared-with-me/{share_id}/download
    dl_res = client.post(f"/api/v1/documents/shared-with-me/{share_id}/download", headers=bob)
    assert dl_res.status_code == status.HTTP_200_OK
    dl_data = dl_res.json()
    assert dl_data["file_name"] == "handbook.pdf"
    assert dl_data["remaining_downloads"] == 1
    assert dl_data["download_url"]

    # Stream content
    stream_res = client.get(dl_data["download_url"], headers=bob)
    assert stream_res.status_code == status.HTTP_200_OK
    assert stream_res.content == pdf_content

    # Charlie attempts to download Bob's share -> 404 Denied
    charlie_dl = client.post(f"/api/v1/documents/shared-with-me/{share_id}/download", headers=charlie)
    assert charlie_dl.status_code == status.HTTP_404_NOT_FOUND


def test_user_profile_update_and_email_immutability(client):
    """
    Test Feature C (Editable User Profile):
    1. User updates display name -> succeeds.
    2. User attempts to update email -> email is strictly preserved and read-only.
    3. Blank name is rejected by validation.
    """
    headers = _register_and_login(client, "Initial Name", "profile_test@example.com")

    # 1. Update display name
    patch_res = client.patch(
        "/api/v1/users/me",
        headers=headers,
        json={"name": "Updated Display Name"},
    )
    assert patch_res.status_code == status.HTTP_200_OK
    profile = patch_res.json()
    assert profile["name"] == "Updated Display Name"
    assert profile["email"] == "profile_test@example.com"

    # Verify GET /me returns updated name
    get_res = client.get("/api/v1/users/me", headers=headers)
    assert get_res.json()["name"] == "Updated Display Name"

    # 2. Attempt to modify email (crafted payload)
    crafted_res = client.patch(
        "/api/v1/users/me",
        headers=headers,
        json={"name": "Attacker Name", "email": "different_email@example.com"},
    )
    assert crafted_res.status_code == status.HTTP_200_OK
    crafted_profile = crafted_res.json()
    assert crafted_profile["name"] == "Attacker Name"
    assert crafted_profile["email"] == "profile_test@example.com"  # Email remains UNCHANGED!

    # 3. Validation rejection for invalid/empty name
    invalid_res = client.patch(
        "/api/v1/users/me",
        headers=headers,
        json={"name": "a"},  # min_length is 2
    )
    assert invalid_res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

import io
from datetime import datetime, timedelta, timezone
import pytest
from fastapi import status

from app.db import crud
from app.db.models import Share


def _register_and_login(client, name, email, password="CompliantP@ssw0rd1"):
    client.post(
        "/api/v1/auth/register",
        json={"name": name, "email": email, "password": password},
    )
    res = client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert res.status_code == status.HTTP_200_OK, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _future(hours=24):
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def _upload_pdf(client, headers, filename="confidential.pdf"):
    pdf_bytes = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"
    res = client.post(
        "/api/v1/upload",
        headers=headers,
        files={"file": (filename, io.BytesIO(pdf_bytes), "application/pdf")},
    )
    assert res.status_code == status.HTTP_201_CREATED, res.text
    return res.json()


def test_alice_shares_with_bob_access_while_active_then_revoked(client, db_session):
    """
    1. Alice shares a document with Bob; Bob can access it while active.
    2. Alice revokes Bob's access; Bob can no longer preview or download.
    3. Bob's previously generated sharing link no longer grants access.
    9. Recipient dashboard immediately updates to remove revoked share.
    """
    alice = _register_and_login(client, "Alice Owner", "alice.rev1@secureshare.io")
    bob = _register_and_login(client, "Bob Recipient", "bob.rev1@secureshare.io")

    # 1. Alice uploads and shares
    file_data = _upload_pdf(client, alice, "project_spec.pdf")
    share_res = client.post(
        "/api/v1/shares",
        headers=alice,
        json={
            "file_id": file_data["id"],
            "recipient_email": "bob.rev1@secureshare.io",
            "expires_at": _future(48),
            "max_downloads": 5,
        },
    )
    assert share_res.status_code == status.HTTP_201_CREATED
    share_id = share_res.json()["share_id"]
    token = share_res.json()["token"]

    # 2. Bob sees the document in his dashboard
    bob_dashboard = client.get("/api/v1/documents/shared-with-me", headers=bob).json()
    assert bob_dashboard["total"] == 1
    assert bob_dashboard["documents"][0]["file_name"] == "project_spec.pdf"
    assert bob_dashboard["documents"][0]["can_download"] is True

    # 3. Bob can download while active
    dl_res = client.post(
        f"/api/v1/documents/shared-with-me/{share_id}/download",
        headers=bob,
    )
    assert dl_res.status_code == status.HTTP_200_OK
    assert dl_res.json()["file_name"] == "project_spec.pdf"

    # 4. Alice revokes access using PATCH /api/v1/shares/{share_id}/revoke
    revoke_res = client.patch(f"/api/v1/shares/{share_id}/revoke", headers=alice)
    assert revoke_res.status_code == status.HTTP_200_OK
    rev_data = revoke_res.json()
    assert rev_data["status"] == "REVOKED"
    assert rev_data["revoked_at"] is not None

    # 5. Bob's dashboard immediately reflects revocation (disappears from active list)
    bob_dashboard_after = client.get("/api/v1/documents/shared-with-me", headers=bob).json()
    assert bob_dashboard_after["total"] == 0

    # 6. Direct share token link no longer grants access
    token_dl = client.post(
        "/api/v1/shares/download",
        headers=bob,
        json={"token": token},
    )
    assert token_dl.status_code == status.HTTP_404_NOT_FOUND

    # 7. Dashboard download endpoint blocked for revoked share
    dash_dl = client.post(
        f"/api/v1/documents/shared-with-me/{share_id}/download",
        headers=bob,
    )
    assert dash_dl.status_code == status.HTTP_404_NOT_FOUND


def test_charlie_cannot_revoke_alice_share(client):
    """
    4. Charlie cannot revoke Alice's share.
    """
    alice = _register_and_login(client, "Alice Owner", "alice.rev2@secureshare.io")
    bob = _register_and_login(client, "Bob Recipient", "bob.rev2@secureshare.io")
    charlie = _register_and_login(client, "Charlie Outsider", "charlie.rev2@secureshare.io")

    file_data = _upload_pdf(client, alice, "secret_notes.pdf")
    share_res = client.post(
        "/api/v1/shares",
        headers=alice,
        json={
            "file_id": file_data["id"],
            "recipient_email": "bob.rev2@secureshare.io",
            "expires_at": _future(24),
            "max_downloads": 2,
        },
    )
    share_id = share_res.json()["share_id"]

    # Charlie attempts to revoke Alice's share
    charlie_revoke = client.patch(f"/api/v1/shares/{share_id}/revoke", headers=charlie)
    assert charlie_revoke.status_code == status.HTTP_403_FORBIDDEN

    # POST attempt also rejected
    charlie_post = client.post(f"/api/v1/shares/{share_id}/revoke", headers=charlie)
    assert charlie_post.status_code == status.HTTP_403_FORBIDDEN


def test_bob_cannot_revoke_his_own_received_permission(client):
    """
    5. Bob cannot revoke his own received permission unless explicitly permitted.
    """
    alice = _register_and_login(client, "Alice Owner", "alice.rev3@secureshare.io")
    bob = _register_and_login(client, "Bob Recipient", "bob.rev3@secureshare.io")

    file_data = _upload_pdf(client, alice, "memo.pdf")
    share_res = client.post(
        "/api/v1/shares",
        headers=alice,
        json={
            "file_id": file_data["id"],
            "recipient_email": "bob.rev3@secureshare.io",
            "expires_at": _future(24),
            "max_downloads": 2,
        },
    )
    share_id = share_res.json()["share_id"]

    # Bob (recipient) attempts to call revoke
    bob_revoke = client.patch(f"/api/v1/shares/{share_id}/revoke", headers=bob)
    assert bob_revoke.status_code == status.HTTP_403_FORBIDDEN


def test_revoking_bob_does_not_affect_alice_ownership_or_charlie_permission(client):
    """
    6. Revoking Bob's access does not affect Alice's ownership or other recipients' permissions.
    """
    alice = _register_and_login(client, "Alice Owner", "alice.rev4@secureshare.io")
    bob = _register_and_login(client, "Bob Recipient", "bob.rev4@secureshare.io")
    charlie = _register_and_login(client, "Charlie Co-Recipient", "charlie.rev4@secureshare.io")

    file_data = _upload_pdf(client, alice, "multi_share.pdf")
    file_id = file_data["id"]

    # Alice shares with Bob
    share_bob = client.post(
        "/api/v1/shares",
        headers=alice,
        json={
            "file_id": file_id,
            "recipient_email": "bob.rev4@secureshare.io",
            "expires_at": _future(24),
            "max_downloads": 3,
        },
    ).json()

    # Alice shares with Charlie
    share_charlie = client.post(
        "/api/v1/shares",
        headers=alice,
        json={
            "file_id": file_id,
            "recipient_email": "charlie.rev4@secureshare.io",
            "expires_at": _future(24),
            "max_downloads": 3,
        },
    ).json()

    # Alice revokes Bob's share only
    revoke_bob = client.patch(f"/api/v1/shares/{share_bob['share_id']}/revoke", headers=alice)
    assert revoke_bob.status_code == status.HTTP_200_OK

    # 1. Alice's file ownership is completely unchanged
    alice_file = client.get(f"/api/v1/files/{file_id}", headers=alice)
    assert alice_file.status_code == status.HTTP_200_OK
    assert alice_file.json()["original_name"] == "multi_share.pdf"

    # 2. Bob's access is revoked
    bob_dash = client.get("/api/v1/documents/shared-with-me", headers=bob).json()
    assert bob_dash["total"] == 0

    # 3. Charlie's access remains ACTIVE and fully functional
    charlie_dash = client.get("/api/v1/documents/shared-with-me", headers=charlie).json()
    assert charlie_dash["total"] == 1
    assert charlie_dash["documents"][0]["file_name"] == "multi_share.pdf"

    charlie_dl = client.post(
        f"/api/v1/documents/shared-with-me/{share_charlie['share_id']}/download",
        headers=charlie,
    )
    assert charlie_dl.status_code == status.HTTP_200_OK


def test_repeated_revocation_safe_and_predictable(client):
    """
    Repeated revocation requests must return predictable 400 Bad Request.
    """
    alice = _register_and_login(client, "Alice Owner", "alice.rev5@secureshare.io")
    file_data = _upload_pdf(client, alice, "contract.pdf")

    share = client.post(
        "/api/v1/shares",
        headers=alice,
        json={
            "file_id": file_data["id"],
            "recipient_email": "someone@secureshare.io",
            "expires_at": _future(24),
            "max_downloads": 2,
        },
    ).json()

    # First revocation
    r1 = client.patch(f"/api/v1/shares/{share['share_id']}/revoke", headers=alice)
    assert r1.status_code == status.HTTP_200_OK

    # Second revocation attempt
    r2 = client.patch(f"/api/v1/shares/{share['share_id']}/revoke", headers=alice)
    assert r2.status_code == status.HTTP_400_BAD_REQUEST
    assert "already been revoked" in r2.text.lower()


def test_direct_api_and_stream_requests_cannot_bypass_revocation(client):
    """
    8. Direct API requests (including byte stream endpoints) cannot bypass revocation.
    """
    alice = _register_and_login(client, "Alice Owner", "alice.rev6@secureshare.io")
    bob = _register_and_login(client, "Bob Recipient", "bob.rev6@secureshare.io")

    file_data = _upload_pdf(client, alice, "confidential_patent.pdf")
    share = client.post(
        "/api/v1/shares",
        headers=alice,
        json={
            "file_id": file_data["id"],
            "recipient_email": "bob.rev6@secureshare.io",
            "expires_at": _future(24),
            "max_downloads": 2,
        },
    ).json()

    # Alice revokes Bob's share
    client.patch(f"/api/v1/shares/{share['share_id']}/revoke", headers=alice)

    # Direct stream download using blob_name
    stream_res = client.get(f"/api/v1/files/download/{file_data['blob_name']}", headers=bob)
    assert stream_res.status_code == status.HTTP_403_FORBIDDEN


def test_audit_log_records_revocation_event(client, db_session):
    """
    Revocation event must be securely recorded in the audit log with acting user and resource.
    """
    alice = _register_and_login(client, "Alice Owner", "alice.rev7@secureshare.io")
    file_data = _upload_pdf(client, alice, "audited_file.pdf")

    share = client.post(
        "/api/v1/shares",
        headers=alice,
        json={
            "file_id": file_data["id"],
            "recipient_email": "audited_recip@secureshare.io",
            "expires_at": _future(24),
            "max_downloads": 1,
        },
    ).json()

    # Revoke share
    client.patch(f"/api/v1/shares/{share['share_id']}/revoke", headers=alice)

    # Check Alice's audit logs
    audit_res = client.get("/api/v1/users/me/audit-logs", headers=alice)
    assert audit_res.status_code == status.HTTP_200_OK
    logs = audit_res.json()
    revoke_logs = [log for log in logs if log["action"] == "SHARE_REVOKED"]
    assert len(revoke_logs) >= 1
    entry = revoke_logs[0]
    assert entry["status"] == "SUCCESS"
    assert share["share_id"] in entry["details"]
    # Verify no raw token is leaked in audit details
    assert share["token"] not in entry["details"]

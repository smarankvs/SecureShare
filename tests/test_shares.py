"""Sharing policy, revocation and download-gatekeeper tests (Member 2 module)."""
import hashlib
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import status

from app.db import crud
from app.db.models import Share


def register_and_login(client, name, email, password="CompliantP@ssw0rd1"):
    client.post(
        "/api/v1/auth/register",
        json={"name": name, "email": email, "password": password},
    )
    res = client.post(
        "/api/v1/auth/login", json={"email": email, "password": password}
    )
    assert res.status_code == status.HTTP_200_OK, res.text
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


@pytest.fixture
def owner(client):
    return register_and_login(client, "Alice Owner", "alice.owner@secureshare.io")


@pytest.fixture
def recipient(client):
    return register_and_login(client, "Bob Recipient", "bob.recipient@secureshare.io")


@pytest.fixture
def outsider(client):
    return register_and_login(client, "Eve Outsider", "eve.outsider@secureshare.io")


@pytest.fixture
def owned_file(db_session, client, owner):
    """Insert a file record directly, bypassing the upload pipeline."""
    owner_id = db_session.query(crud.User).filter_by(email="alice.owner@secureshare.io").one().id
    return crud.create_file_record(
        db=db_session,
        blob_name="11111111-1111-1111-1111-111111111111.pdf",
        original_name="thesis.pdf",
        blob_url="/local/thesis.pdf",
        owner_id=owner_id,
        content_type="application/pdf",
        size=1024,
        sha256_hash="a" * 64,
    )


def _future(minutes=60):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def _create_share(client, headers, file_id, email, max_downloads=2, expires_at=None):
    return client.post(
        "/api/v1/shares",
        headers=headers,
        json={
            "file_id": file_id,
            "recipient_email": email,
            "expires_at": expires_at or _future(),
            "max_downloads": max_downloads,
        },
    )


# ---------------------------------------------------------------------------
# Creation
# ---------------------------------------------------------------------------
def test_create_share_returns_raw_token_once_and_stores_only_hash(
    client, db_session, owner, owned_file
):
    res = _create_share(
        client, owner, owned_file.id, "bob.recipient@secureshare.io", max_downloads=3
    )
    assert res.status_code == status.HTTP_201_CREATED, res.text
    body = res.json()

    token = body["token"]
    assert len(token) >= 32
    assert body["token_prefix"] == token[:8]
    assert body["status"] == "ACTIVE"
    assert body["max_downloads"] == 3
    assert body["share_url"].endswith(token)

    share = db_session.query(Share).filter_by(id=body["share_id"]).one()
    assert share.token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert share.token_hash != token


def test_non_owner_cannot_create_share(client, outsider, owned_file):
    res = _create_share(
        client, outsider, owned_file.id, "bob.recipient@secureshare.io"
    )
    assert res.status_code == status.HTTP_403_FORBIDDEN
    assert res.json()["error"]["code"] == "FORBIDDEN"


def test_share_creation_rejects_past_expiry_and_excess_quota(
    client, owner, owned_file
):
    past = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    assert _create_share(
        client, owner, owned_file.id, "bob.recipient@secureshare.io", expires_at=past
    ).status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    assert _create_share(
        client, owner, owned_file.id, "bob.recipient@secureshare.io", max_downloads=10000
    ).status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


def test_list_shares_never_exposes_token(client, owner, owned_file):
    _create_share(client, owner, owned_file.id, "bob.recipient@secureshare.io", max_downloads=1)
    res = client.get("/api/v1/shares", headers=owner)
    assert res.status_code == status.HTTP_200_OK
    body = res.json()
    assert body["total"] == 1
    assert "token" not in body["shares"][0]
    assert body["shares"][0]["token_prefix"]


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------
def test_revoke_share_blocks_download_immediately(
    client, owner, recipient, owned_file
):
    created = _create_share(
        client, owner, owned_file.id, "bob.recipient@secureshare.io", max_downloads=5
    ).json()

    revoke = client.post(
        f"/api/v1/shares/{created['share_id']}/revoke", headers=owner
    )
    assert revoke.status_code == status.HTTP_200_OK, revoke.text
    assert revoke.json()["status"] == "REVOKED"
    assert revoke.json()["revoked_at"] is not None

    download = client.post(
        "/api/v1/shares/download", headers=recipient, json={"token": created["token"]}
    )
    assert download.status_code == status.HTTP_404_NOT_FOUND


def test_non_owner_cannot_revoke(client, owner, outsider, owned_file):
    created = _create_share(
        client, owner, owned_file.id, "bob.recipient@secureshare.io"
    ).json()
    res = client.post(
        f"/api/v1/shares/{created['share_id']}/revoke", headers=outsider
    )
    assert res.status_code == status.HTTP_403_FORBIDDEN


def test_double_revoke_rejected(client, owner, owned_file):
    created = _create_share(
        client, owner, owned_file.id, "bob.recipient@secureshare.io"
    ).json()
    url = f"/api/v1/shares/{created['share_id']}/revoke"
    assert client.post(url, headers=owner).status_code == status.HTTP_200_OK
    assert client.post(url, headers=owner).status_code == status.HTTP_400_BAD_REQUEST


# ---------------------------------------------------------------------------
# Download gatekeeper
# ---------------------------------------------------------------------------
def test_recipient_download_succeeds_and_decrements_quota(
    client, db_session, owner, recipient, owned_file
):
    created = _create_share(
        client, owner, owned_file.id, "bob.recipient@secureshare.io", max_downloads=2
    ).json()

    res = client.post(
        "/api/v1/shares/download", headers=recipient, json={"token": created["token"]}
    )
    assert res.status_code == status.HTTP_200_OK, res.text
    body = res.json()
    assert body["file_name"] == "thesis.pdf"
    assert body["remaining_downloads"] == 1
    assert body["download_url"]

    share = db_session.query(Share).filter_by(id=created["share_id"]).one()
    assert share.download_count == 1
    assert share.recipient_user_id is not None
    assert share.last_downloaded_at is not None


def test_third_party_recipient_spoofing_is_blocked(
    client, owner, outsider, owned_file
):
    created = _create_share(
        client, owner, owned_file.id, "bob.recipient@secureshare.io"
    ).json()
    res = client.post(
        "/api/v1/shares/download", headers=outsider, json={"token": created["token"]}
    )
    assert res.status_code == status.HTTP_404_NOT_FOUND


def test_quota_cannot_be_exceeded(client, owner, recipient, owned_file):
    created = _create_share(
        client, owner, owned_file.id, "bob.recipient@secureshare.io", max_downloads=1
    ).json()

    first = client.post(
        "/api/v1/shares/download", headers=recipient, json={"token": created["token"]}
    )
    assert first.status_code == status.HTTP_200_OK

    for _ in range(3):
        blocked = client.post(
            "/api/v1/shares/download",
            headers=recipient,
            json={"token": created["token"]},
        )
        assert blocked.status_code == status.HTTP_404_NOT_FOUND

    listing = client.get("/api/v1/shares", headers=owner).json()
    assert listing["shares"][0]["download_count"] == 1


def test_expired_share_is_rejected(client, db_session, owner, recipient, owned_file):
    created = _create_share(
        client, owner, owned_file.id, "bob.recipient@secureshare.io", max_downloads=5
    ).json()

    share = db_session.query(Share).filter_by(id=created["share_id"]).one()
    share.expires_at = datetime.now(timezone.utc) - timedelta(seconds=5)
    db_session.commit()

    res = client.post(
        "/api/v1/shares/download", headers=recipient, json={"token": created["token"]}
    )
    assert res.status_code == status.HTTP_404_NOT_FOUND


def test_unknown_token_is_rejected_uniformly(client, recipient):
    res = client.post(
        "/api/v1/shares/download",
        headers=recipient,
        json={"token": "x" * 43},
    )
    assert res.status_code == status.HTTP_404_NOT_FOUND
    # Same message as revoked/expired/mismatch: no token-existence oracle.
    assert "invalid" in res.json()["error"]["message"].lower()


def test_download_requires_authentication(client, owner, owned_file):
    created = _create_share(
        client, owner, owned_file.id, "bob.recipient@secureshare.io"
    ).json()
    res = client.post(
        "/api/v1/shares/download", json={"token": created["token"]}
    )
    assert res.status_code == status.HTTP_401_UNAUTHORIZED


def test_audit_trail_records_denied_attempt(client, owner, outsider, owned_file):
    created = _create_share(
        client, owner, owned_file.id, "bob.recipient@secureshare.io"
    ).json()
    client.post(
        "/api/v1/shares/download", headers=outsider, json={"token": created["token"]}
    )
    logs = client.get("/api/v1/users/me/audit-logs", headers=outsider).json()
    actions = {entry["action"] for entry in logs}
    assert "SHARE_DOWNLOAD_DENIED" in actions

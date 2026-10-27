from sqlalchemy import select

from app.db.models import AccessEvent, AccessEventType, Document, ScanStatus, User
from app.services import encryption
from app.services.key_wrapping import get_key_wrap_client
from tests.test_file_inspection import EXE, PNG, make_docx

URL = "/api/v1/documents/upload"


def _upload(client, headers, data, name="report.png", ctype="image/png"):
    return client.post(URL, headers=headers, files={"file": (name, data, ctype)})


def _events(db):
    return [e.event_type for e in db.scalars(select(AccessEvent)).all()]


def test_requires_authentication(client):
    assert _upload(client, {}, PNG).status_code == 401


def test_clean_upload_is_encrypted_and_stored(client, auth_headers, scanner, storage, db, quarantine_dir):
    r = _upload(client, auth_headers, PNG, name="../../etc/holiday.png")
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["scan_status"] == "CLEAN"
    assert body["mime_type"] == "image/png"
    assert body["original_filename"] == "holiday.png"  # path components stripped

    doc = db.get(Document, __import__("uuid").UUID(body["id"]))
    assert doc.scan_status == ScanStatus.CLEAN
    assert len(doc.blob_name) == 32 and "holiday" not in doc.blob_name

    # The scanner saw the plaintext, storage only ever saw ciphertext.
    assert scanner.scanned == [PNG]
    ciphertext, metadata = storage.blobs[doc.blob_name]
    assert PNG not in ciphertext
    assert metadata["ss_enc_alg"] == "AES-256-GCM"
    assert encryption.decrypt(ciphertext, metadata, doc.blob_name.encode(), get_key_wrap_client()) == PNG

    user = db.scalar(select(User))
    assert user.email == "alice@example.edu"
    assert _events(db) == [AccessEventType.UPLOAD]
    assert list(quarantine_dir.iterdir()) == []  # ephemeral


def test_extension_is_ignored_magic_bytes_decide(client, auth_headers, storage):
    r = _upload(client, auth_headers, EXE, name="invoice.pdf", ctype="application/pdf")
    assert r.status_code == 415
    assert storage.blobs == {}


def test_docx_upload(client, auth_headers):
    r = _upload(client, auth_headers, make_docx(), name="essay.docx", ctype="application/octet-stream")
    assert r.status_code == 201, r.text
    assert r.json()["mime_type"].endswith("wordprocessingml.document")


def test_infected_file_purged_and_flagged(client, auth_headers, scanner, storage, db, quarantine_dir, monkeypatch):
    alerts = []
    monkeypatch.setattr("app.api.v1.documents.trigger_security_alert", lambda *a, **k: alerts.append((a, k)))
    scanner.mode = "infected"

    r = _upload(client, auth_headers, PNG)
    assert r.status_code == 400
    assert "malware" in r.json()["detail"].lower()

    doc = db.scalar(select(Document))
    assert doc.scan_status == ScanStatus.INFECTED
    assert storage.blobs == {}
    assert list(quarantine_dir.iterdir()) == []
    assert alerts and alerts[0][1]["signature"] == "Eicar-Test-Signature"
    assert AccessEventType.MALWARE_DETECTED in _events(db)


def test_scanner_unavailable_fails_closed(client, auth_headers, scanner, storage, db, quarantine_dir):
    scanner.mode = "down"
    r = _upload(client, auth_headers, PNG)
    assert r.status_code == 503
    assert db.scalar(select(Document)).scan_status == ScanStatus.ERROR
    assert storage.blobs == {}
    assert list(quarantine_dir.iterdir()) == []


def test_storage_failure_does_not_persist_document(client, auth_headers, storage, db):
    storage.fail = True
    r = _upload(client, auth_headers, PNG)
    assert r.status_code == 502
    assert db.scalar(select(Document)) is None


def test_oversized_upload_rejected_immediately(client, auth_headers, scanner):
    big = PNG + b"\x00" * (25 * 1024 * 1024)
    r = _upload(client, auth_headers, big)
    assert r.status_code == 413
    assert scanner.scanned == []


def test_far_oversized_body_rejected_by_middleware_before_parsing(client, auth_headers, scanner, db):
    r = _upload(client, auth_headers, PNG + b"\x00" * (26 * 1024 * 1024))
    assert r.status_code == 413
    assert scanner.scanned == []
    # Rejected before the route ran: no user was provisioned, no event logged.
    assert db.scalar(select(User)) is None
    assert _events(db) == []



def test_just_over_limit_rejected_by_stream_check(client, auth_headers, scanner, quarantine_dir):
    # Body fits within the multipart overhead allowance, file itself is 25 MB + 1 byte.
    data = PNG + b"\x00" * (25 * 1024 * 1024 + 1 - len(PNG))
    r = _upload(client, auth_headers, data)
    assert r.status_code == 413
    assert scanner.scanned == []
    assert list(quarantine_dir.iterdir()) == []


def test_exactly_at_limit_accepted(client, auth_headers):
    data = PNG + b"\x00" * (25 * 1024 * 1024 - len(PNG))
    assert _upload(client, auth_headers, data).status_code == 201

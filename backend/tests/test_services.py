import base64
import os
import socket
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlparse

import pytest
from azure.storage.blob import UserDelegationKey
from cryptography.exceptions import InvalidTag

from app.services import encryption
from app.services.antivirus import ClamAVScanner, ScannerUnavailableError, Verdict
from app.services.blob_storage import BlobStorageService, StorageConfigurationError
from app.services.key_wrapping import LocalDevKeyWrapClient

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


# ── Envelope encryption ────────────────────────────────────────────────────
def test_envelope_roundtrip_and_aad_binding():
    kw = LocalDevKeyWrapClient(os.urandom(32))
    p = encryption.encrypt(b"secret doc", aad=b"blob-a", key_wrapper=kw)
    md = p.to_metadata()
    assert len(p.nonce) == 12 and p.ciphertext != b"secret doc"
    assert encryption.decrypt(p.ciphertext, md, b"blob-a", kw) == b"secret doc"
    with pytest.raises(InvalidTag):
        encryption.decrypt(p.ciphertext, md, b"blob-b", kw)


def test_each_file_gets_a_fresh_dek():
    kw = LocalDevKeyWrapClient(os.urandom(32))
    a = encryption.encrypt(b"x", b"n", kw)
    b = encryption.encrypt(b"x", b"n", kw)
    assert a.wrapped_key.encrypted_key != b.wrapped_key.encrypted_key


# ── Blob storage / SAS ─────────────────────────────────────────────────────
def _fake_udk() -> UserDelegationKey:
    k = UserDelegationKey()
    k.signed_oid = "00000000-0000-0000-0000-000000000001"
    k.signed_tid = "00000000-0000-0000-0000-000000000002"
    k.signed_start = "2026-01-01T00:00:00Z"
    k.signed_expiry = "2026-12-31T00:00:00Z"
    k.signed_service = "b"
    k.signed_version = "2023-11-03"
    k.value = base64.b64encode(os.urandom(32)).decode()
    return k


def _service(public_access=None):
    svc = MagicMock()
    svc.account_name = "ssaccount"
    svc.url = "https://ssaccount.blob.core.windows.net/"
    svc.get_user_delegation_key.return_value = _fake_udk()
    svc.get_container_client.return_value.get_container_properties.return_value.public_access = public_access
    return svc


def test_sas_is_single_blob_read_only_120s():
    svc = _service()
    storage = BlobStorageService(container_name="docs", service_client=svc)
    before = datetime.now(timezone.utc)
    url = storage.generate_download_sas("abc123")
    u = urlparse(url)
    q = {k: v[0] for k, v in parse_qs(u.query).items()}

    assert u.scheme == "https" and u.path == "/docs/abc123"
    assert q["sr"] == "b"          # single blob
    assert q["sp"] == "r"          # read only
    assert q["spr"] == "https"
    assert "skoid" in q            # user delegation SAS (signed with Entra key)
    assert "st" not in q
    expiry = datetime.fromisoformat(q["se"].replace("Z", "+00:00"))
    assert timedelta(seconds=118) <= expiry - before <= timedelta(seconds=121)


def test_user_delegation_key_is_cached():
    svc = _service()
    storage = BlobStorageService(container_name="docs", service_client=svc)
    storage.generate_download_sas("a")
    storage.generate_download_sas("b")
    assert svc.get_user_delegation_key.call_count == 1


@pytest.mark.parametrize("bad", ["", "../x", "a/b"])
def test_sas_rejects_bad_blob_names(bad):
    storage = BlobStorageService(container_name="docs", service_client=_service())
    with pytest.raises(ValueError):
        storage.generate_download_sas(bad)


def test_container_created_private_and_public_rejected():
    svc = _service()
    BlobStorageService(container_name="docs", service_client=svc).ensure_private_container()
    svc.get_container_client.return_value.create_container.assert_called_once_with(public_access=None)

    with pytest.raises(StorageConfigurationError):
        BlobStorageService(container_name="docs", service_client=_service("blob")).ensure_private_container()


# ── ClamAV ─────────────────────────────────────────────────────────────────
def _scanner_with(monkeypatch, result=None, exc=None):
    cd = MagicMock()
    cd.ping.return_value = True
    if exc:
        cd.scan_stream.side_effect = exc
    else:
        cd.scan_stream.return_value = result
    monkeypatch.setattr("app.services.antivirus.pyclamd.ClamdNetworkSocket", lambda **kw: cd)
    return ClamAVScanner()


def test_clamav_clean(monkeypatch):
    assert _scanner_with(monkeypatch, None).scan_stream(b"ok").verdict is Verdict.CLEAN


def test_clamav_infected(monkeypatch):
    r = _scanner_with(monkeypatch, {"stream": ("FOUND", "Eicar-Test-Signature")}).scan_stream(EICAR)
    assert r.verdict is Verdict.INFECTED and r.signature == "Eicar-Test-Signature"


def test_clamav_error_verdict_fails_closed(monkeypatch):
    with pytest.raises(ScannerUnavailableError):
        _scanner_with(monkeypatch, {"stream": ("ERROR", "boom")}).scan_stream(b"x")


def test_clamav_unreachable_fails_closed(monkeypatch):
    def boom(**kw):
        raise ConnectionError("refused")
    monkeypatch.setattr("app.services.antivirus.pyclamd.ClamdNetworkSocket", boom)
    with pytest.raises(ScannerUnavailableError):
        ClamAVScanner().scan_stream(b"x")


def _clamd_up() -> bool:
    try:
        socket.create_connection(("localhost", 3310), timeout=0.5).close()
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _clamd_up(), reason="clamd not running on localhost:3310")
def test_live_clamd_detects_eicar():
    import io
    assert ClamAVScanner(host="localhost").scan_stream(io.BytesIO(EICAR)).verdict is Verdict.INFECTED

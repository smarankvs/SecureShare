import base64
import os
import sys
import tempfile
from pathlib import Path

# Configure the environment BEFORE importing the application.
_TMP = Path(tempfile.mkdtemp(prefix="secureshare-tests-"))
os.environ.setdefault("ENVIRONMENT", "test")
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", f"sqlite:///{_TMP / 'test.db'}")
os.environ["QUARANTINE_DIR"] = str(_TMP / "quarantine")
os.environ["LOCAL_DEV_KEK_B64"] = base64.b64encode(os.urandom(32)).decode()
os.environ.pop("AZURE_KEYVAULT_KEK_ID", None)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.db.models import Base  # noqa: E402
from app.db.session import SessionLocal, engine  # noqa: E402
from app.services.antivirus import ScanResult, ScannerUnavailableError, Verdict, get_scanner  # noqa: E402
from app.services.blob_storage import get_blob_storage  # noqa: E402
from main import app  # noqa: E402


class FakeScanner:
    def __init__(self):
        self.mode = "clean"
        self.scanned: list[bytes] = []

    def scan_stream(self, stream):
        self.scanned.append(stream.read())
        if self.mode == "infected":
            return ScanResult(Verdict.INFECTED, "Eicar-Test-Signature")
        if self.mode == "down":
            raise ScannerUnavailableError("clamd unreachable")
        return ScanResult(Verdict.CLEAN)


class FakeStorage:
    def __init__(self):
        self.blobs: dict[str, tuple[bytes, dict]] = {}
        self.fail = False

    def upload_encrypted(self, blob_name, payload):
        if self.fail:
            raise RuntimeError("storage down")
        self.blobs[blob_name] = (payload.ciphertext, payload.to_metadata())

    def delete_blob(self, blob_name):
        self.blobs.pop(blob_name, None)


@pytest.fixture(autouse=True)
def _db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield


@pytest.fixture
def db():
    s = SessionLocal()
    yield s
    s.close()


@pytest.fixture
def scanner():
    return FakeScanner()


@pytest.fixture
def storage():
    return FakeStorage()


@pytest.fixture
def client(scanner, storage):
    app.dependency_overrides[get_scanner] = lambda: scanner
    app.dependency_overrides[get_blob_storage] = lambda: storage
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def auth_headers():
    return {"X-Dev-Entra-OID": "11111111-2222-3333-4444-555555555555", "X-Dev-Email": "Alice@Example.edu"}


@pytest.fixture
def quarantine_dir() -> Path:
    return settings.QUARANTINE_DIR

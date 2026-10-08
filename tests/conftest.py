import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Set test environment flags
os.environ["ENVIRONMENT"] = "test"
os.environ["SECRET_KEY"] = "super-secret-test-key-32-chars-long-minimum-jwt!"
os.environ["AZURE_KEYVAULT_ENABLED"] = "false"
os.environ["AZURE_STORAGE_USE_LOCAL_FALLBACK"] = "true"

from app.main import app
from app.core.config import settings
from app.db.database import Base, get_db
from app.db.models import User, FileRecord, AuditLog

# In-memory SQLite engine for fast, isolated test runs
TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session():
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def test_user_headers(client):
    """Register and log in a fixture user to obtain valid authorization headers."""
    reg_payload = {
        "name": "Security Tester",
        "email": "tester@example.com",
        "password": "SecurePassword123!"
    }
    client.post("/api/v1/auth/register", json=reg_payload)

    login_res = client.post("/api/v1/auth/login", json={
        "email": "tester@example.com",
        "password": "SecurePassword123!"
    })
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

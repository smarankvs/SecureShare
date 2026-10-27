"""
Centralised application settings (Member 3 module: DB, storage, file inspection).

All values are read from environment variables (or a local ``.env`` file).
Secrets such as DB passwords should be injected at runtime (e.g. from Azure
Key Vault by Member 4's module) and never committed.
"""
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── General ────────────────────────────────────────────────────────────
    ENVIRONMENT: Literal["development", "test", "production"] = "development"
    API_V1_PREFIX: str = "/api/v1"

    # ── PostgreSQL ─────────────────────────────────────────────────────────
    # e.g. postgresql+psycopg://secureshare:secret@localhost:5432/secureshare
    DATABASE_URL: str = "postgresql+psycopg://secureshare:secureshare@localhost:5432/secureshare"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20

    # ── Upload / inspection ────────────────────────────────────────────────
    MAX_UPLOAD_BYTES: int = 25 * 1024 * 1024  # 25 MB hard limit
    # Allowance for multipart boundaries/headers when pre-checking Content-Length.
    MULTIPART_OVERHEAD_BYTES: int = 64 * 1024
    # Bytes fed to libmagic for content sniffing (OOXML needs more than 2 KB).
    MAGIC_SNIFF_BYTES: int = 256 * 1024
    UPLOAD_CHUNK_BYTES: int = 1024 * 1024
    QUARANTINE_DIR: Path = Path("/tmp/secureshare-quarantine")

    # ── ClamAV (clamd) ─────────────────────────────────────────────────────
    CLAMAV_HOST: str = "localhost"
    CLAMAV_PORT: int = 3310
    CLAMAV_TIMEOUT_SECONDS: float = 30.0

    # ── Security alerting ──────────────────────────────────────────────────
    # Optional webhook (Teams / Slack / Logic App / Sentinel ingestion endpoint).
    SECURITY_ALERT_WEBHOOK_URL: str | None = None

    # ── Azure Blob Storage ─────────────────────────────────────────────────
    # e.g. https://<account>.blob.core.windows.net
    AZURE_STORAGE_ACCOUNT_URL: str | None = None
    AZURE_STORAGE_CONTAINER: str = "secureshare-documents"
    # Client ID of a user-assigned Managed Identity (omit for system-assigned).
    AZURE_MANAGED_IDENTITY_CLIENT_ID: str | None = None

    # ── SAS ────────────────────────────────────────────────────────────────
    SAS_TTL_SECONDS: int = Field(default=120, ge=1, le=120)
    # User delegation key lifetime (cached & reused across SAS generations).
    USER_DELEGATION_KEY_TTL_SECONDS: int = 3600

    # ── Envelope encryption / key wrapping (Member 4 integration) ─────────
    # Full key identifier of the KEK in Azure Key Vault, e.g.
    # https://<vault>.vault.azure.net/keys/secureshare-kek/<version>
    AZURE_KEYVAULT_KEK_ID: str | None = None
    # Development-only local KEK (base64, 32 bytes). Rejected in production.
    LOCAL_DEV_KEK_B64: str | None = None

    @field_validator("QUARANTINE_DIR", mode="before")
    @classmethod
    def _expand(cls, v):
        return Path(v).expanduser()

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

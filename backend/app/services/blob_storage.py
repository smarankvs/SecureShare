"""
Azure Blob Storage — private container + short-lived User Delegation SAS.

* Auth: Managed Identity (Entra ID). No account keys / connection strings,
  so only User Delegation SAS (signed by an Entra-issued key) can be minted.
* Container public access level is enforced as **Private** (``None``): the
  container is created private and startup fails if it has been made public.
* SAS tokens: single-blob scope, read-only, HTTPS-only, 120-second lifetime.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.storage.blob import (
    BlobSasPermissions,
    BlobServiceClient,
    ContainerClient,
    ContentSettings,
    UserDelegationKey,
    generate_blob_sas,
)

from app.core.config import settings
from app.services.azure_identity import get_azure_credential
from app.services.encryption import EncryptedPayload

logger = logging.getLogger("secureshare.blob")


class StorageConfigurationError(RuntimeError):
    pass


class BlobStorageService:
    def __init__(
        self,
        account_url: str | None = None,
        container_name: str | None = None,
        credential=None,
        service_client: BlobServiceClient | None = None,
    ):
        self.container_name = container_name or settings.AZURE_STORAGE_CONTAINER
        if service_client is None:
            account_url = account_url or settings.AZURE_STORAGE_ACCOUNT_URL
            if not account_url:
                raise StorageConfigurationError("AZURE_STORAGE_ACCOUNT_URL is not configured")
            service_client = BlobServiceClient(account_url, credential=credential or get_azure_credential())
        self._service = service_client
        self._container: ContainerClient = service_client.get_container_client(self.container_name)
        self._udk: UserDelegationKey | None = None
        self._udk_expiry: datetime | None = None
        self._udk_lock = threading.Lock()

    @property
    def account_name(self) -> str:
        return self._service.account_name

    # ── Container ──────────────────────────────────────────────────────────
    def ensure_private_container(self) -> None:
        """Create the container as Private, or verify an existing one is Private."""
        try:
            self._container.create_container(public_access=None)
            logger.info("Created private container '%s'", self.container_name)
        except ResourceExistsError:
            pass
        props = self._container.get_container_properties()
        if props.public_access is not None:
            raise StorageConfigurationError(
                f"Container '{self.container_name}' has public access '{props.public_access}'; "
                "it must be Private"
            )

    # ── Blobs ──────────────────────────────────────────────────────────────
    def upload_encrypted(self, blob_name: str, payload: EncryptedPayload) -> None:
        self._container.upload_blob(
            name=blob_name,
            data=payload.ciphertext,
            overwrite=False,  # UUID names must never collide/overwrite
            metadata=payload.to_metadata(),
            content_settings=ContentSettings(content_type="application/octet-stream"),
        )

    def download_encrypted(self, blob_name: str) -> tuple[bytes, dict[str, str]]:
        downloader = self._container.download_blob(blob_name)
        return downloader.readall(), dict(downloader.properties.metadata or {})

    def delete_blob(self, blob_name: str) -> None:
        try:
            self._container.delete_blob(blob_name, delete_snapshots="include")
        except ResourceNotFoundError:
            pass

    # ── User Delegation SAS ────────────────────────────────────────────────
    def _get_user_delegation_key(self, now: datetime) -> UserDelegationKey:
        with self._udk_lock:
            # Reuse the key while it remains valid well beyond the SAS lifetime.
            margin = timedelta(seconds=settings.SAS_TTL_SECONDS + 300)
            if self._udk is None or self._udk_expiry is None or now + margin >= self._udk_expiry:
                start = now - timedelta(minutes=5)  # tolerate clock skew for the key itself
                expiry = now + timedelta(seconds=settings.USER_DELEGATION_KEY_TTL_SECONDS)
                self._udk = self._service.get_user_delegation_key(key_start_time=start, key_expiry_time=expiry)
                self._udk_expiry = expiry
            return self._udk

    def generate_download_sas(self, blob_name: str) -> str:
        """
        Return a SAS URL for exactly one blob: read-only, HTTPS-only,
        valid for ``SAS_TTL_SECONDS`` (120 s) from issuance.
        """
        if not blob_name or "/" in blob_name or ".." in blob_name:
            raise ValueError("Invalid blob name")
        now = datetime.now(timezone.utc)
        udk = self._get_user_delegation_key(now)
        expiry = now + timedelta(seconds=settings.SAS_TTL_SECONDS)
        token = generate_blob_sas(
            account_name=self.account_name,
            container_name=self.container_name,
            blob_name=blob_name,           # sr=b → single blob scope
            user_delegation_key=udk,
            permission=BlobSasPermissions(read=True),  # sp=r only
            expiry=expiry,                 # se = now + 120 s (no start → valid from issuance)
            protocol="https",
        )
        return f"{self._service.url.rstrip('/')}/{self.container_name}/{blob_name}?{token}"


_storage: BlobStorageService | None = None


def get_blob_storage() -> BlobStorageService:
    """FastAPI dependency (override in tests)."""
    global _storage
    if _storage is None:
        _storage = BlobStorageService()
    return _storage


def generate_download_sas(blob_name: str) -> str:
    """Module-level service function: short-lived read-only SAS for one blob."""
    return get_blob_storage().generate_download_sas(blob_name)

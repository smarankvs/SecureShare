import json
import logging
import os
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

from app.core.config import settings

logger = logging.getLogger("secureshare.blob")

try:
    from azure.storage.blob import (
        BlobServiceClient,
        BlobSasPermissions,
        ContentSettings,
        generate_blob_sas,
    )
    AZURE_STORAGE_SDK_AVAILABLE = True
except ImportError:
    AZURE_STORAGE_SDK_AVAILABLE = False
    logger.warning("Azure Storage SDK is not installed.")


class AzureBlobService:
    """
    Azure Blob Storage service managing private secure container file operations.
    Follows Azure Security Best Practices:
    - Container access type is strictly PRIVATE.
    - Blobs are identified only by random UUIDs.
    - Files are accessed via short-lived time-restricted Shared Access Signatures (SAS).
    - Stores metadata: original_filename, uploaded_by, upload_time.
    - Seamlessly falls back to local storage sandbox if Azure credentials are not yet configured.
    """

    def __init__(self):
        self.container_name = settings.AZURE_STORAGE_CONTAINER_NAME
        self.blob_service_client: Optional["BlobServiceClient"] = None
        self.use_local_fallback = False
        self._initialize_storage()

    def _initialize_storage(self) -> None:
        """Initialize Azure Blob Storage Client or setup local storage fallback."""
        if AZURE_STORAGE_SDK_AVAILABLE:
            try:
                # 1. Connect via Storage Connection String
                if settings.AZURE_STORAGE_CONNECTION_STRING and not settings.AZURE_STORAGE_CONNECTION_STRING.startswith("dummy"):
                    self.blob_service_client = BlobServiceClient.from_connection_string(
                        settings.AZURE_STORAGE_CONNECTION_STRING
                    )
                # 2. Connect via Storage Account Name + Azure Identity (DefaultAzureCredential)
                elif settings.AZURE_STORAGE_ACCOUNT_NAME and not settings.AZURE_STORAGE_ACCOUNT_NAME.startswith("dummy"):
                    from azure.identity import DefaultAzureCredential
                    account_url = f"https://{settings.AZURE_STORAGE_ACCOUNT_NAME}.blob.core.windows.net"
                    self.blob_service_client = BlobServiceClient(
                        account_url=account_url,
                        credential=DefaultAzureCredential()
                    )

                if self.blob_service_client:
                    # Ensure private container exists
                    container_client = self.blob_service_client.get_container_client(self.container_name)
                    if not container_client.exists():
                        logger.info(f"Creating private Azure container: '{self.container_name}'")
                        # None = private container (no anonymous public read)
                        self.blob_service_client.create_container(self.container_name, public_access=None)
                    logger.info(f"Connected to Azure Blob Storage container '{self.container_name}'.")
                    return
            except Exception as exc:
                logger.warning(
                    f"Azure Blob Storage connection failed: {exc}. "
                    f"Falling back to local secure storage fallback."
                )

        # Fallback to local storage
        self.use_local_fallback = True
        self.local_dir = os.path.join(settings.LOCAL_STORAGE_DIR, self.container_name)
        os.makedirs(self.local_dir, exist_ok=True)
        logger.info(f"Initialized local storage sandbox at '{self.local_dir}'.")

    def upload_file(
        self,
        file_content: bytes,
        blob_name: str,
        content_type: str,
        metadata: Dict[str, str],
    ) -> str:
        """
        Upload file content to private container.
        Stores metadata: original_filename, uploaded_by, upload_time.
        Returns the canonical blob URL.
        """
        # Azure metadata requires ASCII-safe values
        sanitized_metadata = {
            k: urllib.parse.quote(str(v), safe="") for k, v in metadata.items()
        }

        if not self.use_local_fallback and self.blob_service_client:
            try:
                blob_client = self.blob_service_client.get_blob_client(
                    container=self.container_name,
                    blob=blob_name,
                )
                blob_client.upload_blob(
                    data=file_content,
                    overwrite=True,
                    content_settings=ContentSettings(content_type=content_type),
                    metadata=sanitized_metadata,
                )
                logger.info(f"Successfully uploaded blob '{blob_name}' to Azure container '{self.container_name}'.")
                return blob_client.url
            except Exception as exc:
                logger.error(f"Error uploading blob to Azure: {exc}")
                raise

        # Local storage fallback
        file_path = os.path.join(self.local_dir, blob_name)
        meta_path = f"{file_path}.meta.json"

        with open(file_path, "wb") as f:
            f.write(file_content)

        meta_payload = {
            "content_type": content_type,
            "metadata": metadata,
        }
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(meta_payload, f, indent=2)

        return f"/api/v1/files/download/{blob_name}"

    def generate_download_url(self, blob_name: str, expiry_minutes: int = 15) -> str:
        """
        Generate a secure short-lived SAS download URL for private blobs.
        If using local fallback, returns internal secure download endpoint.
        """
        if not self.use_local_fallback and self.blob_service_client:
            try:
                # Generate user-delegation or account SAS
                account_name = self.blob_service_client.account_name
                account_key = self.blob_service_client.credential.account_key
                expiry_time = datetime.now(timezone.utc) + timedelta(minutes=expiry_minutes)

                sas_token = generate_blob_sas(
                    account_name=account_name,
                    container_name=self.container_name,
                    blob_name=blob_name,
                    account_key=account_key,
                    permission=BlobSasPermissions(read=True),
                    expiry=expiry_time,
                )
                blob_client = self.blob_service_client.get_blob_client(self.container_name, blob_name)
                return f"{blob_client.url}?{sas_token}"
            except Exception as exc:
                logger.warning(f"Could not generate Azure SAS URL: {exc}. Returning standard download path.")
                return f"/api/v1/files/download/{blob_name}"

        return f"/api/v1/files/download/{blob_name}"

    def download_file(self, blob_name: str) -> Tuple[bytes, str]:
        """
        Download blob content and content_type from storage.
        """
        if not self.use_local_fallback and self.blob_service_client:
            blob_client = self.blob_service_client.get_blob_client(
                container=self.container_name,
                blob=blob_name
            )
            data = blob_client.download_blob().readall()
            properties = blob_client.get_blob_properties()
            content_type = properties.content_settings.content_type or "application/octet-stream"
            return data, content_type

        file_path = os.path.join(self.local_dir, blob_name)
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Blob '{blob_name}' does not exist.")

        with open(file_path, "rb") as f:
            data = f.read()

        meta_path = f"{file_path}.meta.json"
        content_type = "application/octet-stream"
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
                content_type = meta.get("content_type", content_type)

        return data, content_type

    def delete_file(self, blob_name: str) -> bool:
        """Delete blob from container."""
        if not self.use_local_fallback and self.blob_service_client:
            try:
                blob_client = self.blob_service_client.get_blob_client(self.container_name, blob_name)
                blob_client.delete_blob()
                return True
            except Exception as exc:
                logger.error(f"Error deleting blob '{blob_name}' from Azure: {exc}")
                return False

        file_path = os.path.join(self.local_dir, blob_name)
        meta_path = f"{file_path}.meta.json"
        deleted = False
        if os.path.exists(file_path):
            os.remove(file_path)
            deleted = True
        if os.path.exists(meta_path):
            os.remove(meta_path)
        return deleted


blob_service = AzureBlobService()

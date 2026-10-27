"""
Centralized Secret Provider for SecureShare.
Zero-Trust credential isolation using Azure Key Vault with automatic .env fallback.
"""
import logging
import os
from typing import Dict, Optional
from app.core.config import Settings, settings

logger = logging.getLogger("secureshare.keyvault")

try:
    from azure.identity import DefaultAzureCredential, ClientSecretCredential
    from azure.keyvault.secrets import SecretClient
    AZURE_SDK_AVAILABLE = True
except ImportError:
    AZURE_SDK_AVAILABLE = False
    logger.warning("Azure SDK libraries (azure-identity, azure-keyvault-secrets) not installed.")


class SecretProvider:
    """
    Centralized secret provider supporting Azure Key Vault with automatic local .env fallback.
    Implements the Singleton pattern, in-memory caching, and seamless secret hydration.
    Supports JWT Secret, Storage Connection String, Database Password, ClamAV config,
    and arbitrary future secrets.
    """

    def __init__(self, app_settings: Optional[Settings] = None):
        self.settings: Settings = app_settings or settings
        self.client: Optional["SecretClient"] = None
        self._cache: Dict[str, str] = {}
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize Azure Key Vault SecretClient if enabled and SDK is present."""
        if not self.settings.AZURE_KEYVAULT_ENABLED or not self.settings.AZURE_KEYVAULT_URL:
            logger.info("Azure Key Vault is disabled. SecretProvider will use environment variables.")
            return

        if not AZURE_SDK_AVAILABLE:
            logger.warning("Azure SDK is missing; cannot initialize Key Vault client. Falling back to .env.")
            return

        try:
            # Check for explicit service principal credentials or fall back to DefaultAzureCredential
            if (
                self.settings.AZURE_TENANT_ID
                and self.settings.AZURE_CLIENT_ID
                and self.settings.AZURE_CLIENT_SECRET
            ):
                logger.info("Authenticating to Azure Key Vault using ClientSecretCredential.")
                credential = ClientSecretCredential(
                    tenant_id=self.settings.AZURE_TENANT_ID,
                    client_id=self.settings.AZURE_CLIENT_ID,
                    client_secret=self.settings.AZURE_CLIENT_SECRET,
                )
            else:
                logger.info("Authenticating to Azure Key Vault using DefaultAzureCredential (Managed Identity / Azure CLI).")
                credential = DefaultAzureCredential()

            self.client = SecretClient(
                vault_url=self.settings.AZURE_KEYVAULT_URL,
                credential=credential
            )
            logger.info("Connected successfully to Azure Key Vault at %s", self.settings.AZURE_KEYVAULT_URL)
        except Exception as exc:
            logger.error("Failed to connect to Azure Key Vault: %s. Falling back to .env values.", exc)
            self.client = None

    def get_secret(self, secret_name: str, fallback_value: Optional[str] = None) -> Optional[str]:
        """
        Retrieve a secret by name with caching.
        First checks in-memory cache, then queries Azure Key Vault.
        If Key Vault is disabled, unavailable, or the secret does not exist,
        falls back to OS environment variable or the provided fallback value.
        """
        # Normalize secret name (Key Vault uses hyphens, env vars use underscores)
        kv_name = secret_name.replace("_", "-")
        env_name = secret_name.replace("-", "_").upper()

        if kv_name in self._cache:
            return self._cache[kv_name]

        # 1. Attempt retrieval from Azure Key Vault
        if self.client:
            try:
                retrieved = self.client.get_secret(kv_name)
                if retrieved and retrieved.value:
                    logger.info("Successfully retrieved secret '%s' from Azure Key Vault.", kv_name)
                    self._cache[kv_name] = retrieved.value
                    return retrieved.value
            except Exception as exc:
                logger.warning(
                    "Could not retrieve secret '%s' from Key Vault (%s). Falling back to environment.",
                    kv_name,
                    exc
                )

        # 2. Fall back to environment variable or provided fallback
        env_val = os.getenv(env_name, fallback_value)
        if env_val is not None:
            self._cache[kv_name] = env_val
            return env_val

        return fallback_value

    def get_jwt_secret(self) -> str:
        """Retrieve JWT Secret Key."""
        val = self.get_secret("jwt-secret", self.settings.SECRET_KEY)
        return val or self.settings.SECRET_KEY

    def get_storage_connection_string(self) -> Optional[str]:
        """Retrieve Azure Blob Storage Connection String."""
        return self.get_secret("storage-connection-string", self.settings.AZURE_STORAGE_CONNECTION_STRING)

    def get_database_password(self) -> str:
        """Retrieve Database Password."""
        val = self.get_secret("database-password", self.settings.POSTGRES_PASSWORD)
        return val or self.settings.POSTGRES_PASSWORD

    def get_clamav_config(self) -> Dict[str, str]:
        """Retrieve ClamAV Antivirus Configuration."""
        host = self.get_secret("clamav-host", self.settings.CLAMAV_HOST) or self.settings.CLAMAV_HOST
        port = self.get_secret("clamav-port", str(self.settings.CLAMAV_PORT)) or str(self.settings.CLAMAV_PORT)
        enabled = self.get_secret("clamav-enabled", str(self.settings.CLAMAV_ENABLED).lower())
        return {
            "host": host,
            "port": port,
            "enabled": enabled.lower() in ("true", "1", "yes") if enabled else False
        }

    def inject_secrets(self) -> None:
        """
        Fetch critical secrets from Key Vault (or fallbacks) and hydrate them
        into application settings at startup:
        - JWT Secret
        - Storage Connection String
        - Database Password & URL
        - ClamAV Configuration
        """
        # 1. JWT Secret
        jwt_secret = self.get_jwt_secret()
        if jwt_secret:
            self.settings.SECRET_KEY = jwt_secret

        # 2. Storage Connection String
        storage_conn = self.get_storage_connection_string()
        if storage_conn:
            self.settings.AZURE_STORAGE_CONNECTION_STRING = storage_conn

        # 3. Database Password
        db_pwd = self.get_database_password()
        if db_pwd:
            self.settings.POSTGRES_PASSWORD = db_pwd

        # 4. ClamAV Configuration
        clamav_conf = self.get_clamav_config()
        self.settings.CLAMAV_HOST = clamav_conf["host"]
        try:
            self.settings.CLAMAV_PORT = int(clamav_conf["port"])
        except ValueError:
            pass
        self.settings.CLAMAV_ENABLED = bool(clamav_conf["enabled"])

        logger.info("Application settings hydrated with centralized secret provider.")


# Global Singleton Instance
secret_provider = SecretProvider(settings)


def get_secret_provider() -> SecretProvider:
    """Dependency injection provider for FastAPI endpoints and services."""
    return secret_provider


# Backwards compatibility alias
KeyVaultManager = SecretProvider


def init_keyvault_secrets(app_settings: Settings) -> SecretProvider:
    """Helper function to load Azure Key Vault secrets into the application settings."""
    provider = SecretProvider(app_settings)
    provider.inject_secrets()
    return provider

import logging
from typing import Optional
from app.core.config import Settings

logger = logging.getLogger("secureshare.keyvault")

try:
    from azure.identity import DefaultAzureCredential, ClientSecretCredential
    from azure.keyvault.secrets import SecretClient
    AZURE_SDK_AVAILABLE = True
except ImportError:
    AZURE_SDK_AVAILABLE = False
    logger.warning("Azure SDK libraries (azure-identity, azure-keyvault-secrets) not installed.")


class KeyVaultManager:
    """
    Manages secret retrieval from Azure Key Vault with automatic fallback to environment variables.
    Adheres to Cloud Security Zero-Trust & Least Privilege best practices.
    """

    def __init__(self, settings: Settings):
        self.settings = settings
        self.client: Optional["SecretClient"] = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize Azure Key Vault SecretClient if configured and SDK is present."""
        if not self.settings.AZURE_KEYVAULT_ENABLED or not self.settings.AZURE_KEYVAULT_URL:
            logger.info("Azure Key Vault is not enabled. Relying on environment variables.")
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
            logger.info(f"Connected to Azure Key Vault at {self.settings.AZURE_KEYVAULT_URL}")
        except Exception as exc:
            logger.error(f"Failed to connect to Azure Key Vault: {exc}. Falling back to .env values.")
            self.client = None

    def get_secret(self, secret_name: str, fallback_value: Optional[str] = None) -> Optional[str]:
        """
        Retrieve a secret by name from Azure Key Vault.
        If unavailable, returns the fallback value from the environment.
        """
        if self.client:
            try:
                # Key Vault names use hyphens instead of underscores
                normalized_name = secret_name.replace("_", "-")
                retrieved_secret = self.client.get_secret(normalized_name)
                if retrieved_secret and retrieved_secret.value:
                    logger.info(f"Successfully retrieved secret '{normalized_name}' from Azure Key Vault.")
                    return retrieved_secret.value
            except Exception as exc:
                logger.warning(
                    f"Could not retrieve secret '{secret_name}' from Key Vault ({exc}). "
                    f"Falling back to local environment configuration."
                )

        return fallback_value

    def inject_secrets(self) -> None:
        """
        Fetch critical secrets from Key Vault and inject them into settings:
        1. Storage Connection String
        2. JWT Secret
        3. Database Password
        """
        # 1. Storage Connection String
        storage_conn = self.get_secret(
            "storage-connection-string",
            self.settings.AZURE_STORAGE_CONNECTION_STRING
        )
        if storage_conn:
            self.settings.AZURE_STORAGE_CONNECTION_STRING = storage_conn

        # 2. JWT Secret
        jwt_secret = self.get_secret(
            "jwt-secret",
            self.settings.SECRET_KEY
        )
        if jwt_secret:
            self.settings.SECRET_KEY = jwt_secret

        # 3. Database Password
        db_password = self.get_secret(
            "database-password",
            self.settings.POSTGRES_PASSWORD
        )
        if db_password:
            self.settings.POSTGRES_PASSWORD = db_password


def init_keyvault_secrets(settings: Settings) -> KeyVaultManager:
    """Helper function to load Azure Key Vault secrets into the application settings."""
    kv_manager = KeyVaultManager(settings)
    kv_manager.inject_secrets()
    return kv_manager

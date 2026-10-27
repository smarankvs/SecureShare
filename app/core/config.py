import os
from typing import List, Optional
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application Settings loaded from Environment variables and/or Azure Key Vault.
    Strictly follows 12-factor application design principles.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # General App Config
    APP_NAME: str = "SecureShare"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    API_V1_STR: str = "/api/v1"
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Security & JWT Configuration
    SECRET_KEY: str = "insecure-development-secret-key-change-in-production-vault-64chars-min"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Authentication Mode: "local" (app-issued HS256), "entra" (Microsoft Entra ID
    # RS256 via JWKS) or "both" (dispatch per token shape). Defaults to "local" so
    # that existing endpoints, tests and team-mates' flows keep working unchanged.
    AUTH_MODE: str = "local"

    # Microsoft Entra ID (OIDC) Configuration
    ENTRA_TENANT_ID: Optional[str] = None
    ENTRA_CLIENT_ID: Optional[str] = None  # API Application ID / audience
    ENTRA_ISSUER: Optional[str] = None  # defaults to tenant v2.0 issuer
    ENTRA_JWKS_URI: Optional[str] = None  # explicit override (e.g. for tests)
    JWKS_CACHE_TTL_SECONDS: int = 86400
    JWKS_REFRESH_COOLDOWN_SECONDS: int = 300
    JWKS_HTTP_TIMEOUT_SECONDS: int = 5
    JWT_LEEWAY_SECONDS: int = 60

    # Sharing Policy Defaults (Member 2 module)
    SHARE_SAS_EXPIRY_MINUTES: int = 5  # short-lived SAS issued by Member 3's service
    SHARE_MAX_DOWNLOADS_CAP: int = 100
    SHARE_MAX_EXPIRY_DAYS: int = 90

    # Database Configuration (PostgreSQL)
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "secureshare_user"
    POSTGRES_PASSWORD: str = "SecureShareP@ssw0rd123!"
    POSTGRES_DB: str = "secureshare_db"
    POSTGRES_SSLMODE: Optional[str] = None  # e.g., 'require' for Azure Database for PostgreSQL
    DATABASE_URL: Optional[str] = None

    # Azure Key Vault Configuration
    AZURE_KEYVAULT_URL: Optional[str] = None
    AZURE_KEYVAULT_ENABLED: bool = False
    AZURE_TENANT_ID: Optional[str] = None
    AZURE_CLIENT_ID: Optional[str] = None
    AZURE_CLIENT_SECRET: Optional[str] = None
    AZURE_KEYVAULT_FALLBACK_TO_ENV: bool = True

    # Azure Blob Storage Configuration
    AZURE_STORAGE_CONNECTION_STRING: Optional[str] = None
    AZURE_STORAGE_ACCOUNT_NAME: Optional[str] = None
    AZURE_STORAGE_CONTAINER_NAME: str = "secure-files"
    AZURE_STORAGE_USE_LOCAL_FALLBACK: bool = True
    LOCAL_STORAGE_DIR: str = "secure_storage_data"

    # File Upload Constraints
    MAX_FILE_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 Megabytes
    ALLOWED_EXTENSIONS: List[str] = [".pdf", ".png", ".jpg", ".jpeg", ".docx"]
    ALLOWED_MIME_TYPES: List[str] = [
        "application/pdf",
        "image/png",
        "image/jpeg",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    ]

    # CORS and Rate Limiting
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8000",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8000"
    ]
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = 60
    RATE_LIMIT_AUTH_REQUESTS_PER_MINUTE: int = 10

    # Virus Scanning (ClamAV Integration)
    CLAMAV_ENABLED: bool = False
    CLAMAV_HOST: str = "localhost"
    CLAMAV_PORT: int = 3310

    def get_database_url(self) -> str:
        """
        Construct or return the SQLAlchemy-compatible PostgreSQL connection string.
        Supports both local PostgreSQL and Azure Database for PostgreSQL Flexible Server
        without code changes via environment variables.
        """
        if self.DATABASE_URL:
            return self.DATABASE_URL
        import urllib.parse
        encoded_user = urllib.parse.quote_plus(self.POSTGRES_USER)
        encoded_pwd = urllib.parse.quote_plus(self.POSTGRES_PASSWORD)
        url = (
            f"postgresql+psycopg2://{encoded_user}:{encoded_pwd}@"
            f"{self.POSTGRES_SERVER}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )
        if self.POSTGRES_SSLMODE:
            url += f"?sslmode={self.POSTGRES_SSLMODE}"
        return url

    def get_entra_issuer(self) -> Optional[str]:
        """Resolve the expected token issuer for the configured Entra tenant."""
        if self.ENTRA_ISSUER:
            return self.ENTRA_ISSUER
        if self.ENTRA_TENANT_ID:
            return f"https://login.microsoftonline.com/{self.ENTRA_TENANT_ID}/v2.0"
        return None

    def get_entra_jwks_uri(self) -> Optional[str]:
        """Resolve the JWKS endpoint used to fetch signing keys."""
        if self.ENTRA_JWKS_URI:
            return self.ENTRA_JWKS_URI
        if self.ENTRA_TENANT_ID:
            return (
                f"https://login.microsoftonline.com/{self.ENTRA_TENANT_ID}"
                "/discovery/v2.0/keys"
            )
        return None



settings = Settings()

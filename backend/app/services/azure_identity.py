"""Shared Azure credential (Managed Identity in Azure, developer login locally)."""
from functools import lru_cache

from azure.identity import DefaultAzureCredential, ManagedIdentityCredential

from app.core.config import settings


@lru_cache
def get_azure_credential():
    if settings.is_production:
        # Production: Managed Identity only — no secrets, no CLI fallbacks.
        return ManagedIdentityCredential(client_id=settings.AZURE_MANAGED_IDENTITY_CLIENT_ID)
    return DefaultAzureCredential(managed_identity_client_id=settings.AZURE_MANAGED_IDENTITY_CLIENT_ID)

"""
Key-wrapping interface for envelope encryption — **Member 4 integration point**.

This module defines the contract (:class:`KeyWrapClient`) that the upload
pipeline depends on. Member 4's Key Vault client can be plugged in by either:

* implementing ``wrap_key`` / ``unwrap_key`` and calling
  :func:`register_key_wrap_client` at application startup, or
* relying on the bundled :class:`AzureKeyVaultKeyWrapClient`, which wraps the
  DEK with the Key Vault KEK (RSA-OAEP-256) using Managed Identity.

:class:`LocalDevKeyWrapClient` (AES-KW with a local KEK) exists solely for
local development/tests and is refused in production.
"""
from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from app.core.config import settings

logger = logging.getLogger("secureshare.keywrap")


@dataclass(frozen=True)
class WrappedKey:
    key_id: str          # KEK identifier (Key Vault key URL incl. version)
    algorithm: str       # e.g. "RSA-OAEP-256"
    encrypted_key: bytes


@runtime_checkable
class KeyWrapClient(Protocol):
    def wrap_key(self, dek: bytes) -> WrappedKey: ...
    def unwrap_key(self, wrapped: WrappedKey) -> bytes: ...


class AzureKeyVaultKeyWrapClient:
    """Wraps DEKs with an RSA KEK held in Azure Key Vault (keys never leave the HSM/vault)."""

    ALGORITHM = "RSA-OAEP-256"

    def __init__(self, kek_id: str, credential=None):
        from azure.keyvault.keys.crypto import CryptographyClient

        from app.services.azure_identity import get_azure_credential

        self._client = CryptographyClient(kek_id, credential or get_azure_credential())
        self._kek_id = kek_id

    def wrap_key(self, dek: bytes) -> WrappedKey:
        from azure.keyvault.keys.crypto import KeyWrapAlgorithm

        res = self._client.wrap_key(KeyWrapAlgorithm.rsa_oaep_256, dek)
        return WrappedKey(key_id=res.key_id or self._kek_id, algorithm=self.ALGORITHM, encrypted_key=res.encrypted_key)

    def unwrap_key(self, wrapped: WrappedKey) -> bytes:
        from azure.keyvault.keys.crypto import KeyWrapAlgorithm

        if wrapped.algorithm != self.ALGORITHM:
            raise ValueError(f"Unsupported wrap algorithm {wrapped.algorithm}")
        return self._client.unwrap_key(KeyWrapAlgorithm.rsa_oaep_256, wrapped.encrypted_key).key


class LocalDevKeyWrapClient:
    """RFC 3394 AES key wrap with a local KEK. Development/test use only."""

    ALGORITHM = "A256KW"

    def __init__(self, kek: bytes, key_id: str = "local-dev-kek"):
        if settings.is_production:
            raise RuntimeError("LocalDevKeyWrapClient must not be used in production")
        if len(kek) != 32:
            raise ValueError("Local KEK must be 32 bytes")
        self._kek = kek
        self._key_id = key_id

    def wrap_key(self, dek: bytes) -> WrappedKey:
        return WrappedKey(self._key_id, self.ALGORITHM, aes_key_wrap(self._kek, dek))

    def unwrap_key(self, wrapped: WrappedKey) -> bytes:
        if wrapped.algorithm != self.ALGORITHM:
            raise ValueError(f"Unsupported wrap algorithm {wrapped.algorithm}")
        return aes_key_unwrap(self._kek, wrapped.encrypted_key)


_client: KeyWrapClient | None = None


def register_key_wrap_client(client: KeyWrapClient) -> None:
    """Hook for Member 4: install their Key Vault client at startup."""
    global _client
    if not isinstance(client, KeyWrapClient):
        raise TypeError("client must implement wrap_key(dek) and unwrap_key(wrapped)")
    _client = client


def get_key_wrap_client() -> KeyWrapClient:
    global _client
    if _client is not None:
        return _client
    if settings.AZURE_KEYVAULT_KEK_ID:
        _client = AzureKeyVaultKeyWrapClient(settings.AZURE_KEYVAULT_KEK_ID)
    elif settings.LOCAL_DEV_KEK_B64 and not settings.is_production:
        logger.warning("Using LOCAL development KEK — not for production use.")
        _client = LocalDevKeyWrapClient(base64.b64decode(settings.LOCAL_DEV_KEK_B64))
    else:
        raise RuntimeError(
            "No key-wrap client configured: set AZURE_KEYVAULT_KEK_ID or register Member 4's client"
        )
    return _client

"""
Envelope encryption with AES-256-GCM.

For every document a fresh, ephemeral 256-bit Data Encryption Key (DEK) is
generated, used once to encrypt the payload, then wrapped by the KEK via the
:class:`~app.services.key_wrapping.KeyWrapClient`. Only the *wrapped* DEK is
persisted (as blob metadata); the plaintext DEK never leaves process memory.

The blob name is bound to the ciphertext as Additional Authenticated Data
(AAD), so a ciphertext copied to another blob name fails authentication.
"""
from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.services.key_wrapping import KeyWrapClient, WrappedKey

ENC_ALGORITHM = "AES-256-GCM"
ENVELOPE_VERSION = "1"
NONCE_BYTES = 12


@dataclass(frozen=True)
class EncryptedPayload:
    ciphertext: bytes  # includes the 16-byte GCM tag
    nonce: bytes
    wrapped_key: WrappedKey

    def to_metadata(self) -> dict[str, str]:
        """Azure blob metadata (ASCII, case-insensitive keys)."""
        return {
            "ss_envelope_version": ENVELOPE_VERSION,
            "ss_enc_alg": ENC_ALGORITHM,
            "ss_nonce": base64.b64encode(self.nonce).decode(),
            "ss_wrapped_dek": base64.b64encode(self.wrapped_key.encrypted_key).decode(),
            "ss_wrap_alg": self.wrapped_key.algorithm,
            "ss_kek_id": self.wrapped_key.key_id,
        }


def encrypt(plaintext: bytes, aad: bytes, key_wrapper: KeyWrapClient) -> EncryptedPayload:
    dek = AESGCM.generate_key(bit_length=256)
    try:
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
        wrapped = key_wrapper.wrap_key(dek)
    finally:
        del dek  # drop the only reference to the plaintext DEK
    return EncryptedPayload(ciphertext=ciphertext, nonce=nonce, wrapped_key=wrapped)


def decrypt(ciphertext: bytes, metadata: dict[str, str], aad: bytes, key_wrapper: KeyWrapClient) -> bytes:
    md = {k.lower(): v for k, v in metadata.items()}
    if md.get("ss_enc_alg") != ENC_ALGORITHM:
        raise ValueError("Unsupported or missing envelope encryption metadata")
    wrapped = WrappedKey(
        key_id=md["ss_kek_id"],
        algorithm=md["ss_wrap_alg"],
        encrypted_key=base64.b64decode(md["ss_wrapped_dek"]),
    )
    dek = key_wrapper.unwrap_key(wrapped)
    try:
        return AESGCM(dek).decrypt(base64.b64decode(md["ss_nonce"]), ciphertext, aad)
    finally:
        del dek

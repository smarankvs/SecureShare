import hashlib
import hmac
import os
import secrets
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def calculate_sha256(data: bytes) -> str:
    """
    Compute cryptographic SHA-256 hash of file content for integrity auditing.
    """
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()


def generate_encryption_key() -> bytes:
    """Generate a cryptographically secure 256-bit AES-GCM key."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_data(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt data using AES-256-GCM (Authenticated Encryption with Associated Data).
    Returns (ciphertext, nonce).
    """
    nonce = os.urandom(12)  # Standard 96-bit nonce for AES-GCM
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return ciphertext, nonce


def decrypt_data(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    """
    Decrypt data using AES-256-GCM.
    Ensures message integrity and authenticity; raises InvalidTag if tampered with.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def secure_compare(val1: str, val2: str) -> bool:
    """
    Constant-time comparison against timing attacks.
    """
    return hmac.compare_digest(val1.encode("utf-8"), val2.encode("utf-8"))

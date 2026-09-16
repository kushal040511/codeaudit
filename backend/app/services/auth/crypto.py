"""Encryption of stored OAuth tokens and hashing of session / API tokens.

GitHub access tokens are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) using
keys from TOKEN_ENCRYPTION_KEYS; they are never stored or logged in plaintext.
Session and API tokens are random secrets we only need to recognise, so only
their SHA-256 hash is stored.
"""

import hashlib
import hmac
import secrets
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.config import get_settings


class TokenEncryptionUnavailableError(RuntimeError):
    """TOKEN_ENCRYPTION_KEYS is not configured (or invalid)."""


class TokenDecryptionError(RuntimeError):
    """A stored token can't be decrypted (wrong or rotated-out key, or tampering)."""


def generate_key() -> str:
    return Fernet.generate_key().decode()


@lru_cache
def _fernet(keys: str) -> MultiFernet:
    try:
        return MultiFernet([Fernet(key.strip().encode()) for key in keys.split(",") if key.strip()])
    except (ValueError, TypeError) as exc:
        raise TokenEncryptionUnavailableError(
            "TOKEN_ENCRYPTION_KEYS contains an invalid Fernet key."
        ) from exc


def _cipher() -> MultiFernet:
    configured = get_settings().token_encryption_keys
    if configured is None or not configured.get_secret_value().strip():
        raise TokenEncryptionUnavailableError(
            "TOKEN_ENCRYPTION_KEYS is not set; GitHub tokens can't be stored."
        )
    return _fernet(configured.get_secret_value())


def encrypt_token(token: str) -> bytes:
    return _cipher().encrypt(token.encode())


def decrypt_token(ciphertext: bytes) -> str:
    try:
        return _cipher().decrypt(bytes(ciphertext)).decode()
    except InvalidToken:
        raise TokenDecryptionError("Stored token could not be decrypted.") from None


def reencrypt_token(ciphertext: bytes) -> bytes:
    """Re-encrypt with the current primary key (key rotation)."""
    return _cipher().rotate(bytes(ciphertext))


def new_secret(prefix: str = "", nbytes: int = 32) -> str:
    return f"{prefix}{secrets.token_urlsafe(nbytes)}"


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def secrets_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())

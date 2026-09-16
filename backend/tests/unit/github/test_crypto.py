import pytest
from cryptography.fernet import Fernet

from app.config import get_settings
from app.services.auth import crypto


def test_encryption_round_trip_and_ciphertext_hides_token() -> None:
    token = "gho_exampleTokenValue1234567890"
    encrypted = crypto.encrypt_token(token)
    assert token.encode() not in encrypted
    assert crypto.encrypt_token(token) != encrypted  # random IV
    assert crypto.decrypt_token(encrypted) == token


def test_tampered_ciphertext_is_rejected_without_leaking() -> None:
    encrypted = bytearray(crypto.encrypt_token("gho_secret"))
    encrypted[-5] ^= 1
    with pytest.raises(crypto.TokenDecryptionError) as info:
        crypto.decrypt_token(bytes(encrypted))
    assert "gho_secret" not in str(info.value)
    assert info.value.__cause__ is None and info.value.__suppress_context__


def test_key_rotation(monkeypatch: pytest.MonkeyPatch) -> None:
    old_key = get_settings().token_encryption_keys
    assert old_key is not None
    encrypted = crypto.encrypt_token("gho_rotate")
    new_key = Fernet.generate_key().decode()
    settings = get_settings()
    monkeypatch.setattr(
        settings, "token_encryption_keys", type(old_key)(f"{new_key},{old_key.get_secret_value()}")
    )
    assert crypto.decrypt_token(encrypted) == "gho_rotate"  # old key still decrypts
    rotated = crypto.reencrypt_token(encrypted)
    monkeypatch.setattr(settings, "token_encryption_keys", type(old_key)(new_key))
    assert crypto.decrypt_token(rotated) == "gho_rotate"
    with pytest.raises(crypto.TokenDecryptionError):
        crypto.decrypt_token(encrypted)


def test_missing_key_refuses_to_store(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "token_encryption_keys", None)
    with pytest.raises(crypto.TokenEncryptionUnavailableError):
        crypto.encrypt_token("gho_x")


def test_secrets_are_hashed() -> None:
    secret = crypto.new_secret("cat_")
    assert secret.startswith("cat_") and len(secret) > 40
    assert crypto.hash_secret(secret) != secret and len(crypto.hash_secret(secret)) == 64

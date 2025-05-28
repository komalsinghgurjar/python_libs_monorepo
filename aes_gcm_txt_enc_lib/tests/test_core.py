import pytest
from aes_gcm_txt_enc_lib.core import generate_key, encrypt, decrypt, validate_b64
import math

def test_generate_key_valid_sizes():
    for size in (128, 192, 256):
        key = generate_key(size)
        assert isinstance(key, str)
        expected_len = 4 * math.ceil((size // 8) / 3)
        assert len(key) == expected_len

def test_generate_key_invalid_size():
    with pytest.raises(ValueError):
        generate_key(100)

def test_validate_b64_valid_key():
    key = generate_key(256)
    validate_b64(key)  # should not raise

def test_validate_b64_invalid_key():
    with pytest.raises(ValueError):
        validate_b64("not_base64!!")

def test_encrypt_decrypt():
    key = generate_key(256)
    plaintext = "Hello, AES-GCM!"
    ciphertext = encrypt(plaintext, key)
    assert isinstance(ciphertext, str)
    decrypted = decrypt(ciphertext, key)
    assert decrypted == plaintext

def test_decrypt_invalid_ciphertext():
    key = generate_key(256)
    with pytest.raises(ValueError):
        decrypt("invalidciphertext", key)

def test_decrypt_with_wrong_key():
    key1 = generate_key(256)
    key2 = generate_key(256)
    plaintext = "Secret message"
    ciphertext = encrypt(plaintext, key1)
    with pytest.raises(ValueError):
        decrypt(ciphertext, key2)

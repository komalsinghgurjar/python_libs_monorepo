import pytest
from aes_gcm_txt_enc_lib.aes_gcm_encryptor import AesGcmEncryptor
from aes_gcm_txt_enc_lib.core import generate_key, validate_b64

def test_init_with_generated_key():
    encryptor = AesGcmEncryptor()
    key = encryptor.get_key()
    validate_b64(key)  # Should not raise
    assert isinstance(key, str)

def test_init_with_provided_key():
    key = generate_key(256)
    encryptor = AesGcmEncryptor(b64_key=key)
    assert encryptor.get_key() == key

def test_set_key_and_get_key():
    encryptor = AesGcmEncryptor()
    key = generate_key(192)
    encryptor.set_key(key)
    assert encryptor.get_key() == key
    with pytest.raises(ValueError):
        encryptor.set_key("invalid_base64!!")

def test_generate_key_method_changes_key():
    encryptor = AesGcmEncryptor()
    old_key = encryptor.get_key()
    encryptor.generate_key(128)
    new_key = encryptor.get_key()
    assert old_key != new_key

def test_encrypt_decrypt_cycle():
    encryptor = AesGcmEncryptor()
    plaintext = "Testing AES-GCM class!"
    ciphertext = encryptor.encrypt(plaintext)
    assert isinstance(ciphertext, str)
    decrypted = encryptor.decrypt(ciphertext)
    assert decrypted == plaintext

def test_decrypt_with_wrong_key_raises():
    encryptor1 = AesGcmEncryptor()
    encryptor2 = AesGcmEncryptor()
    plaintext = "Sensitive data"
    ciphertext = encryptor1.encrypt(plaintext)
    with pytest.raises(ValueError):
        encryptor2.decrypt(ciphertext)

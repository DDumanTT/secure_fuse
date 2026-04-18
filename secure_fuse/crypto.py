import json
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .constants import NONCE_SIZE


def derive_master_key(password, salt, key_length=32):
    if isinstance(password, str):
        password = password.encode("utf-8")

    kdf = Argon2id(
        salt=salt,
        length=key_length,
        iterations=3,
        memory_cost=2**16,  # 64 MB
        lanes=4,
    )

    return kdf.derive(password)


def encrypt_bytes(key, plaintext):
    nonce = secrets.token_bytes(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt_bytes(key, blob):
    if not blob:
        return b""
    nonce = blob[:NONCE_SIZE]
    ciphertext = blob[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def encrypt_json(key, payload):
    return encrypt_bytes(key, json.dumps(payload).encode("utf-8"))


def decrypt_json(key, blob):
    plaintext = decrypt_bytes(key, blob)
    if not plaintext:
        return {}
    return json.loads(plaintext.decode("utf-8"))

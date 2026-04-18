import json
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .constants import KDF_ITERATIONS, KDF_LANES, KDF_MEMORY_COST, NONCE_SIZE


def derive_master_key(password, keyfile_material, salt, key_length=32, *, kdf_params=None):
    if isinstance(password, str):
        password = password.encode("utf-8")

    if not keyfile_material:
        raise ValueError("Keyfile material is required")

    params = {
        "iterations": KDF_ITERATIONS,
        "memory_cost": KDF_MEMORY_COST,
        "lanes": KDF_LANES,
    }
    if kdf_params:
        params.update(kdf_params)

    combined_secret = password + keyfile_material

    kdf = Argon2id(
        salt=salt,
        length=key_length,
        iterations=params["iterations"],
        memory_cost=params["memory_cost"],
        lanes=params["lanes"],
    )

    return kdf.derive(combined_secret)


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

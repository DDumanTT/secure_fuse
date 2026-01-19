#!/usr/bin/env python3
import os
import errno
from fuse import FUSE, FuseOSError, Operations
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag
import secrets
import json

KEY_SIZE = 32 # AES-256
NONCE_SIZE = 12


class FuseFS(Operations):
    def __init__(self, backend_path, password):
        self.backend = os.path.abspath(backend_path)
        self.master_key = self._derive_master_key(password)

    # Key management

    def _derive_master_key(self, password: bytes) -> bytes:
        if isinstance(password, str):
            password = password.encode("utf-8")

        kdf = Argon2id(
            salt=b'saltsalt', # TODO: generate salt
            length=32,
            iterations=3,
            memory_cost=2**16, # 64 MB
            lanes=4,
        )

        return kdf.derive(password)

    def _key_path(self, path):
        return self._full_path(path) + ".key"

    def _load_or_create_fek(self, path):
        key_path = self._key_path(path)

        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                wrapped = f.read()
            aes = AESGCM(self.master_key)
            try:
                return aes.decrypt(wrapped[:NONCE_SIZE], wrapped[NONCE_SIZE:], None)
            except InvalidTag:
                raise FuseOSError(errno.EACCES)

        fek = secrets.token_bytes(KEY_SIZE)
        aes = AESGCM(self.master_key)
        nonce = secrets.token_bytes(NONCE_SIZE)
        wrapped = nonce + aes.encrypt(nonce, fek, None)

        with open(key_path, "wb") as f:
            f.write(wrapped)

        return fek

    # Path helpers

    def _full_path(self, path):
        if path.startswith("/"):
            path = path[1:]
        return os.path.join(self.backend, path)

    # Filesystem operations

    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
        try:
            st = os.lstat(full_path)
        except FileNotFoundError:
            raise FuseOSError(errno.ENOENT)

        return dict(
            st_mode=st.st_mode,
            st_size=st.st_size,
            st_uid=st.st_uid,
            st_gid=st.st_gid,
            st_atime=st.st_atime,
            st_mtime=st.st_mtime,
            st_ctime=st.st_ctime,
            st_nlink=st.st_nlink,
        )

    def readdir(self, path, fh):
        full_path = self._full_path(path)
        entries = [".", ".."]

        if os.path.isdir(full_path):
            entries.extend(
                f for f in os.listdir(full_path) if not f.endswith(".key")
            )

        for entry in entries:
            yield entry

    def create(self, path, mode, fi=None):
        full_path = self._full_path(path)
        open(full_path, "wb").close()
        self._load_or_create_fek(path)
        return os.open(full_path, os.O_WRONLY)

    def unlink(self, path):
        os.unlink(self._full_path(path))
        try:
            os.unlink(self._key_path(path))
        except FileNotFoundError:
            pass

    # File operations

    def read(self, path, size, offset, fh):
        full_path = self._full_path(path)
        fek = self._load_or_create_fek(path)

        with open(full_path, "rb") as f:
            blob = f.read()

        if not blob:
            return b""

        nonce = blob[:NONCE_SIZE]
        ciphertext = blob[NONCE_SIZE:]
        aes = AESGCM(fek)
        plaintext = aes.decrypt(nonce, ciphertext, None)

        return plaintext[offset : offset + size]

    def write(self, path, data, offset, fh):
        full_path = self._full_path(path)
        fek = self._load_or_create_fek(path)

        try:
            plaintext = b""
            if os.path.exists(full_path):
                with open(full_path, "rb") as f:
                    blob = f.read()
                if blob:
                    nonce = blob[:NONCE_SIZE]
                    aes = AESGCM(fek)
                    plaintext = aes.decrypt(nonce, blob[NONCE_SIZE:], None)

            plaintext = (
                plaintext[:offset] + data + plaintext[offset + len(data) :]
            )

            nonce = secrets.token_bytes(NONCE_SIZE)
            aes = AESGCM(fek)
            ciphertext = aes.encrypt(nonce, plaintext, None)

            with open(full_path, "wb") as f:
                f.write(nonce + ciphertext)

            return len(data)

        except Exception:
            raise FuseOSError(errno.EIO)

    def release(self, path, fh):
        os.close(fh)


def main(mountpoint, backend, password):
    os.makedirs(backend, exist_ok=True)
    FUSE(FuseFS(backend, password), mountpoint, foreground=True)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        print("Usage: python prototype.py <mountpoint> <backend> <password>")
        exit(1)

    main(sys.argv[1], sys.argv[2], sys.argv[3])
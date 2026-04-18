#!/usr/bin/env python3
import json
import logging
import os
import stat
import errno
import time
from fuse import FUSE, FuseOSError, Operations
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidTag
import secrets

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fuse_fs")
# Suppress fusepy's internal per-call debug/traceback messages
logging.getLogger("fuse").setLevel(logging.WARNING)

KEY_SIZE = 32  # AES-256
NONCE_SIZE = 12
SALT_SIZE = 16
GCM_TAG_SIZE = 16
WIPE_PASSES = 1
WIPE_CHUNK_SIZE = 64 * 1024


class FuseFS(Operations):
    def __init__(self, backend_path, password):
        self.backend = os.path.abspath(backend_path)
        self.objects_dir = os.path.join(self.backend, "objects")
        os.makedirs(self.backend, exist_ok=True)
        os.makedirs(self.objects_dir, exist_ok=True)
        log.info("Initialising filesystem (backend=%s)", self.backend)
        salt = self._load_or_create_salt()
        self.master_key = self._derive_master_key(password, salt)
        self.root_id = self._load_or_create_root_id()
        log.info("Filesystem ready (root_id=%s)", self.root_id)

    # Key management

    def _load_or_create_salt(self) -> bytes:
        salt_path = os.path.join(self.backend, ".salt")
        if os.path.exists(salt_path):
            log.debug("Loading existing salt")
            with open(salt_path, "rb") as f:
                return f.read()
        log.info("Creating new salt")
        salt = secrets.token_bytes(SALT_SIZE)
        with open(salt_path, "wb") as f:
            f.write(salt)
        return salt

    def _derive_master_key(self, password: bytes, salt: bytes) -> bytes:
        if isinstance(password, str):
            password = password.encode("utf-8")

        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            memory_cost=2**16,  # 64 MB
            lanes=4,
        )

        return kdf.derive(password)

    def _root_path(self):
        return os.path.join(self.backend, ".root")

    def _node_path(self, node_id, suffix):
        return os.path.join(self.objects_dir, f"{node_id}{suffix}")

    def _blob_path(self, node_id):
        return self._node_path(node_id, ".blob")

    def _meta_path(self, node_id):
        return self._node_path(node_id, ".meta")

    def _key_path(self, node_id):
        return self._node_path(node_id, ".key")

    def _generate_node_id(self):
        return secrets.token_hex(16)

    def _encrypt_bytes(self, key, plaintext):
        nonce = secrets.token_bytes(NONCE_SIZE)
        return nonce + AESGCM(key).encrypt(nonce, plaintext, None)

    def _decrypt_bytes(self, key, blob):
        if not blob:
            return b""
        nonce = blob[:NONCE_SIZE]
        ciphertext = blob[NONCE_SIZE:]
        return AESGCM(key).decrypt(nonce, ciphertext, None)

    def _encrypt_json(self, key, payload):
        return self._encrypt_bytes(key, json.dumps(payload).encode("utf-8"))

    def _decrypt_json(self, key, blob):
        plaintext = self._decrypt_bytes(key, blob)
        if not plaintext:
            return {}
        return json.loads(plaintext.decode("utf-8"))

    def _load_or_create_fek(self, node_id):
        key_path = self._key_path(node_id)

        if os.path.exists(key_path):
            log.debug("Loading FEK for node %s", node_id)
            with open(key_path, "rb") as f:
                wrapped = f.read()
            try:
                return self._decrypt_bytes(self.master_key, wrapped)
            except InvalidTag:
                log.warning("FEK decryption failed for node %s (bad master key?)", node_id)
                raise FuseOSError(errno.EACCES)

        log.debug("Generating new FEK for node %s", node_id)
        fek = secrets.token_bytes(KEY_SIZE)
        wrapped = self._encrypt_bytes(self.master_key, fek)

        with open(key_path, "wb") as f:
            f.write(wrapped)

        return fek

    def _default_metadata(self, node_type, mode):
        now = time.time()
        file_type = stat.S_IFDIR if node_type == "dir" else stat.S_IFREG
        return {
            "type": node_type,
            "mode": file_type | mode,
            "uid": os.getuid(),
            "gid": os.getgid(),
            "atime": now,
            "mtime": now,
            "ctime": now,
            "nlink": 2 if node_type == "dir" else 1,
        }

    def _load_or_create_root_id(self):
        root_path = self._root_path()
        if os.path.exists(root_path):
            with open(root_path, "r", encoding="utf-8") as f:
                root_id = f.read().strip()
            log.debug("Loaded existing root node %s", root_id)
        else:
            root_id = self._generate_node_id()
            with open(root_path, "w", encoding="utf-8") as f:
                f.write(root_id)
            log.info("Created new root node %s", root_id)

        if not os.path.exists(self._meta_path(root_id)):
            self._create_node(root_id, "dir", 0o755)
        return root_id

    def _create_node(self, node_id, node_type, mode):
        fek = self._load_or_create_fek(node_id)
        metadata = self._default_metadata(node_type, mode)
        self._save_metadata(node_id, metadata)
        if node_type == "dir":
            self._save_directory_entries(node_id, {})
        else:
            with open(self._blob_path(node_id), "wb") as f:
                f.write(b"")
        return fek

    def _load_metadata(self, node_id):
        fek = self._load_or_create_fek(node_id)
        try:
            with open(self._meta_path(node_id), "rb") as f:
                return self._decrypt_json(fek, f.read())
        except FileNotFoundError:
            raise FuseOSError(errno.ENOENT)
        except InvalidTag:
            raise FuseOSError(errno.EACCES)

    def _save_metadata(self, node_id, metadata):
        fek = self._load_or_create_fek(node_id)
        with open(self._meta_path(node_id), "wb") as f:
            f.write(self._encrypt_json(fek, metadata))

    def _load_directory_entries(self, node_id):
        fek = self._load_or_create_fek(node_id)
        try:
            with open(self._blob_path(node_id), "rb") as f:
                payload = self._decrypt_json(fek, f.read())
        except FileNotFoundError:
            raise FuseOSError(errno.ENOENT)
        except InvalidTag:
            raise FuseOSError(errno.EACCES)
        return payload.get("entries", {})

    def _save_directory_entries(self, node_id, entries):
        fek = self._load_or_create_fek(node_id)
        with open(self._blob_path(node_id), "wb") as f:
            f.write(self._encrypt_json(fek, {"entries": entries}))

    def _load_file_data(self, node_id):
        fek = self._load_or_create_fek(node_id)
        blob_path = self._blob_path(node_id)
        try:
            with open(blob_path, "rb") as f:
                blob = f.read()
        except FileNotFoundError:
            raise FuseOSError(errno.ENOENT)

        if not blob:
            return b""

        try:
            return self._decrypt_bytes(fek, blob)
        except InvalidTag:
            raise FuseOSError(errno.EACCES)

    def _save_file_data(self, node_id, plaintext):
        fek = self._load_or_create_fek(node_id)
        with open(self._blob_path(node_id), "wb") as f:
            if plaintext:
                f.write(self._encrypt_bytes(fek, plaintext))
            else:
                f.write(b"")

    def _split_path(self, path):
        if path in ("", "/"):
            return []
        return [part for part in path.split("/") if part]

    def _resolve_path(self, path):
        current_id = self.root_id
        current_meta = self._load_metadata(current_id)

        for part in self._split_path(path):
            if current_meta["type"] != "dir":
                raise FuseOSError(errno.ENOTDIR)

            entries = self._load_directory_entries(current_id)
            try:
                current_id = entries[part]
            except KeyError:
                raise FuseOSError(errno.ENOENT)
            current_meta = self._load_metadata(current_id)

        return current_id, current_meta

    def _resolve_parent(self, path):
        parts = self._split_path(path)
        if not parts:
            raise FuseOSError(errno.EINVAL)

        name = parts[-1]
        parent_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
        parent_id, parent_meta = self._resolve_path(parent_path)
        if parent_meta["type"] != "dir":
            raise FuseOSError(errno.ENOTDIR)
        return parent_id, parent_meta, name

    def _touch_metadata(
        self,
        node_id,
        *,
        update_access=False,
        update_modify=False,
        update_change=False,
    ):
        metadata = self._load_metadata(node_id)
        now = time.time()
        if update_access:
            metadata["atime"] = now
        if update_modify:
            metadata["mtime"] = now
        if update_modify or update_change:
            metadata["ctime"] = now
        self._save_metadata(node_id, metadata)
        return metadata

    def _is_descendant(self, ancestor_id, candidate_id):
        if ancestor_id == candidate_id:
            return True

        metadata = self._load_metadata(ancestor_id)
        if metadata["type"] != "dir":
            return False

        for child_id in self._load_directory_entries(ancestor_id).values():
            if self._is_descendant(child_id, candidate_id):
                return True

        return False

    def _secure_wipe_blob(self, node_id):
        blob_path = self._blob_path(node_id)
        try:
            size = os.path.getsize(blob_path)
        except FileNotFoundError:
            return

        if size <= 0:
            return

        try:
            with open(blob_path, "r+b", buffering=0) as f:
                for _ in range(WIPE_PASSES):
                    f.seek(0)
                    remaining = size
                    while remaining > 0:
                        chunk_size = min(remaining, WIPE_CHUNK_SIZE)
                        f.write(secrets.token_bytes(chunk_size))
                        remaining -= chunk_size
                    f.flush()
                    os.fsync(f.fileno())

                f.seek(0)
                f.truncate(0)
                f.flush()
                os.fsync(f.fileno())
        except FileNotFoundError:
            return
        except OSError as exc:
            # Wipe is best-effort; deletion continues with a warning.
            log.warning("Best-effort blob wipe failed for node %s: %s", node_id, exc)

    def _fsync_path(self, path):
        fd = os.open(path, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _fsync_directory(self, path):
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        fd = os.open(path, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _sync_directory_node(self, node_id):
        self._fsync_path(self._blob_path(node_id))
        self._fsync_path(self._meta_path(node_id))

    def _remove_node(self, node_id):
        for suffix in (".key", ".blob", ".meta"):
            try:
                os.unlink(self._node_path(node_id, suffix))
            except FileNotFoundError:
                pass

    # Filesystem operations

    def getattr(self, path, fh=None):
        log.debug("getattr %s", path)
        node_id, metadata = self._resolve_path(path)

        if metadata["type"] == "file":
            try:
                raw_size = os.path.getsize(self._blob_path(node_id))
            except FileNotFoundError:
                raise FuseOSError(errno.ENOENT)
            plaintext_size = max(0, raw_size - NONCE_SIZE - GCM_TAG_SIZE) if raw_size > 0 else 0
        else:
            plaintext_size = 0

        return dict(
            st_mode=metadata["mode"],
            st_size=plaintext_size,
            st_uid=metadata["uid"],
            st_gid=metadata["gid"],
            st_atime=metadata["atime"],
            st_mtime=metadata["mtime"],
            st_ctime=metadata["ctime"],
            st_nlink=metadata["nlink"],
        )

    def readdir(self, path, fh):
        log.debug("readdir %s", path)
        entries = [".", ".."]

        node_id, metadata = self._resolve_path(path)
        if metadata["type"] != "dir":
            raise FuseOSError(errno.ENOTDIR)

        entries.extend(sorted(self._load_directory_entries(node_id)))

        for entry in entries:
            yield entry

    def create(self, path, mode, fi=None):
        log.info("create %s (mode=%o)", path, mode)
        parent_id, _, name = self._resolve_parent(path)
        entries = self._load_directory_entries(parent_id)
        if name in entries:
            raise FuseOSError(errno.EEXIST)

        node_id = self._generate_node_id()
        self._create_node(node_id, "file", mode)
        entries[name] = node_id
        self._save_directory_entries(parent_id, entries)
        self._touch_metadata(parent_id, update_modify=True)
        return os.open(self._blob_path(node_id), os.O_WRONLY)

    def mkdir(self, path, mode):
        log.info("mkdir %s (mode=%o)", path, mode)
        parent_id, _, name = self._resolve_parent(path)
        entries = self._load_directory_entries(parent_id)
        if name in entries:
            raise FuseOSError(errno.EEXIST)

        node_id = self._generate_node_id()
        self._create_node(node_id, "dir", mode)
        entries[name] = node_id
        self._save_directory_entries(parent_id, entries)
        self._touch_metadata(parent_id, update_modify=True)

    def unlink(self, path):
        log.info("unlink %s", path)
        parent_id, _, name = self._resolve_parent(path)
        entries = self._load_directory_entries(parent_id)
        try:
            node_id = entries[name]
        except KeyError:
            raise FuseOSError(errno.ENOENT)

        if self._load_metadata(node_id)["type"] != "file":
            raise FuseOSError(errno.EISDIR)

        self._secure_wipe_blob(node_id)
        self._remove_node(node_id)
        del entries[name]
        self._save_directory_entries(parent_id, entries)
        self._touch_metadata(parent_id, update_modify=True)
        self._sync_directory_node(parent_id)
        self._fsync_directory(self.objects_dir)

    def rmdir(self, path):
        log.info("rmdir %s", path)
        parent_id, _, name = self._resolve_parent(path)
        entries = self._load_directory_entries(parent_id)
        try:
            node_id = entries[name]
        except KeyError:
            raise FuseOSError(errno.ENOENT)

        if self._load_metadata(node_id)["type"] != "dir":
            raise FuseOSError(errno.ENOTDIR)
        if self._load_directory_entries(node_id):
            raise FuseOSError(errno.ENOTEMPTY)

        self._remove_node(node_id)
        del entries[name]
        self._save_directory_entries(parent_id, entries)
        self._touch_metadata(parent_id, update_modify=True)
        self._sync_directory_node(parent_id)
        self._fsync_directory(self.objects_dir)

    def rename(self, old, new):
        log.info("rename %s -> %s", old, new)
        old_parent_id, _, old_name = self._resolve_parent(old)
        new_parent_id, _, new_name = self._resolve_parent(new)

        if old_parent_id == new_parent_id:
            entries = self._load_directory_entries(old_parent_id)
            try:
                node_id = entries[old_name]
            except KeyError:
                raise FuseOSError(errno.ENOENT)

            if old_name == new_name:
                return 0

            node_metadata = self._load_metadata(node_id)
            replaced_node_id = entries.get(new_name)
            if replaced_node_id is not None and replaced_node_id != node_id:
                replaced_metadata = self._load_metadata(replaced_node_id)
                if node_metadata["type"] == "file" and replaced_metadata["type"] == "dir":
                    raise FuseOSError(errno.EISDIR)
                if node_metadata["type"] == "dir" and replaced_metadata["type"] == "file":
                    raise FuseOSError(errno.ENOTDIR)
                if replaced_metadata["type"] == "dir" and self._load_directory_entries(replaced_node_id):
                    raise FuseOSError(errno.ENOTEMPTY)
                if replaced_metadata["type"] == "file":
                    self._secure_wipe_blob(replaced_node_id)

                self._remove_node(replaced_node_id)
                del entries[new_name]

            del entries[old_name]
            entries[new_name] = node_id
            self._save_directory_entries(old_parent_id, entries)
            self._touch_metadata(node_id, update_change=True)
            self._touch_metadata(old_parent_id, update_modify=True)
            self._sync_directory_node(old_parent_id)
            self._fsync_directory(self.objects_dir)
            return 0

        old_entries = self._load_directory_entries(old_parent_id)
        try:
            node_id = old_entries[old_name]
        except KeyError:
            raise FuseOSError(errno.ENOENT)

        node_metadata = self._load_metadata(node_id)
        if node_metadata["type"] == "dir" and self._is_descendant(node_id, new_parent_id):
            raise FuseOSError(errno.EINVAL)

        new_entries = self._load_directory_entries(new_parent_id)
        replaced_node_id = new_entries.get(new_name)
        if replaced_node_id is not None:
            if replaced_node_id == node_id:
                del old_entries[old_name]
                new_entries[new_name] = node_id
                self._save_directory_entries(old_parent_id, old_entries)
                self._save_directory_entries(new_parent_id, new_entries)
                self._touch_metadata(node_id, update_change=True)
                self._touch_metadata(old_parent_id, update_modify=True)
                self._touch_metadata(new_parent_id, update_modify=True)
                self._sync_directory_node(old_parent_id)
                self._sync_directory_node(new_parent_id)
                self._fsync_directory(self.objects_dir)
                return 0

            replaced_metadata = self._load_metadata(replaced_node_id)
            if node_metadata["type"] == "file" and replaced_metadata["type"] == "dir":
                raise FuseOSError(errno.EISDIR)
            if node_metadata["type"] == "dir" and replaced_metadata["type"] == "file":
                raise FuseOSError(errno.ENOTDIR)
            if replaced_metadata["type"] == "dir" and self._load_directory_entries(replaced_node_id):
                raise FuseOSError(errno.ENOTEMPTY)
            if replaced_metadata["type"] == "file":
                self._secure_wipe_blob(replaced_node_id)

            self._remove_node(replaced_node_id)
            del new_entries[new_name]

        del old_entries[old_name]
        new_entries[new_name] = node_id
        self._save_directory_entries(old_parent_id, old_entries)
        self._save_directory_entries(new_parent_id, new_entries)
        self._touch_metadata(node_id, update_change=True)
        self._touch_metadata(old_parent_id, update_modify=True)
        self._touch_metadata(new_parent_id, update_modify=True)
        self._sync_directory_node(old_parent_id)
        self._sync_directory_node(new_parent_id)
        self._fsync_directory(self.objects_dir)
        return 0

    # File operations

    def open(self, path, flags):
        log.debug("open %s (flags=%o)", path, flags)
        node_id, metadata = self._resolve_path(path)
        if metadata["type"] != "file":
            raise FuseOSError(errno.EISDIR)
        return os.open(self._blob_path(node_id), flags)

    def read(self, path, size, offset, fh):
        log.debug("read %s (size=%d, offset=%d)", path, size, offset)
        node_id, metadata = self._resolve_path(path)
        if metadata["type"] != "file":
            raise FuseOSError(errno.EISDIR)

        plaintext = self._load_file_data(node_id)
        self._touch_metadata(node_id, update_access=True)

        return plaintext[offset : offset + size]

    def write(self, path, data, offset, fh):
        log.debug("write %s (size=%d, offset=%d)", path, len(data), offset)
        node_id, metadata = self._resolve_path(path)
        if metadata["type"] != "file":
            raise FuseOSError(errno.EISDIR)

        try:
            plaintext = self._load_file_data(node_id)
            if offset > len(plaintext):
                plaintext += b"\x00" * (offset - len(plaintext))

            plaintext = plaintext[:offset] + data + plaintext[offset + len(data):]

            self._save_file_data(node_id, plaintext)
            self._touch_metadata(node_id, update_access=True, update_modify=True)

            return len(data)

        except FuseOSError:
            raise
        except InvalidTag:
            raise FuseOSError(errno.EACCES)
        except Exception:
            raise FuseOSError(errno.EIO)

    def truncate(self, path, length, fh=None):
        log.debug("truncate %s (length=%d)", path, length)
        node_id, metadata = self._resolve_path(path)
        if metadata["type"] != "file":
            raise FuseOSError(errno.EISDIR)

        try:
            plaintext = self._load_file_data(node_id)

            plaintext = plaintext[:length] + b"\x00" * max(0, length - len(plaintext))

            self._save_file_data(node_id, plaintext)
            self._touch_metadata(node_id, update_modify=True)

        except InvalidTag:
            raise FuseOSError(errno.EACCES)
        except Exception:
            raise FuseOSError(errno.EIO)

    def utimens(self, path, times=None):
        log.debug("utimens %s", path)
        node_id, _ = self._resolve_path(path)
        metadata = self._load_metadata(node_id)

        if times is None:
            now = time.time()
            atime = now
            mtime = now
        else:
            atime, mtime = times

        metadata["atime"] = atime
        metadata["mtime"] = mtime
        metadata["ctime"] = time.time()
        self._save_metadata(node_id, metadata)
        return 0

    def getxattr(self, path, name, position=0):
        raise FuseOSError(errno.ENOTSUP)

    def listxattr(self, path):
        return []

    def release(self, path, fh):
        log.debug("release %s", path)
        os.close(fh)


def main(mountpoint, backend, password):
    os.makedirs(backend, exist_ok=True)
    log.info("Mounting at %s", mountpoint)
    FUSE(FuseFS(backend, password), mountpoint, foreground=True)
    log.info("Unmounted")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        print("Usage: python prototype.py <mountpoint> <backend> <password>")
        exit(1)

    main(sys.argv[1], sys.argv[2], sys.argv[3])
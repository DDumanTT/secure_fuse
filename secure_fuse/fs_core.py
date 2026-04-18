import errno
import logging
import os
import secrets
import stat
import time

from cryptography.exceptions import InvalidTag
from fuse import FuseOSError

from .constants import KEY_SIZE, SALT_SIZE, WIPE_CHUNK_SIZE, WIPE_PASSES
from .crypto import decrypt_bytes, decrypt_json, derive_master_key, encrypt_bytes, encrypt_json
from .storage import blob_path, fsync_directory, fsync_path, key_path, meta_path, node_path, secure_wipe_blob

log = logging.getLogger("fuse_fs")


class CoreOpsMixin:
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

    def _derive_master_key(self, password, salt):
        return derive_master_key(password, salt, key_length=KEY_SIZE)

    def _root_path(self):
        return os.path.join(self.backend, ".root")

    def _node_path(self, node_id, suffix):
        return node_path(self.objects_dir, node_id, suffix)

    def _blob_path(self, node_id):
        return blob_path(self.objects_dir, node_id)

    def _meta_path(self, node_id):
        return meta_path(self.objects_dir, node_id)

    def _key_path(self, node_id):
        return key_path(self.objects_dir, node_id)

    def _generate_node_id(self):
        return secrets.token_hex(16)

    def _encrypt_bytes(self, key, plaintext):
        return encrypt_bytes(key, plaintext)

    def _decrypt_bytes(self, key, blob):
        return decrypt_bytes(key, blob)

    def _encrypt_json(self, key, payload):
        return encrypt_json(key, payload)

    def _decrypt_json(self, key, blob):
        return decrypt_json(key, blob)

    def _load_or_create_fek(self, node_id):
        node_key_path = self._key_path(node_id)

        if os.path.exists(node_key_path):
            log.debug("Loading FEK for node %s", node_id)
            with open(node_key_path, "rb") as f:
                wrapped = f.read()
            try:
                return self._decrypt_bytes(self.master_key, wrapped)
            except InvalidTag:
                log.warning("FEK decryption failed for node %s (bad master key?)", node_id)
                raise FuseOSError(errno.EACCES)

        log.debug("Generating new FEK for node %s", node_id)
        fek = secrets.token_bytes(KEY_SIZE)
        wrapped = self._encrypt_bytes(self.master_key, fek)

        with open(node_key_path, "wb") as f:
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
        node_blob_path = self._blob_path(node_id)
        try:
            with open(node_blob_path, "rb") as f:
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
        secure_wipe_blob(
            self._blob_path(node_id),
            wipe_passes=WIPE_PASSES,
            wipe_chunk_size=WIPE_CHUNK_SIZE,
            logger=log,
        )

    def _fsync_path(self, path):
        fsync_path(path)

    def _fsync_directory(self, path):
        fsync_directory(path)

    def _sync_directory_node(self, node_id):
        self._fsync_path(self._blob_path(node_id))
        self._fsync_path(self._meta_path(node_id))

    def _remove_node(self, node_id):
        for suffix in (".key", ".blob", ".meta"):
            try:
                os.unlink(self._node_path(node_id, suffix))
            except FileNotFoundError:
                pass

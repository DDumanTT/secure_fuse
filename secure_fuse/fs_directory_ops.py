import errno
import logging
import os
from typing import TYPE_CHECKING, Any, Protocol

from fuse import FuseOSError

from .constants import GCM_TAG_SIZE, NONCE_SIZE

if TYPE_CHECKING:
    from .audit import AuditLogger

log = logging.getLogger("fuse_fs")


class _DirCoreProtocol(Protocol):
    objects_dir: str
    audit: "AuditLogger"

    def _resolve_path(self, path: str) -> tuple[str, dict[str, Any]]: ...
    def _resolve_parent(self, path: str) -> tuple[str, dict[str, Any], str]: ...
    def _blob_path(self, node_id: str) -> str: ...
    def _generate_node_id(self) -> str: ...
    def _create_node(self, node_id: str, node_type: str, mode: int) -> bytes: ...
    def _load_metadata(self, node_id: str) -> dict[str, Any]: ...
    def _load_directory_entries(self, node_id: str) -> dict[str, str]: ...
    def _save_directory_entries(self, node_id: str, entries: dict[str, str]) -> None: ...
    def _touch_metadata(
        self,
        node_id: str,
        *,
        update_access: bool = False,
        update_modify: bool = False,
        update_change: bool = False,
    ) -> dict[str, Any]: ...
    def _secure_wipe_blob(self, node_id: str) -> None: ...
    def _remove_node(self, node_id: str) -> None: ...
    def _sync_directory_node(self, node_id: str) -> None: ...
    def _fsync_directory(self, path: str) -> None: ...
    def _is_descendant(self, ancestor_id: str, candidate_id: str) -> bool: ...


class DirectoryOpsMixin:
    def getattr(self: _DirCoreProtocol, path, fh=None):
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

    def readdir(self: _DirCoreProtocol, path, fh):
        log.debug("readdir %s", path)
        entries = [".", ".."]

        node_id, metadata = self._resolve_path(path)
        if metadata["type"] != "dir":
            raise FuseOSError(errno.ENOTDIR)

        entries.extend(sorted(self._load_directory_entries(node_id)))

        for entry in entries:
            yield entry

    def create(self: _DirCoreProtocol, path, mode, fi=None):
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
        fh = os.open(self._blob_path(node_id), os.O_WRONLY)
        self.audit.log_event("create", path, node_id=node_id)
        return fh

    def mkdir(self: _DirCoreProtocol, path, mode):
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
        self.audit.log_event("mkdir", path, node_id=node_id)

    def unlink(self: _DirCoreProtocol, path):
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
        self.audit.log_event("unlink", path, node_id=node_id)

    def rmdir(self: _DirCoreProtocol, path):
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
        self.audit.log_event("rmdir", path, node_id=node_id)

    def rename(self: _DirCoreProtocol, old, new):
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
            self.audit.log_event("rename", old, node_id=node_id, new_path=new)
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
                self.audit.log_event("rename", old, node_id=node_id, new_path=new)
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
        self.audit.log_event("rename", old, node_id=node_id, new_path=new)
        return 0

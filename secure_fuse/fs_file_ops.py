import errno
import logging
import os
import time
from typing import Any, Protocol

from cryptography.exceptions import InvalidTag
from fuse import FuseOSError

log = logging.getLogger("fuse_fs")


class _FileCoreProtocol(Protocol):
    def _resolve_path(self, path: str) -> tuple[str, dict[str, Any]]: ...
    def _blob_path(self, node_id: str) -> str: ...
    def _load_file_data(self, node_id: str) -> bytes: ...
    def _save_file_data(self, node_id: str, plaintext: bytes) -> None: ...
    def _load_metadata(self, node_id: str) -> dict[str, Any]: ...
    def _save_metadata(self, node_id: str, metadata: dict[str, Any]) -> None: ...
    def _touch_metadata(
        self,
        node_id: str,
        *,
        update_access: bool = False,
        update_modify: bool = False,
        update_change: bool = False,
    ) -> dict[str, Any]: ...


class FileOpsMixin:
    def open(self: _FileCoreProtocol, path, flags):
        log.debug("open %s (flags=%o)", path, flags)
        node_id, metadata = self._resolve_path(path)
        if metadata["type"] != "file":
            raise FuseOSError(errno.EISDIR)
        return os.open(self._blob_path(node_id), flags)

    def read(self: _FileCoreProtocol, path, size, offset, fh):
        log.debug("read %s (size=%d, offset=%d)", path, size, offset)
        node_id, metadata = self._resolve_path(path)
        if metadata["type"] != "file":
            raise FuseOSError(errno.EISDIR)

        plaintext = self._load_file_data(node_id)
        self._touch_metadata(node_id, update_access=True)

        return plaintext[offset : offset + size]

    def write(self: _FileCoreProtocol, path, data, offset, fh):
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

    def truncate(self: _FileCoreProtocol, path, length, fh=None):
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

    def utimens(self: _FileCoreProtocol, path, times=None):
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

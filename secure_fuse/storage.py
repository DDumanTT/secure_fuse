import os
import secrets


def node_path(objects_dir, node_id, suffix):
    return os.path.join(objects_dir, f"{node_id}{suffix}")


def blob_path(objects_dir, node_id):
    return node_path(objects_dir, node_id, ".blob")


def meta_path(objects_dir, node_id):
    return node_path(objects_dir, node_id, ".meta")


def key_path(objects_dir, node_id):
    return node_path(objects_dir, node_id, ".key")


def secure_wipe_blob(blob_path, wipe_passes, wipe_chunk_size, logger=None):
    try:
        size = os.path.getsize(blob_path)
    except FileNotFoundError:
        return

    if size <= 0:
        return

    try:
        with open(blob_path, "r+b", buffering=0) as f:
            for _ in range(wipe_passes):
                f.seek(0)
                remaining = size
                while remaining > 0:
                    chunk_size = min(remaining, wipe_chunk_size)
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
        if logger is not None:
            logger.warning("Best-effort blob wipe failed for %s: %s", blob_path, exc)


def fsync_path(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def fsync_directory(path):
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

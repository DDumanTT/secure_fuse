import importlib
import errno
import os
import sys

import pytest


@pytest.fixture
def fuse_fs_module(monkeypatch):
    """Import fuse_fs using the real fuse module when available."""
    try:
        importlib.import_module("fuse")
    except Exception as exc:
        pytest.skip(f"Real fuse module is unavailable: {exc}")

    sys.modules.pop("fuse_fs", None)

    module = importlib.import_module("fuse_fs")

    # Keep tests fast and deterministic by avoiding real Argon2 work.
    monkeypatch.setattr(
        module.FuseFS,
        "_derive_master_key",
        lambda self, password, salt: b"\x11" * 32,
    )

    yield module

    sys.modules.pop("fuse_fs", None)


@pytest.fixture
def fs(tmp_path, fuse_fs_module):
    return fuse_fs_module.FuseFS(str(tmp_path), "password")


def test_derive_master_key_is_deterministic_for_same_password(fuse_fs_module, tmp_path):
    """Remounting the same backend with the same password yields the same master key."""
    backend = str(tmp_path / "fs")
    fs1 = fuse_fs_module.FuseFS(backend, "password")
    fs2 = fuse_fs_module.FuseFS(backend, "password")

    assert fs1.master_key == fs2.master_key
    assert len(fs1.master_key) == 32


def test_salt_is_persisted_across_remounts(fuse_fs_module, tmp_path):
    backend = str(tmp_path / "fs")
    fs1 = fuse_fs_module.FuseFS(backend, "password")
    salt_file = tmp_path / "fs" / ".salt"

    assert salt_file.exists()
    salt_bytes = salt_file.read_bytes()
    assert len(salt_bytes) == 16

    # Remounting must reuse the same salt file (not overwrite it).
    fs2 = fuse_fs_module.FuseFS(backend, "password")
    assert salt_file.read_bytes() == salt_bytes
    assert fs1.master_key == fs2.master_key


def test_root_node_is_persisted_across_remounts(fuse_fs_module, tmp_path):
    backend = str(tmp_path / "fs")

    fs1 = fuse_fs_module.FuseFS(backend, "password")
    fs2 = fuse_fs_module.FuseFS(backend, "password")

    assert fs1.root_id == fs2.root_id
    assert (tmp_path / "fs" / ".root").read_text(encoding="utf-8") == fs1.root_id


def test_load_or_create_fek_creates_and_reloads_same_key(fs, tmp_path):
    node_id = fs._generate_node_id()

    first = fs._load_or_create_fek(node_id)
    second = fs._load_or_create_fek(node_id)

    assert first == second
    assert len(first) == 32
    assert os.path.exists(tmp_path / "objects" / f"{node_id}.key")


def test_create_write_and_read_round_trip(fs):
    path = "/data.bin"

    fh = fs.create(path, 0o644)
    fs.release(path, fh)

    written = fs.write(path, b"hello world", 0, None)
    assert written == len(b"hello world")

    out = fs.read(path, size=5, offset=6, fh=None)
    assert out == b"world"


def test_open_returns_a_file_handle_for_existing_file(fs):
    path = "/open.bin"

    fh = fs.create(path, 0o644)
    fs.release(path, fh)

    fh = fs.open(path, os.O_RDONLY)
    fs.release(path, fh)


def test_read_returns_empty_for_empty_file(fs):
    path = "/empty.txt"

    fh = fs.create(path, 0o644)
    fs.release(path, fh)

    assert fs.read(path, size=10, offset=0, fh=None) == b""


def test_readdir_returns_directory_entries_from_encrypted_manifest(fs):
    fs.mkdir("/docs", 0o755)
    fh = fs.create("/docs/visible.txt", 0o644)
    fs.release("/docs/visible.txt", fh)

    root_entries = set(fs.readdir("/", None))
    nested_entries = set(fs.readdir("/docs", None))

    assert "." in root_entries
    assert ".." in root_entries
    assert "docs" in root_entries
    assert "visible.txt" not in root_entries

    assert "." in nested_entries
    assert ".." in nested_entries
    assert "visible.txt" in nested_entries


def test_truncate_shortens_file(fs):
    path = "/truncate.txt"

    fh = fs.create(path, 0o644)
    fs.release(path, fh)
    fs.write(path, b"hello world", 0, None)

    fs.truncate(path, 5)
    out = fs.read(path, size=100, offset=0, fh=None)
    assert out == b"hello"


def test_truncate_to_zero_clears_file(fs):
    path = "/zero.txt"

    fh = fs.create(path, 0o644)
    fs.release(path, fh)
    fs.write(path, b"data", 0, None)

    fs.truncate(path, 0)
    assert fs.read(path, size=100, offset=0, fh=None) == b""


def test_truncate_pads_with_zeros_when_extending(fs):
    path = "/pad.txt"

    fh = fs.create(path, 0o644)
    fs.release(path, fh)
    fs.write(path, b"hi", 0, None)

    fs.truncate(path, 5)
    out = fs.read(path, size=100, offset=0, fh=None)
    assert out == b"hi\x00\x00\x00"


def test_unlink_removes_all_opaque_node_files(fs, tmp_path):
    path = "/remove.me"
    fh = fs.create(path, 0o644)
    fs.release(path, fh)

    node_id, _ = fs._resolve_path(path)
    blob_file = tmp_path / "objects" / f"{node_id}.blob"
    meta_file = tmp_path / "objects" / f"{node_id}.meta"
    key_file = tmp_path / "objects" / f"{node_id}.key"

    assert blob_file.exists()
    assert meta_file.exists()
    assert key_file.exists()

    fs.unlink(path)

    assert not blob_file.exists()
    assert not meta_file.exists()
    assert not key_file.exists()


def test_write_pads_with_zeros_when_offset_exceeds_size(fs):
    path = "/sparse.bin"

    fh = fs.create(path, 0o644)
    fs.release(path, fh)

    fs.write(path, b"x", 3, None)

    assert fs.read(path, size=10, offset=0, fh=None) == b"\x00\x00\x00x"


def test_rename_moves_file_between_directories(fs):
    fs.mkdir("/src", 0o755)
    fs.mkdir("/dst", 0o755)
    fh = fs.create("/src/file.txt", 0o644)
    fs.release("/src/file.txt", fh)
    fs.write("/src/file.txt", b"moved", 0, None)

    fs.rename("/src/file.txt", "/dst/file.txt")

    assert "file.txt" not in set(fs.readdir("/src", None))
    assert "file.txt" in set(fs.readdir("/dst", None))
    assert fs.read("/dst/file.txt", size=10, offset=0, fh=None) == b"moved"


def test_rename_replaces_existing_file(fs):
    fh = fs.create("/source.txt", 0o644)
    fs.release("/source.txt", fh)
    fs.write("/source.txt", b"new", 0, None)

    fh = fs.create("/target.txt", 0o644)
    fs.release("/target.txt", fh)
    fs.write("/target.txt", b"old", 0, None)

    fs.rename("/source.txt", "/target.txt")

    assert fs.read("/target.txt", size=10, offset=0, fh=None) == b"new"
    with pytest.raises(importlib.import_module("fuse_fs").FuseOSError) as exc_info:
        fs.getattr("/source.txt")

    assert exc_info.value.errno == errno.ENOENT


def test_rename_rejects_replacing_non_empty_directory(fs, fuse_fs_module):
    fs.mkdir("/src", 0o755)
    fh = fs.create("/src/file.txt", 0o644)
    fs.release("/src/file.txt", fh)
    fs.mkdir("/dst", 0o755)
    fh = fs.create("/dst/occupied.txt", 0o644)
    fs.release("/dst/occupied.txt", fh)

    with pytest.raises(fuse_fs_module.FuseOSError) as exc_info:
        fs.rename("/src", "/dst")

    assert exc_info.value.errno == errno.ENOTEMPTY


def test_rename_rejects_moving_directory_inside_itself(fs, fuse_fs_module):
    fs.mkdir("/parent", 0o755)
    fs.mkdir("/parent/child", 0o755)

    with pytest.raises(fuse_fs_module.FuseOSError) as exc_info:
        fs.rename("/parent", "/parent/child/moved")

    assert exc_info.value.errno == errno.EINVAL


def test_utimens_updates_encrypted_metadata_timestamps(fs):
    path = "/clock.txt"

    fh = fs.create(path, 0o644)
    fs.release(path, fh)

    fs.utimens(path, (123.5, 456.5))

    attrs = fs.getattr(path)
    assert attrs["st_atime"] == 123.5
    assert attrs["st_mtime"] == 456.5


def test_backend_storage_does_not_leak_plaintext_names_or_structure(fs, tmp_path):
    fs.mkdir("/projects", 0o755)
    fs.mkdir("/projects/private", 0o755)
    fh = fs.create("/projects/private/roadmap.txt", 0o644)
    fs.release("/projects/private/roadmap.txt", fh)
    fs.write("/projects/private/roadmap.txt", b"top secret", 0, None)

    backend_names = []
    for entry in tmp_path.rglob("*"):
        relative = entry.relative_to(tmp_path)
        backend_names.append(relative.as_posix())

    joined = "\n".join(sorted(backend_names))
    assert "projects" not in joined
    assert "private" not in joined
    assert "roadmap.txt" not in joined


def test_rmdir_removes_empty_directory(fs):
    fs.mkdir("/empty", 0o755)

    fs.rmdir("/empty")

    assert "empty" not in set(fs.readdir("/", None))


def test_rmdir_rejects_non_empty_directory(fs, fuse_fs_module):
    fs.mkdir("/docs", 0o755)
    fh = fs.create("/docs/file.txt", 0o644)
    fs.release("/docs/file.txt", fh)

    with pytest.raises(fuse_fs_module.FuseOSError) as exc_info:
        fs.rmdir("/docs")

    assert exc_info.value.errno == errno.ENOTEMPTY


def test_nested_paths_round_trip(fs):
    fs.mkdir("/alpha", 0o755)
    fs.mkdir("/alpha/beta", 0o755)
    fh = fs.create("/alpha/beta/data.bin", 0o644)
    fs.release("/alpha/beta/data.bin", fh)

    fs.write("/alpha/beta/data.bin", b"payload", 0, None)

    assert fs.read("/alpha/beta/data.bin", size=7, offset=0, fh=None) == b"payload"


def test_main_creates_backend_and_invokes_fuse(monkeypatch, tmp_path, fuse_fs_module):
    calls = {}

    def fake_fuse(obj, mountpoint, foreground):
        calls["obj"] = obj
        calls["mountpoint"] = mountpoint
        calls["foreground"] = foreground

    monkeypatch.setattr(fuse_fs_module, "FUSE", fake_fuse)

    mountpoint = str(tmp_path / "mnt")
    backend = str(tmp_path / "backend")

    fuse_fs_module.main(mountpoint, backend, "pw")

    assert os.path.isdir(backend)
    assert calls["mountpoint"] == mountpoint
    assert calls["foreground"] is True
    assert isinstance(calls["obj"], fuse_fs_module.FuseFS)


def test_unlink_wipes_blob_before_removing_node(fs):
    path = "/ordered-delete.txt"
    fh = fs.create(path, 0o644)
    fs.release(path, fh)
    fs.write(path, b"data", 0, None)
    node_id, _ = fs._resolve_path(path)

    order = []
    original_remove_node = fs._remove_node

    def record_wipe(target_node_id):
        order.append(("wipe", target_node_id))

    def record_remove(target_node_id):
        order.append(("remove", target_node_id))
        return original_remove_node(target_node_id)

    fs._secure_wipe_blob = record_wipe
    fs._remove_node = record_remove

    fs.unlink(path)

    assert order[:2] == [("wipe", node_id), ("remove", node_id)]


def test_rename_same_parent_replacement_wipes_replaced_file(fs):
    fh = fs.create("/source.txt", 0o644)
    fs.release("/source.txt", fh)
    fs.write("/source.txt", b"new", 0, None)

    fh = fs.create("/target.txt", 0o644)
    fs.release("/target.txt", fh)
    fs.write("/target.txt", b"old", 0, None)

    replaced_node_id, _ = fs._resolve_path("/target.txt")
    wiped_nodes = []

    def record_wipe(node_id):
        wiped_nodes.append(node_id)

    fs._secure_wipe_blob = record_wipe

    fs.rename("/source.txt", "/target.txt")

    assert replaced_node_id in wiped_nodes


def test_rename_cross_parent_replacement_wipes_replaced_file(fs):
    fs.mkdir("/src", 0o755)
    fs.mkdir("/dst", 0o755)

    fh = fs.create("/src/file.txt", 0o644)
    fs.release("/src/file.txt", fh)
    fs.write("/src/file.txt", b"new", 0, None)

    fh = fs.create("/dst/file.txt", 0o644)
    fs.release("/dst/file.txt", fh)
    fs.write("/dst/file.txt", b"old", 0, None)

    replaced_node_id, _ = fs._resolve_path("/dst/file.txt")
    wiped_nodes = []

    def record_wipe(node_id):
        wiped_nodes.append(node_id)

    fs._secure_wipe_blob = record_wipe

    fs.rename("/src/file.txt", "/dst/file.txt")

    assert replaced_node_id in wiped_nodes


def test_rmdir_does_not_wipe_blob(fs):
    fs.mkdir("/empty", 0o755)

    def fail_if_called(_node_id):
        raise AssertionError("_secure_wipe_blob should not be called by rmdir")

    fs._secure_wipe_blob = fail_if_called

    fs.rmdir("/empty")

    assert "empty" not in set(fs.readdir("/", None))


def test_unlink_invokes_directory_sync_hooks(fs):
    fh = fs.create("/sync.txt", 0o644)
    fs.release("/sync.txt", fh)

    synced_nodes = []
    synced_dirs = []

    def record_sync_node(node_id):
        synced_nodes.append(node_id)

    def record_sync_dir(path):
        synced_dirs.append(path)

    fs._sync_directory_node = record_sync_node
    fs._fsync_directory = record_sync_dir

    fs.unlink("/sync.txt")

    assert fs.root_id in synced_nodes
    assert fs.objects_dir in synced_dirs


def test_rename_cross_parent_invokes_sync_for_both_parents(fs):
    fs.mkdir("/src", 0o755)
    fs.mkdir("/dst", 0o755)
    fh = fs.create("/src/file.txt", 0o644)
    fs.release("/src/file.txt", fh)

    src_node_id, _ = fs._resolve_path("/src")
    dst_node_id, _ = fs._resolve_path("/dst")

    synced_nodes = []
    synced_dirs = []

    def record_sync_node(node_id):
        synced_nodes.append(node_id)

    def record_sync_dir(path):
        synced_dirs.append(path)

    fs._sync_directory_node = record_sync_node
    fs._fsync_directory = record_sync_dir

    fs.rename("/src/file.txt", "/dst/file.txt")

    assert src_node_id in synced_nodes
    assert dst_node_id in synced_nodes
    assert fs.objects_dir in synced_dirs

import importlib
import errno
import json
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
        lambda self, password, keyfile_material, salt, auth_metadata: b"\x11" * 32,
    )

    yield module

    sys.modules.pop("fuse_fs", None)


@pytest.fixture
def fs(tmp_path, fuse_fs_module):
    backend = tmp_path / "backend"
    keyfile_path = tmp_path / "auth.key"
    keyfile_path.write_bytes(b"k" * 32)
    return fuse_fs_module.FuseFS(str(backend), "password", str(keyfile_path))


def test_derive_master_key_is_deterministic_for_same_password(fuse_fs_module, tmp_path):
    """Remounting the same backend with the same password yields the same master key."""
    backend = str(tmp_path / "fs")
    keyfile = tmp_path / "auth.key"
    keyfile.write_bytes(b"k" * 32)
    fs1 = fuse_fs_module.FuseFS(backend, "password", str(keyfile))
    fs2 = fuse_fs_module.FuseFS(backend, "password", str(keyfile))

    assert fs1.master_key == fs2.master_key
    assert len(fs1.master_key) == 32


def test_salt_is_persisted_across_remounts(fuse_fs_module, tmp_path):
    backend = str(tmp_path / "fs")
    keyfile = tmp_path / "auth.key"
    keyfile.write_bytes(b"k" * 32)
    fs1 = fuse_fs_module.FuseFS(backend, "password", str(keyfile))
    salt_file = tmp_path / "fs" / ".salt"

    assert salt_file.exists()
    salt_bytes = salt_file.read_bytes()
    assert len(salt_bytes) == 32

    # Remounting must reuse the same salt file (not overwrite it).
    fs2 = fuse_fs_module.FuseFS(backend, "password", str(keyfile))
    assert salt_file.read_bytes() == salt_bytes
    assert fs1.master_key == fs2.master_key


def test_root_node_is_persisted_across_remounts(fuse_fs_module, tmp_path):
    backend = str(tmp_path / "fs")
    keyfile = tmp_path / "auth.key"
    keyfile.write_bytes(b"k" * 32)

    fs1 = fuse_fs_module.FuseFS(backend, "password", str(keyfile))
    fs2 = fuse_fs_module.FuseFS(backend, "password", str(keyfile))

    assert fs1.root_id == fs2.root_id
    assert (tmp_path / "fs" / ".root").read_text(encoding="utf-8") == fs1.root_id


def test_load_or_create_fek_creates_and_reloads_same_key(fs, tmp_path):
    node_id = fs._generate_node_id()

    first = fs._load_or_create_fek(node_id)
    second = fs._load_or_create_fek(node_id)

    assert first == second
    assert len(first) == 32
    assert os.path.exists(fs.objects_dir + f"/{node_id}.key")


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
    blob_file = os.path.join(fs.objects_dir, f"{node_id}.blob")
    meta_file = os.path.join(fs.objects_dir, f"{node_id}.meta")
    key_file = os.path.join(fs.objects_dir, f"{node_id}.key")

    assert os.path.exists(blob_file)
    assert os.path.exists(meta_file)
    assert os.path.exists(key_file)

    fs.unlink(path)

    assert not os.path.exists(blob_file)
    assert not os.path.exists(meta_file)
    assert not os.path.exists(key_file)


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
    keyfile = tmp_path / "auth.key"
    keyfile.write_bytes(b"k" * 32)

    fuse_fs_module.main(mountpoint, backend, "pw", str(keyfile))

    assert os.path.isdir(backend)
    assert calls["mountpoint"] == mountpoint
    assert calls["foreground"] is True
    assert isinstance(calls["obj"], fuse_fs_module.FuseFS)


# ---------------------------------------------------------------------------
# Phase 1: AES-GCM AAD binding — blob swaps between nodes must be rejected
# ---------------------------------------------------------------------------

def test_aad_binding_blob_swap_between_nodes_raises_eacces(fs, fuse_fs_module):
    """Swapping .blob files between two file nodes must cause EACCES on read."""
    fh1 = fs.create("/a.bin", 0o644)
    fs.release("/a.bin", fh1)
    fs.write("/a.bin", b"aaa", 0, None)

    fh2 = fs.create("/b.bin", 0o644)
    fs.release("/b.bin", fh2)
    fs.write("/b.bin", b"bbb", 0, None)

    node_a, _ = fs._resolve_path("/a.bin")
    node_b, _ = fs._resolve_path("/b.bin")

    # Swap the raw .blob files on disk
    blob_a = os.path.join(fs.objects_dir, f"{node_a}.blob")
    blob_b = os.path.join(fs.objects_dir, f"{node_b}.blob")
    blob_a_data = open(blob_a, "rb").read()
    blob_b_data = open(blob_b, "rb").read()
    open(blob_a, "wb").write(blob_b_data)
    open(blob_b, "wb").write(blob_a_data)

    with pytest.raises(fuse_fs_module.FuseOSError) as exc:
        fs.read("/a.bin", 100, 0, None)
    assert exc.value.errno == errno.EACCES


def test_aad_binding_meta_swap_between_nodes_raises_eacces(fs, fuse_fs_module):
    """Swapping .meta files between two nodes must cause EACCES on getattr."""
    fh1 = fs.create("/x.bin", 0o644)
    fs.release("/x.bin", fh1)
    fh2 = fs.create("/y.bin", 0o644)
    fs.release("/y.bin", fh2)

    node_x, _ = fs._resolve_path("/x.bin")
    node_y, _ = fs._resolve_path("/y.bin")

    meta_x = os.path.join(fs.objects_dir, f"{node_x}.meta")
    meta_y = os.path.join(fs.objects_dir, f"{node_y}.meta")
    meta_x_data = open(meta_x, "rb").read()
    meta_y_data = open(meta_y, "rb").read()
    open(meta_x, "wb").write(meta_y_data)
    open(meta_y, "wb").write(meta_x_data)

    with pytest.raises(fuse_fs_module.FuseOSError) as exc:
        fs.getattr("/x.bin")
    assert exc.value.errno == errno.EACCES


# ---------------------------------------------------------------------------
# Phase 2: backend control file MAC integrity
# ---------------------------------------------------------------------------

def test_tampered_auth_file_raises_eacces_on_remount(fuse_fs_module, tmp_path):
    backend = str(tmp_path / "fs")
    keyfile = tmp_path / "auth.key"
    keyfile.write_bytes(b"k" * 32)
    # Create a fresh filesystem (writes .auth and .auth.mac)
    fuse_fs_module.FuseFS(backend, "password", str(keyfile))

    # Tamper with the .auth file
    auth_file = tmp_path / "fs" / ".auth"
    content = auth_file.read_text(encoding="utf-8")
    tampered = content.replace('"version": 1', '"version": 2')
    auth_file.write_text(tampered, encoding="utf-8")

    with pytest.raises(fuse_fs_module.FuseOSError) as exc:
        fuse_fs_module.FuseFS(backend, "password", str(keyfile))
    assert exc.value.errno == errno.EACCES


def test_tampered_root_file_raises_eacces_on_remount(fuse_fs_module, tmp_path):
    backend = str(tmp_path / "fs")
    keyfile = tmp_path / "auth.key"
    keyfile.write_bytes(b"k" * 32)
    fuse_fs_module.FuseFS(backend, "password", str(keyfile))

    # Tamper with the .root file
    root_file = tmp_path / "fs" / ".root"
    root_file.write_text("000000000000000000000000000000000000", encoding="utf-8")

    with pytest.raises(fuse_fs_module.FuseOSError) as exc:
        fuse_fs_module.FuseFS(backend, "password", str(keyfile))
    assert exc.value.errno == errno.EACCES


# ---------------------------------------------------------------------------
# Phase 3: open() flag enforcement
# ---------------------------------------------------------------------------

def test_write_to_rdonly_handle_raises_ebadf(fs, fuse_fs_module):
    fh = fs.create("/rdonly.txt", 0o644)
    fs.release("/rdonly.txt", fh)

    fh = fs.open("/rdonly.txt", os.O_RDONLY)
    try:
        with pytest.raises(fuse_fs_module.FuseOSError) as exc:
            fs.write("/rdonly.txt", b"data", 0, fh)
        assert exc.value.errno == errno.EBADF
    finally:
        fs.release("/rdonly.txt", fh)


def test_read_via_wronly_handle_raises_ebadf(fs, fuse_fs_module):
    fh_create = fs.create("/wronly.txt", 0o644)
    fs.release("/wronly.txt", fh_create)

    fh = fs.open("/wronly.txt", os.O_WRONLY)
    try:
        with pytest.raises(fuse_fs_module.FuseOSError) as exc:
            fs.read("/wronly.txt", 10, 0, fh)
        assert exc.value.errno == errno.EBADF
    finally:
        fs.release("/wronly.txt", fh)


# ---------------------------------------------------------------------------
# Phase 5: Merkle tree audit log
# ---------------------------------------------------------------------------

def test_audit_log_created_after_create_and_unlink(fs, tmp_path):
    fh = fs.create("/audited.txt", 0o644)
    fs.release("/audited.txt", fh)
    fs.unlink("/audited.txt")

    log_path = tmp_path / "backend" / "audit.log"
    assert log_path.exists()
    lines = [json.loads(l) for l in log_path.read_text().splitlines() if l]
    ops = [e["op"] for e in lines]
    assert "create" in ops
    assert "unlink" in ops
    for entry in lines:
        assert "ts" in entry
        assert "leaf_hash" in entry
        assert "path" in entry


def test_audit_verify_returns_true_on_untampered_log(fs, tmp_path):
    fh = fs.create("/verify.txt", 0o644)
    fs.release("/verify.txt", fh)
    fs.write("/verify.txt", b"hello", 0, None)

    assert fs.audit.verify() is True


def test_audit_verify_returns_false_after_log_entry_mutation(fs, tmp_path):
    fh = fs.create("/tamper.txt", 0o644)
    fs.release("/tamper.txt", fh)

    log_path = tmp_path / "backend" / "audit.log"
    content = log_path.read_text()
    # Corrupt the first character of the first line
    corrupted = "X" + content[1:]
    log_path.write_text(corrupted)

    assert fs.audit.verify() is False


def test_audit_verify_returns_false_after_entry_deletion(fs, tmp_path):
    fh = fs.create("/del1.txt", 0o644)
    fs.release("/del1.txt", fh)
    fh = fs.create("/del2.txt", 0o644)
    fs.release("/del2.txt", fh)

    log_path = tmp_path / "backend" / "audit.log"
    lines = log_path.read_text().splitlines()
    # Remove the first entry
    log_path.write_text("\n".join(lines[1:]) + "\n")

    assert fs.audit.verify() is False


def test_audit_root_tamper_raises_on_remount(fuse_fs_module, tmp_path):
    backend = str(tmp_path / "fs")
    keyfile = tmp_path / "auth.key"
    keyfile.write_bytes(b"k" * 32)
    fs = fuse_fs_module.FuseFS(backend, "password", str(keyfile))
    fh = fs.create("/x.txt", 0o644)
    fs.release("/x.txt", fh)

    # Corrupt the Merkle root MAC
    root_mac = tmp_path / "fs" / ".audit_root"
    root_mac.write_bytes(b"\x00" * 32)

    with pytest.raises(RuntimeError):
        fuse_fs_module.FuseFS(backend, "password", str(keyfile))


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


def test_backend_auth_metadata_is_created_for_new_backend(fuse_fs_module, tmp_path):
    backend = tmp_path / "fs"
    keyfile = tmp_path / "auth.key"
    keyfile.write_bytes(b"k" * 32)

    fuse_fs_module.FuseFS(str(backend), "password", str(keyfile))

    auth_payload = json.loads((backend / ".auth").read_text(encoding="utf-8"))
    assert auth_payload["mode"] == "password_keyfile"
    assert auth_payload["version"] == 1


def test_existing_backend_without_auth_metadata_is_rejected(fuse_fs_module, tmp_path):
    backend = tmp_path / "fs"
    objects_dir = backend / "objects"
    backend.mkdir()
    objects_dir.mkdir()
    (backend / ".salt").write_bytes(b"s" * 16)
    (backend / ".root").write_text("deadbeef", encoding="utf-8")

    keyfile = tmp_path / "auth.key"
    keyfile.write_bytes(b"k" * 32)

    with pytest.raises(fuse_fs_module.FuseOSError) as exc_info:
        fuse_fs_module.FuseFS(str(backend), "password", str(keyfile))

    assert exc_info.value.errno == errno.EACCES


def test_missing_keyfile_is_rejected(fuse_fs_module, tmp_path):
    with pytest.raises(fuse_fs_module.FuseOSError) as exc_info:
        fuse_fs_module.FuseFS(str(tmp_path / "fs"), "password", str(tmp_path / "missing.key"))

    assert exc_info.value.errno == errno.EACCES


def test_small_keyfile_is_rejected(fuse_fs_module, tmp_path):
    keyfile = tmp_path / "small.key"
    keyfile.write_bytes(b"tiny")

    with pytest.raises(fuse_fs_module.FuseOSError) as exc_info:
        fuse_fs_module.FuseFS(str(tmp_path / "fs"), "password", str(keyfile))

    assert exc_info.value.errno == errno.EACCES

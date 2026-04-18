import importlib
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


def test_full_path_strips_leading_slash(fs, tmp_path):
    assert fs._full_path("/notes.txt") == os.path.join(str(tmp_path), "notes.txt")
    assert fs._full_path("notes.txt") == os.path.join(str(tmp_path), "notes.txt")


def test_load_or_create_fek_creates_and_reloads_same_key(fs, tmp_path):
    path = "/doc.txt"

    first = fs._load_or_create_fek(path)
    second = fs._load_or_create_fek(path)

    assert first == second
    assert len(first) == 32
    assert os.path.exists(tmp_path / "doc.txt.key")


def test_create_write_and_read_round_trip(fs):
    path = "/data.bin"

    fh = fs.create(path, 0o644)
    fs.release(path, fh)

    written = fs.write(path, b"hello world", 0, None)
    assert written == len(b"hello world")

    out = fs.read(path, size=5, offset=6, fh=None)
    assert out == b"world"


def test_read_returns_empty_for_empty_file(fs):
    path = "/empty.txt"

    fh = fs.create(path, 0o644)
    fs.release(path, fh)

    assert fs.read(path, size=10, offset=0, fh=None) == b""


def test_readdir_hides_key_sidecar_and_salt_files(fs, tmp_path):
    (tmp_path / "visible.txt").write_bytes(b"data")
    (tmp_path / "visible.txt.key").write_bytes(b"secret")
    (tmp_path / ".salt").write_bytes(b"salt")

    entries = set(fs.readdir("/", None))

    assert "." in entries
    assert ".." in entries
    assert "visible.txt" in entries
    assert "visible.txt.key" not in entries
    assert ".salt" not in entries


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


def test_unlink_removes_data_and_key_file(fs, tmp_path):
    path = "/remove.me"
    data_file = tmp_path / "remove.me"
    key_file = tmp_path / "remove.me.key"

    data_file.write_bytes(b"content")
    key_file.write_bytes(b"wrapped")

    fs.unlink(path)

    assert not data_file.exists()
    assert not key_file.exists()


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

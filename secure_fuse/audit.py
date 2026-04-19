"""Merkle-tree-backed audit log for secure_fuse.

Log entries are written as JSON lines to ``backend/audit.log``.  Each entry
is a leaf in an incremental binary Merkle tree (RFC 6962 / Certificate
Transparency algorithm).  The Merkle root is committed via an HMAC-SHA256
keyed with the filesystem master key and stored in ``backend/.audit_root``.
The running peak stack is persisted in ``backend/.audit_tree`` so the root can
be recomputed without re-reading the whole log on every operation.

On initialisation the root MAC is verified before any filesystem operation
executes.  Tampering with any log entry, removing entries, or forging the root
MAC without the master key are all detectable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import struct
from datetime import datetime, timezone

log = logging.getLogger("fuse_fs")

_HASH_SIZE = 32  # SHA-256 output bytes


# ---------------------------------------------------------------------------
# RFC 6962 incremental Merkle tree
# ---------------------------------------------------------------------------

def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _combine(left: bytes, right: bytes) -> bytes:
    """RFC 6962 parent hash: SHA256(0x01 || left || right)."""
    return _sha256(b"\x01" + left + right)


class MerkleTree:
    """Incremental binary Merkle tree (RFC 6962 peak-stack algorithm).

    Maintains at most ``ceil(log2(n))`` peak hashes in memory.  Each call to
    ``append_leaf`` is O(log n) without storing the full tree.
    """

    def __init__(self, peaks: list[bytes] | None = None) -> None:
        # peaks[i] represents a complete subtree of size 2**i when set.
        # We store them as a flat list where index corresponds to bit position.
        self._peaks: list[bytes] = list(peaks) if peaks else []

    # ------------------------------------------------------------------
    # Serialisation helpers (used by AuditLogger to persist .audit_tree)
    # ------------------------------------------------------------------

    def serialise(self) -> bytes:
        count = len(self._peaks)
        header = struct.pack(">I", count)
        return header + b"".join(
            (b"\x01" + p) if p else b"\x00" + b"\x00" * _HASH_SIZE
            for p in self._peaks
        )

    @classmethod
    def deserialise(cls, data: bytes) -> "MerkleTree":
        if len(data) < 4:
            return cls()
        (count,) = struct.unpack_from(">I", data, 0)
        offset = 4
        slot_size = 1 + _HASH_SIZE
        peaks: list[bytes] = []
        for _ in range(count):
            if offset + slot_size > len(data):
                break
            present = data[offset]
            hash_bytes = data[offset + 1 : offset + slot_size]
            peaks.append(hash_bytes if present else b"")
            offset += slot_size
        return cls(peaks)

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def append_leaf(self, leaf_hash: bytes) -> None:
        """Append a new leaf and update internal peak stack."""
        carry = leaf_hash
        for i in range(len(self._peaks)):
            existing = self._peaks[i]
            if existing:
                carry = _combine(existing, carry)
                self._peaks[i] = b""
            else:
                self._peaks[i] = carry
                return
        self._peaks.append(carry)

    def root(self) -> bytes:
        """Compute the current Merkle root from peaks.

        Returns the SHA-256 of the empty string for an empty tree.
        """
        result: bytes | None = None
        for peak in self._peaks:
            if not peak:
                continue
            result = _combine(peak, result) if result else peak
        return result if result else _sha256(b"")

    @property
    def size(self) -> int:
        """Number of leaves appended so far (derived from peak bitmask)."""
        total = 0
        for i, p in enumerate(self._peaks):
            if p:
                total += 1 << i
        return total


# ---------------------------------------------------------------------------
# Audit logger
# ---------------------------------------------------------------------------

class AuditLogger:
    """Append-only Merkle-tree-backed audit logger.

    Files written to ``backend_path``:
    - ``audit.log``    – newline-delimited JSON entries
    - ``.audit_tree``  – serialised Merkle peak stack
    - ``.audit_root``  – HMAC-SHA256(master_key, merkle_root)

    Raises ``RuntimeError`` on construction if the stored root MAC does not
    match the recomputed root, indicating tampering.
    """

    LOG_FILE = "audit.log"
    TREE_FILE = ".audit_tree"
    ROOT_FILE = ".audit_root"

    def __init__(self, backend_path: str, master_key: bytes) -> None:
        self._backend = backend_path
        self._key = master_key
        self._log_path = os.path.join(backend_path, self.LOG_FILE)
        self._tree_path = os.path.join(backend_path, self.TREE_FILE)
        self._root_path = os.path.join(backend_path, self.ROOT_FILE)

        self._tree = self._load_tree()

        # Verify the stored root MAC against the loaded peaks.
        if os.path.exists(self._root_path):
            self._verify_root_mac()

        # Open log file in append mode (line-buffered text).
        self._log_fh = open(self._log_path, "a", encoding="utf-8", buffering=1)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def log_event(
        self,
        op: str,
        path: str,
        *,
        node_id: str | None = None,
        outcome: str = "ok",
        **extra,
    ) -> None:
        """Write one audit entry and update the Merkle tree + root MAC."""
        try:
            from fuse import fuse_get_context
            uid, gid, pid = fuse_get_context()
        except Exception:
            uid = gid = pid = -1

        entry: dict = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "op": op,
            "path": path,
            "node_id": node_id,
            "uid": uid,
            "gid": gid,
            "pid": pid,
            "outcome": outcome,
        }
        entry.update(extra)

        entry_bytes = json.dumps(entry, separators=(",", ":")).encode("utf-8")
        leaf_hash = _sha256(entry_bytes)
        entry["leaf_hash"] = leaf_hash.hex()

        line = json.dumps(entry, separators=(",", ":"))
        self._log_fh.write(line + "\n")
        self._log_fh.flush()

        self._tree.append_leaf(leaf_hash)
        self._persist_tree()
        self._persist_root_mac()

    def verify(self) -> bool:
        """Re-read every log line, rebuild the Merkle tree, compare root MAC.

        Returns True if the log is intact, False if any tampering is detected.
        """
        rebuilt = MerkleTree()
        try:
            with open(self._log_path, "r", encoding="utf-8") as f:
                for raw_line in f:
                    raw_line = raw_line.rstrip("\n")
                    if not raw_line:
                        continue
                    entry = json.loads(raw_line)
                    stored_hex = entry.pop("leaf_hash", None)
                    if stored_hex is None:
                        return False
                    entry_bytes = json.dumps(entry, separators=(",", ":")).encode("utf-8")
                    computed = _sha256(entry_bytes)
                    if computed.hex() != stored_hex:
                        return False
                    rebuilt.append_leaf(computed)
        except (FileNotFoundError, json.JSONDecodeError):
            return False

        expected_mac = _compute_root_mac(self._key, rebuilt.root())
        try:
            with open(self._root_path, "rb") as f:
                stored_mac = f.read()
        except FileNotFoundError:
            return False

        return hmac.compare_digest(expected_mac, stored_mac)

    def close(self) -> None:
        self._log_fh.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_tree(self) -> MerkleTree:
        try:
            with open(self._tree_path, "rb") as f:
                return MerkleTree.deserialise(f.read())
        except FileNotFoundError:
            return MerkleTree()

    def _persist_tree(self) -> None:
        with open(self._tree_path, "wb") as f:
            f.write(self._tree.serialise())

    def _persist_root_mac(self) -> None:
        mac = _compute_root_mac(self._key, self._tree.root())
        with open(self._root_path, "wb") as f:
            f.write(mac)

    def _verify_root_mac(self) -> None:
        with open(self._root_path, "rb") as f:
            stored_mac = f.read()
        expected_mac = _compute_root_mac(self._key, self._tree.root())
        if not hmac.compare_digest(expected_mac, stored_mac):
            log.error("Audit log root MAC verification failed — log may have been tampered")
            raise RuntimeError("Audit log integrity check failed")


def _compute_root_mac(key: bytes, root: bytes) -> bytes:
    return hmac.new(key, root, "sha256").digest()

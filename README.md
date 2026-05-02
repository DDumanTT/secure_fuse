# secure_fuse

An encrypted userspace filesystem built on FUSE. All file content, metadata, and directory structure are encrypted at rest using AES-256-GCM. An observer with full access to the backend directory cannot determine filenames, directory hierarchy, or file contents without the correct password and keyfile.

## Features

- **Transparent AES-256-GCM encryption** of all files and metadata
- **Two-factor authentication** — password and keyfile are both required
- **Hidden directory structure** — filenames and paths are stored only in encrypted manifests
- **Per-node File Encryption Keys (FEKs)** wrapped by a master key
- **Memory-hard key derivation** via Argon2id (64 MB, 3 iterations, 4 lanes)
- **Append-only Merkle tree audit log** for tamper-evident operation history
- **Inclusion certificates** — export and offline-verify individual audit entries
- **Secure deletion** — blob overwrite before removal
- **Integrity protection** on all control files via HMAC-SHA256

## Requirements

- Python 3.7+
- FUSE kernel support
  - Linux: `sudo apt install fuse` (Debian/Ubuntu) or equivalent
  - macOS: install [macFUSE](https://osxfuse.github.io/)

```bash
pip install fusepy cryptography
```

## Quick Start

**1. Generate a keyfile** (minimum 32 bytes):

```bash
head -c 64 /dev/urandom > my.key
chmod 600 my.key
```

**2. Mount** (initialises a new backend on first use):

```bash
./fuse_fs.py mount ./mount/ ./backend/ --keyfile my.key
```

You will be prompted for a password interactively. The password is never passed as a command-line argument.

**3. Use the filesystem** normally through `./mount/`. Unmount with Ctrl+C or:

```bash
fusermount -u ./mount/
```

## CLI Reference

All commands prompt for a password interactively. The `--keyfile` flag is required for every command.

---

### `mount` — Mount the encrypted filesystem

```bash
./fuse_fs.py mount <mountpoint> <backend> --keyfile <path>
# Short form (no subcommand):
./fuse_fs.py <mountpoint> <backend> --keyfile <path>
```

| Argument | Description |
|---|---|
| `mountpoint` | Directory where the virtual filesystem will appear |
| `backend` | Directory where encrypted objects are persisted |
| `--keyfile <path>` | Path to keyfile (≥ 32 bytes of random data) |

First run initialises the backend. Subsequent mounts require the same password and keyfile.

---

### `audit-log` — Decrypt and view the audit log

```bash
./fuse_fs.py audit-log <backend> --keyfile <path>
```

Decrypts `audit.log`, verifies the Merkle root MAC, and prints every entry as NDJSON (one JSON object per line). Exits with an error if tampering is detected.

Example output:

```
{"ts":"2026-05-02T14:30:45.123456+00:00","op":"create","path":"/notes.txt","node_id":"a3f1...","uid":1000,"gid":1000,"pid":12345,"outcome":"ok"}
{"ts":"2026-05-02T14:30:46.234567+00:00","op":"write","path":"/notes.txt","node_id":"a3f1...","uid":1000,"gid":1000,"pid":12345,"outcome":"ok","size":128,"offset":0}
```

---

### `audit-export` — Export a Merkle inclusion certificate

```bash
./fuse_fs.py audit-export <backend> <leaf_index> --keyfile <path> [--output <file>]
```

| Argument | Description |
|---|---|
| `backend` | Backend directory |
| `leaf_index` | 0-based index of the audit entry to certify |
| `--keyfile <path>` | Path to keyfile |
| `--output <file>` | Write certificate to this file (default: stdout) |

The certificate is a JSON document containing the entry payload, leaf hash, Merkle root, root HMAC, and the Merkle proof path. It can be verified offline without access to the live backend.

```bash
./fuse_fs.py audit-export ./backend/ 0 --keyfile my.key --output cert.json
```

---

### `audit-verify` — Verify a Merkle inclusion certificate

```bash
./fuse_fs.py audit-verify <backend> <certificate> --keyfile <path>
```

| Argument | Description |
|---|---|
| `backend` | Backend directory |
| `certificate` | Path to certificate JSON file |
| `--keyfile <path>` | Path to keyfile |

Recomputes the leaf hash from the entry payload, applies the proof path, validates the resulting Merkle root against the stored HMAC, and prints `valid` (exit 0) or `invalid` (exit 1).

```bash
./fuse_fs.py audit-verify ./backend/ cert.json --keyfile my.key
valid
```

---

## Security Model

### Two-Factor Authentication

Authentication requires **both** a password (entered interactively) and a keyfile (a file with at least 32 bytes of random data). Neither alone is sufficient.

### Key Derivation

The master key is derived with Argon2id:

```
master_key = Argon2id(
  input    = password || keyfile_bytes,
  salt     = 32 random bytes (stored in backend),
  t_cost   = 3 iterations,
  m_cost   = 65 536 KiB  (64 MB),
  p_cost   = 4 lanes
)
```

KDF parameters are stored in `.auth` on first initialisation and re-read on every remount, so existing backends are unaffected by changes to the defaults in source.

### Encryption

Every filesystem node (file or directory) has its own random **File Encryption Key (FEK)**. The FEK is wrapped with the master key and stored as `<node_id>.key`. All blobs and metadata are encrypted with the FEK using AES-256-GCM:

```
ciphertext = nonce (12 B) || AES-256-GCM(FEK, plaintext, aad=node_id) || tag (16 B)
```

Using `node_id` as Additional Authenticated Data (AAD) binds each ciphertext to its node, preventing blob-swap attacks.

### Control File Integrity

`.auth`, `.root`, and `.audit_root` are protected by `HMAC-SHA256(master_key, file_contents)`. Any modification to these files is detected on mount and results in `EACCES`.

### Audit Log

All mutating operations (`create`, `write`, `truncate`, `mkdir`, `unlink`, `rmdir`, `rename`) are recorded in an append-only, AES-256-GCM-encrypted `audit.log`. The log is backed by an incremental RFC 6962 Merkle tree; the tree root is committed with an HMAC so the log cannot be silently truncated, reordered, or modified.

### Secure Deletion

On `unlink` or `rmdir`, blob files are overwritten with random bytes (configurable passes) and `fsync`-ed before being removed. Note: this is most effective on HDDs; SSD wear-levelling may preserve data in remapped blocks.

---

## Backend Layout

```
backend/
├── .auth              # JSON: KDF parameters and auth version
├── .auth.mac          # HMAC-SHA256(master_key, .auth)
├── .salt              # 32 random bytes (written once)
├── .root              # Hex node ID of the root directory
├── .root.mac          # HMAC-SHA256(master_key, .root)
├── audit.log          # Encrypted, append-only audit entries (NDJSON hex lines)
├── .audit_tree        # Serialised Merkle peak stack
├── .audit_root        # HMAC-SHA256(master_key, merkle_root)
└── objects/
    ├── <node_id>.blob  # Encrypted file content or directory manifest
    ├── <node_id>.meta  # Encrypted stat metadata (mode, uid, gid, times, …)
    ├── <node_id>.key   # FEK wrapped with master key
    └── …
```

Filenames, paths, and directory hierarchy are never visible in the backend. All naming information lives inside the encrypted directory blobs.

---

## Configuration Constants

Defaults are in `secure_fuse/constants.py`. Most constants must not be changed after a backend is initialised.

| Constant | Default | Description |
|---|---|---|
| `KDF_ITERATIONS` | 3 | Argon2id time cost |
| `KDF_MEMORY_COST` | 65536 | Argon2id memory cost (KiB) |
| `KDF_LANES` | 4 | Argon2id parallelism |
| `MIN_KEYFILE_SIZE` | 32 | Minimum keyfile size (bytes) |
| `WIPE_PASSES` | 1 | Overwrite iterations on delete |
| `WIPE_CHUNK_SIZE` | 65536 | I/O chunk size for wipe (bytes) |
| `KEY_SIZE` | 32 | AES key size (bytes) |
| `NONCE_SIZE` | 12 | GCM nonce size (bytes) |
| `SALT_SIZE` | 32 | KDF salt size (bytes) |

`WIPE_PASSES`, `WIPE_CHUNK_SIZE`, and `MIN_KEYFILE_SIZE` can be changed without affecting existing backends. All other constants are fixed once a backend is created.

---

## Implementation Notes

- **Full-blob I/O:** Every read or write decrypts or re-encrypts the entire file blob. This keeps the implementation simple and correct at the cost of performance on large files.
- **No partial decryption:** AES-256-GCM requires the full ciphertext to verify the tag, so random-access within a file is not supported without decrypting the whole blob.
- **Reported file size:** `getattr` subtracts the 28-byte overhead (12-byte nonce + 16-byte tag) from the blob size to report the plaintext length.
- **Backends without `.auth`** are rejected — the filesystem will not mount an uninitialised or foreign backend.

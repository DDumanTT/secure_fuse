# secure_fuse

```bash
pip install fusepy
pip install cryptography
```

## Mounting

Authentication is two-factor: password + keyfile.

```bash
./fuse_fs.py <mountpoint> <backend> --keyfile <path-to-keyfile>
```

The password is requested interactively at runtime and is never passed in argv.

Use a keyfile with at least 32 bytes of random data.

```bash
head -c 64 /dev/urandom > my.key
chmod 600 my.key
```

Backends without authentication metadata are treated as unsupported and are not mounted.

The backend now uses a flat opaque object store under `objects/`.
Visible file names, directory names, and directory hierarchy are kept inside encrypted manifests, so gaining access to the backend does not reveal the mounted filesystem structure.

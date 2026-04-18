# secure_fuse

```bash
pip install fusepy
pip install cryptography
```

The backend now uses a flat opaque object store under `objects/`.
Visible file names, directory names, and directory hierarchy are kept inside encrypted manifests, so gaining access to the backend does not reveal the mounted filesystem structure.

#!/usr/bin/env python3
import logging
import os

from fuse import FUSE, FuseOSError, Operations

from secure_fuse.filesystem import FuseFS

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)-8s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("fuse_fs")
# Suppress fusepy's internal per-call debug/traceback messages
logging.getLogger("fuse").setLevel(logging.WARNING)


def main(mountpoint, backend, password):
    os.makedirs(backend, exist_ok=True)
    log.info("Mounting at %s", mountpoint)
    FUSE(FuseFS(backend, password), mountpoint, foreground=True)
    log.info("Unmounted")


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 4:
        print("Usage: python prototype.py <mountpoint> <backend> <password>")
        exit(1)

    main(sys.argv[1], sys.argv[2], sys.argv[3])


__all__ = ["FUSE", "FuseOSError", "Operations", "FuseFS", "main"]

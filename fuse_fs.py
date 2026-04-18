#!/usr/bin/env python3
import argparse
import getpass
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


def main(mountpoint, backend, password, keyfile):
    os.makedirs(backend, exist_ok=True)
    log.info("Mounting at %s", mountpoint)
    FUSE(FuseFS(backend, password, keyfile), mountpoint, foreground=True)
    log.info("Unmounted")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Mount secure_fuse filesystem")
    parser.add_argument("mountpoint")
    parser.add_argument("backend")
    parser.add_argument("--keyfile", required=True, help="Path to keyfile used for authentication")
    args = parser.parse_args()

    password = getpass.getpass("Password: ")
    main(args.mountpoint, args.backend, password, args.keyfile)


__all__ = ["FUSE", "FuseOSError", "Operations", "FuseFS", "main"]

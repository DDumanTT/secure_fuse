#!/usr/bin/env python3
import argparse
import getpass
import json
import logging
import os
import sys

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


def export_audit_certificate(backend, password, keyfile, leaf_index, output_path=None):
    """Export an audit inclusion certificate for one log leaf."""
    fs = FuseFS(backend, password, keyfile)
    cert = fs.audit.export_certificate(leaf_index)

    payload = json.dumps(cert, indent=2)
    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(payload + "\n")
    else:
        print(payload)

    return cert


def verify_audit_certificate(backend, password, keyfile, certificate_path):
    """Verify an audit inclusion certificate from JSON on disk."""
    with open(certificate_path, "r", encoding="utf-8") as f:
        certificate = json.load(f)

    fs = FuseFS(backend, password, keyfile)
    is_valid = fs.audit.verify_certificate(certificate)
    print("valid" if is_valid else "invalid")
    return is_valid


def view_audit_log(backend, password, keyfile):
    """Decrypt and print all audit log entries, one JSON object per line."""
    fs = FuseFS(backend, password, keyfile)
    entries, _ = fs.audit._read_log_entries_and_leaves()
    for entry in entries:
        print(json.dumps(entry))
    return entries


def _build_parser():
    parser = argparse.ArgumentParser(description="secure_fuse CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    mount_parser = subparsers.add_parser("mount", help="Mount secure_fuse filesystem")
    mount_parser.add_argument("mountpoint")
    mount_parser.add_argument("backend")
    mount_parser.add_argument("--keyfile", required=True, help="Path to keyfile used for authentication")

    export_parser = subparsers.add_parser("audit-export", help="Export Merkle inclusion certificate")
    export_parser.add_argument("backend")
    export_parser.add_argument("leaf_index", type=int, help="0-based audit log leaf index")
    export_parser.add_argument("--keyfile", required=True, help="Path to keyfile used for authentication")
    export_parser.add_argument(
        "--output",
        dest="output_path",
        help="Write certificate JSON to this file (defaults to stdout)",
    )

    verify_parser = subparsers.add_parser("audit-verify", help="Verify Merkle inclusion certificate")
    verify_parser.add_argument("backend")
    verify_parser.add_argument("certificate", help="Path to certificate JSON file")
    verify_parser.add_argument("--keyfile", required=True, help="Path to keyfile used for authentication")

    log_parser = subparsers.add_parser("audit-log", help="Decrypt and print audit log entries")
    log_parser.add_argument("backend")
    log_parser.add_argument("--keyfile", required=True, help="Path to keyfile used for authentication")

    return parser


def _is_legacy_mount_invocation(argv):
    if not argv:
        return False
    known = {"mount", "audit-export", "audit-verify", "audit-log", "-h", "--help"}
    return argv[0] not in known


def _run_cli(argv=None):
    argv = list(argv if argv is not None else sys.argv[1:])

    # Backward compatibility for the original CLI:
    #   ./fuse_fs.py <mountpoint> <backend> --keyfile <path>
    if _is_legacy_mount_invocation(argv):
        parser = argparse.ArgumentParser(description="Mount secure_fuse filesystem")
        parser.add_argument("mountpoint")
        parser.add_argument("backend")
        parser.add_argument("--keyfile", required=True, help="Path to keyfile used for authentication")
        args = parser.parse_args(argv)

        password = getpass.getpass("Password: ")
        main(args.mountpoint, args.backend, password, args.keyfile)
        return 0

    parser = _build_parser()
    args = parser.parse_args(argv)
    password = getpass.getpass("Password: ")

    if args.command == "mount":
        main(args.mountpoint, args.backend, password, args.keyfile)
        return 0
    if args.command == "audit-export":
        export_audit_certificate(
            args.backend,
            password,
            args.keyfile,
            args.leaf_index,
            output_path=args.output_path,
        )
        return 0
    if args.command == "audit-verify":
        return 0 if verify_audit_certificate(args.backend, password, args.keyfile, args.certificate) else 1
    if args.command == "audit-log":
        view_audit_log(args.backend, password, args.keyfile)
        return 0

    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(_run_cli())


__all__ = [
    "FUSE",
    "FuseOSError",
    "Operations",
    "FuseFS",
    "main",
    "export_audit_certificate",
    "verify_audit_certificate",
    "view_audit_log",
    "_run_cli",
]

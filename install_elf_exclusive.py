#!/usr/bin/env python3
"""One fixed ELF, one fixed target; no replacement, package hooks or policy edits."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat

TARGET = "/usr/bin/bwrap"
ELF_BYTES = 72160
ELF_SHA256 = "e318903862396f96de3df57264e0158682b952fd3fb53ac23d876413e7b30f71"


def create_exclusive(path, data):
    """The open is the atomic admission point; failures never remove the target."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise RuntimeError("exclusive_copy_short_write")
            offset += written
        os.fsync(fd)
        os.fchown(fd, os.geteuid(), os.getegid())
        os.fchmod(fd, 0o755)
    finally:
        os.close(fd)


def verified_elf(source):
    if not re.fullmatch(r"/tmp/issue943-held-note-[0-9]+/bubblewrap-setup/extracted/usr/bin/bwrap",
                        str(source)) or source.resolve(strict=True) != source:
        raise RuntimeError("fixed_source_path_required")
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb", buffering=0) as f:
        before = os.fstat(f.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != ELF_BYTES:
            raise RuntimeError("source_identity")
        data = f.read(ELF_BYTES + 1)
        after = os.fstat(f.fileno())
    if (len(data) != ELF_BYTES or not data.startswith(b"\x7fELF")
            or hashlib.sha256(data).hexdigest() != ELF_SHA256
            or (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns)):
        raise RuntimeError("source_bytes_mismatch")
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dispatch", action="store_true", required=True)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or os.geteuid() != 0 or os.getegid() != 0:
        raise RuntimeError("fixed_root_linux_required")
    data = verified_elf(args.source)
    create_exclusive(TARGET, data)
    print(json.dumps({"status": "EXCLUSIVE_ELF_CREATED", "path": TARGET,
                      "sha256": ELF_SHA256, "bytes": len(data), "replacedExisting": False}))


if __name__ == "__main__":
    main()

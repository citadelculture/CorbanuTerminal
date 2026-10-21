#!/usr/bin/env python3
"""Authenticated public keyring in a fresh root-owned run directory; no repairs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat

ASSET = "ubuntu-archive-keyring.gpg"
KEY_BYTES = 3607
KEY_SHA256 = "80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31"
FINGERPRINTS = (
    "790BC7277767219C42C86F933B4FE6ACC0B21F32",
    "843938DF228D22F7B3742BC0D94AA3F0EFE21092",
    "F6ECB3762474EDA9D21B7022871920D1991BC93C",
)
# This fixed public artifact uses RFC4880 old-format definite-length packets.
# Not a general OpenPGP parser or a replacement for gpgv signature verification.
PACKET_TAGS = (6, 12, 13, 12, 2, 12) * 3


def require(value, code):
    if not value:
        raise RuntimeError(code)


def public_fingerprints(data):
    require(type(data) is bytes and 0 < len(data) <= KEY_BYTES, "keyring_size")
    offset, tags, fingerprints = 0, [], []
    while offset < len(data):
        header = data[offset]
        offset += 1
        require(header & 0xC0 == 0x80 and header & 3 != 3, "keyring_packet_header")
        width = (1, 2, 4)[header & 3]
        require(offset + width <= len(data), "keyring_packet_length")
        size = int.from_bytes(data[offset:offset + width], "big")
        offset += width
        require(0 < size <= len(data) - offset and len(tags) < len(PACKET_TAGS),
                "keyring_packet_bound")
        body = data[offset:offset + size]
        offset += size
        tags.append((header >> 2) & 15)
        if tags[-1] == 6:
            require(len(body) == 525 and body[0] == 4 and body[5] == 1
                    and body[6:8] == b"\x10\x00", "keyring_v4_rsa4096_required")
            # OpenPGP v4 fingerprint: 0x99, two-byte body length, public-key body.
            fingerprints.append(hashlib.sha1(
                b"\x99" + len(body).to_bytes(2, "big") + body).hexdigest().upper())
    require(tuple(tags) == PACKET_TAGS, "keyring_exact_packet_inventory")
    return tuple(fingerprints)


def authenticate(data):
    fingerprints = public_fingerprints(data)
    require(fingerprints == FINGERPRINTS, "keyring_documented_fingerprints")
    require(len(data) == KEY_BYTES and hashlib.sha256(data).hexdigest() == KEY_SHA256,
            "keyring_frozen_public_bytes")
    return {"sha256": KEY_SHA256, "bytes": KEY_BYTES, "fingerprints": list(fingerprints)}


def trusted_directory(st):
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_gid == 0
            and not st.st_mode & 0o022, "keyring_parent_identity")


def target_identity(st):
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_gid == 0
            and stat.S_IMODE(st.st_mode) == 0o444 and st.st_nlink == 1,
            "keyring_created_identity")


def source_bytes():
    source = Path(__file__).resolve().with_name(ASSET)
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb", buffering=0) as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_size == KEY_BYTES,
                "keyring_source_identity")
        data = stream.read(KEY_BYTES + 1)
        after = os.fstat(stream.fileno())
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns),
            "keyring_source_changed")
    authenticate(data)
    return data


def parent_name(run_id):
    require(type(run_id) is str and re.fullmatch(r"[1-9][0-9]{0,19}", run_id),
            "keyring_run_id")
    return "issue943-authenticated-keyring-" + run_id


def identity(st):
    return {"device": int(st.st_dev), "inode": int(st.st_ino),
            "uid": int(st.st_uid), "gid": int(st.st_gid),
            "mode": int(st.st_mode), "fileType": stat.S_IFMT(st.st_mode)}


def install(data, run_id):
    # Authenticate before opening any destination. No chmod/chown, replacement,
    # unlink, package manager, or unsafe original keyring/directory access.
    facts = authenticate(data)
    name = parent_name(run_id)
    target = "/" + name + "/" + ASSET
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    root = os.open("/", flags)
    try:
        trusted_directory(os.fstat(root))
        # mkdir is exclusive: any existing file, directory or symlink is a hold.
        # No exist_ok, reuse, chmod/chown or umask change is permitted.
        os.mkdir(name, 0o755, dir_fd=root)
        parent = os.open(name, flags, dir_fd=root)
        try:
            parent_before = os.fstat(parent)
            trusted_directory(parent_before)
            require(stat.S_IMODE(parent_before.st_mode) == 0o755,
                    "keyring_new_parent_readable_mode")
            named_parent = os.stat(name, dir_fd=root, follow_symlinks=False)
            require(identity(named_parent) == identity(parent_before),
                    "keyring_new_parent_name_identity")
            fd = os.open(ASSET, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o444, dir_fd=parent)
            try:
                target_identity(os.fstat(fd))
                offset = 0
                while offset < len(data):
                    wrote = os.write(fd, data[offset:])
                    require(wrote > 0, "keyring_short_write")
                    offset += wrote
                os.fsync(fd)
                after = os.fstat(fd)
                target_identity(after)
                require(after.st_size == KEY_BYTES, "keyring_created_size")
            finally:
                os.close(fd)
            os.fsync(parent)
            parent_after = os.fstat(parent)
            trusted_directory(parent_after)
            require(identity(parent_before) == identity(parent_after),
                    "keyring_new_parent_changed")
            require(identity(os.stat(name, dir_fd=root, follow_symlinks=False))
                    == identity(parent_after), "keyring_new_parent_name_changed")
        finally:
            os.close(parent)
        os.fsync(root)
    finally:
        os.close(root)
    return {"status": "AUTHENTICATED_KEYRING_EXCLUSIVELY_CREATED",
            "path": target, **facts, "mode": "0444", "replacedExisting": False,
            "parentPath": "/" + name, "parentIdentity": identity(parent_after),
            "fileIdentity": identity(after),
            "lifetime": "RETAIN_UNTIL_DISPOSABLE_HOSTED_VM_END",
            "existingParentReused": False}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dispatch", action="store_true", required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    require(platform.system() == "Linux" and os.getuid() == 0 and os.geteuid() == 0
            and os.getgid() == 0 and os.getegid() == 0, "keyring_root_linux_required")
    print(json.dumps(install(source_bytes(), args.run_id), sort_keys=True))


if __name__ == "__main__":
    main()

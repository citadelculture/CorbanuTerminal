#!/usr/bin/env python3
"""One fixed descriptor traversal, metadata only; never creates a destination."""
import argparse
import json
import os
import platform
import stat
import sys

LABELS = ("/", "/usr", "/usr/share", "/usr/share/keyrings")
MAX_BYTES = 4096


def require(value, code):
    if not value:
        raise RuntimeError(code)


def trusted_directory(st):
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_gid == 0
            and not st.st_mode & 0o022, "keyring_parent_identity")


class Records:
    def __init__(self, stream):
        self.stream = stream
        self.bytes = 0
        self.labels = []

    def emit(self, value):
        data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        require(self.bytes + len(data) <= MAX_BYTES, "observation_output_bound")
        written = self.stream.write(data)
        require(written == len(data), "observation_short_write")
        self.stream.flush()
        self.bytes += len(data)

    def parent(self, label, st):
        require(len(self.labels) < 4 and label == LABELS[len(self.labels)],
                "observation_label_order")
        self.emit({
            "record": "parent", "pathLabel": label,
            "uid": int(st.st_uid), "gid": int(st.st_gid), "mode": int(st.st_mode),
            "fileType": stat.S_IFMT(st.st_mode),
            "device": int(st.st_dev), "inode": int(st.st_ino),
        })
        self.labels.append(label)


def observe(records):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent = os.open("/", flags)
    try:
        st = os.fstat(parent)
        records.parent("/", st)
        trusted_directory(st)
        for component, label in zip(("usr", "share", "keyrings"), LABELS[1:]):
            child = os.open(component, flags, dir_fd=parent)
            try:
                st = os.fstat(child)
                records.parent(label, st)
                trusted_directory(st)
            except BaseException:
                os.close(child)
                raise
            os.close(parent)
            parent = child
        # There is deliberately no destination-open, authentication/install,
        # package acquisition, namespace, build or product continuation.
        return "PARENT_IDENTITIES_CAPTURED_NOT_PROVISIONED"
    finally:
        os.close(parent)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dispatch", action="store_true", required=True)
    parser.parse_args()
    records = Records(sys.stdout.buffer)
    status, failure, code = "HOLD_PARENT_OBSERVATION", None, 1
    try:
        require(platform.system() == "Linux" and os.getuid() == 0 and os.geteuid() == 0
                and os.getgid() == 0 and os.getegid() == 0, "keyring_root_linux_required")
        status = observe(records)
        code = 0
    except BaseException as exc:
        safe = {
            "keyring_parent_identity", "keyring_root_linux_required",
            "observation_output_bound", "observation_short_write", "observation_label_order",
        }
        failure = str(exc) if type(exc) is RuntimeError and str(exc) in safe else (
            "observation_" + type(exc).__name__)
    try:
        records.emit({
            "record": "summary", "status": status, "failureCode": failure,
            "parentRows": len(records.labels), "qualified": False,
            "targetCreationReached": False, "provisioningReached": False,
            "downloadReached": False, "buildReached": False, "productTestsExecuted": 0,
        })
    except BaseException:
        # Missing or partial output remains a supervisor/parser HOLD.
        return 1
    return code


if __name__ == "__main__":
    sys.exit(main())

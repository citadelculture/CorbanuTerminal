"""Inert on import. Fixed Darwin POSIX group observation, never group mutation.

Apple's extended getgroups is a directory-derived access list; the unextended
POSIX symbol reads the calling process's kernel credential. Only the latter
can verify the explicit setgroups call made by the owned drop-child.
"""
import ctypes
import os
import sys

LIBSYSTEM = "/usr/lib/libSystem.B.dylib"
SYMBOL = "getgroups"
CAPACITY = 32


def _native_getgroups():
    if sys.platform != "darwin":
        raise RuntimeError("darwin_kernel_groups_required")
    # Absolute trusted system library; no environment search or extended-symbol
    # fallback. An absent symbol/library remains an error, never a pass.
    library = ctypes.CDLL(LIBSYSTEM, use_errno=True)
    function = getattr(library, SYMBOL)
    function.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_uint32))
    function.restype = ctypes.c_int
    return library, function


def read_kernel_groups(function=None, errno_reader=None):
    """One bounded call. No size-discovery loop, retry, or truncation success."""
    library = None
    if function is None:
        library, function = _native_getgroups()
    if errno_reader is None:
        errno_reader = ctypes.get_errno
    values = (ctypes.c_uint32 * CAPACITY)()
    ctypes.set_errno(0)
    count = function(CAPACITY, values)
    if type(count) is not int or count < 0:
        error = errno_reader()
        return {"state": "error", "errno": error if type(error) is int else None,
                "groups": None, "complete": False}
    if count > CAPACITY:
        return {"state": "invalid-count", "errno": None,
                "groups": None, "complete": False}
    return {"state": "observed", "errno": None,
            "groups": [int(values[i]) for i in range(count)], "complete": True}


def exact_credentials(record, uid, gid):
    """Strict kernel tuple; directory-derived group membership is not accepted."""
    return (
        type(uid) is int and 60000 <= uid < 64000 and type(gid) is int and gid == uid
        and all(type(record.get(k)) is int and record[k] == expected
                for k, expected in (("uid", uid), ("euid", uid), ("gid", gid), ("egid", gid)))
        and record.get("kernel", {}).get("state") == "observed"
        and record["kernel"].get("complete") is True
        and record["kernel"].get("groups") == [gid]
        and all(type(v) is int for v in record["kernel"]["groups"])
        and record.get("pythonGroupAccessList", {}).get("complete") is True
    )


def observe(uid, gid, os_api=None, function=None, errno_reader=None):
    """Called only after the existing irreversible drop, and again after exec."""
    if type(uid) is not int or not 60000 <= uid < 64000 or type(gid) is not int or gid != uid:
        raise RuntimeError("owned_synthetic_identity_required")
    if os_api is None:
        os_api = os
    record = {
        "schema": "network-kernel-credentials-v1",
        "expectedUid": uid, "expectedGid": gid,
        "uid": os_api.getuid(), "euid": os_api.geteuid(),
        "gid": os_api.getgid(), "egid": os_api.getegid(),
        "library": LIBSYSTEM, "symbol": SYMBOL, "capacity": CAPACITY,
        "kernel": {"state": "unobserved", "groups": None, "complete": False},
        "pythonGroupAccessList": {"state": "unobserved", "complete": False},
        "credentialPassed": False,
    }
    try:
        record["kernel"] = read_kernel_groups(function, errno_reader)
    except Exception as exc:
        record["kernel"] = {"state": "api-error", "groups": None, "complete": False,
                            "exceptionType": type(exc).__name__}
    try:
        groups = os_api.getgroups()
        if type(groups) is not list or not all(type(v) is int and 0 <= v < 2**32 for v in groups):
            raise ValueError("invalid_group_access_list")
        record["pythonGroupAccessList"] = {
            "state": "observed", "groups": groups[:CAPACITY], "count": len(groups),
            "complete": len(groups) <= CAPACITY,
            "semantics": "macOS Python directory-derived access list; not kernel groups",
        }
    except Exception as exc:
        record["pythonGroupAccessList"] = {
            "state": "api-error", "complete": False, "exceptionType": type(exc).__name__,
        }
    record["credentialPassed"] = exact_credentials(record, uid, gid)
    return record

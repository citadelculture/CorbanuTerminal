#!/usr/bin/env python3
"""Synthetic child only; no product code, credential fixture, provider or IP traffic."""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import resource
import socket
import sys

PT_DENY_ATTACH = 31  # Apple's bsd/sys/ptrace.h; matches the pinned Rust libc operation.
MAX_ERROR_BYTES = 4096


def broker_profile(raw, canonical):
    for value in (raw, canonical):
        if not value.startswith('/') or any(c in value for c in ('"', '\\', '\n', '\r')):
            raise ValueError('profile_path_not_quotable')
    # Verbatim no-extra-writable-files branch of pinned broker_seatbelt_profile_with_files.
    return f'''(version 1)
(allow default)
(deny process-exec*)
(deny process-fork)
(deny signal (target others))
(deny process-info* (target others))
(deny file-write*
  (require-all
    (require-not (subpath "{raw}"))
    (require-not (subpath "{canonical}"))
    (require-not (literal "/dev/null"))
    (require-not (literal "/private/var/run/syslog"))))
'''


def socket_probe(runtime, name):
    directory = runtime / name
    directory.mkdir(mode=0o700)
    path = directory / 'c.sock'
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    accepted = None
    row = {'pathBytes': len(os.fsencode(path)), 'bind': False, 'connect': False,
           'accept': False, 'errno': None, 'listenersClosed': False}
    try:
        listener.settimeout(2); client.settimeout(2)
        listener.bind(str(path)); row['bind'] = True
        listener.listen(1)
        client.connect(str(path)); row['connect'] = True
        accepted, _ = listener.accept(); row['accept'] = True
    except OSError as e:
        row['errno'] = e.errno
    finally:
        if accepted is not None: accepted.close()
        client.close(); listener.close(); row['listenersClosed'] = True
        if path.exists(): path.unlink()
        directory.rmdir()
    return row


def denied_file(path, write=False):
    try:
        if write:
            with path.open('wb') as f: f.write(b'UNEXPECTED_SYNTHETIC_WRITE\n')
        else:
            with path.open('rb') as f: f.read(1)
        return {'denied': False, 'errno': None}
    except OSError as e:
        return {'denied': e.errno in (errno.EPERM, errno.EACCES), 'errno': e.errno}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--dispatch', action='store_true', required=True)
    for name in ('runtime', 'sentinel', 'foreign'):
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    if sys.platform != 'darwin' or os.geteuid() == 0:
        raise RuntimeError('nonroot_macos_child_required')
    runtime = a.runtime
    canonical = runtime.resolve(strict=True)
    if (runtime.parent != Path('/var/tmp') or canonical.parent != Path('/private/var/tmp')
            or not runtime.name.startswith('corbanu-credential-canary-')
            or not runtime.is_dir() or runtime.is_symlink()):
        raise RuntimeError('owned_fixture_parent_mismatch')
    row = {'schema': 'synthetic-broker-nesting-probe-v1', 'status': 'INCOMPLETE',
           'productBodiesExecuted': 0, 'canaryInvocations': 0, 'canaryReady': False,
           'runtimeParentBytes': len(os.fsencode(runtime)),
           'canonicalParentBytes': len(os.fsencode(canonical)),
           'runtimeCleanupOwner': 'supervisor', 'error': None}
    try:
        row['outerForeignFile'] = denied_file(a.foreign)
        row['outerWritableSentinel'] = a.sentinel.read_bytes() == b'SYNTHETIC_INNER_ONLY_SENTINEL\n'
        # Confirm outer policy permits this same synthetic writable file before applying inner policy.
        with a.sentinel.open('ab') as f: f.write(b'')
        row['outerUnix'] = socket_probe(runtime, 'cbk-Pre001')
        if (not row['outerForeignFile']['denied'] or not row['outerWritableSentinel']
                or not all(row['outerUnix'][k] for k in ('bind','connect','accept','listenersClosed'))):
            row['status'] = 'OUTER_SYNTHETIC_CONTROL_FAILED'
            return row
        libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
        ptrace = libc.ptrace
        ptrace.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
        ptrace.restype = ctypes.c_int
        ctypes.set_errno(0)
        ret = ptrace(PT_DENY_ATTACH, 0, None, 0)
        row['selfHardening'] = {'ptraceReturn': ret, 'errno': ctypes.get_errno()}
        if ret == -1:
            row['status'] = 'SELF_HARDENING_REJECTED'
            return row
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        row['selfHardening']['coreLimitZero'] = resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
        # The supervisor does not forward loader-injection variables; do not alter caller controls.
        if any(k.startswith(('DYLD_', 'LD_')) for k in os.environ):
            row['status'] = 'UNEXPECTED_LOADER_ENVIRONMENT'
            return row
        profile = broker_profile(str(runtime), str(canonical)).encode()
        row['innerProfileSha256'] = hashlib.sha256(profile).hexdigest()
        sandbox_init = libc.sandbox_init
        sandbox_init.argtypes = (ctypes.c_char_p, ctypes.c_uint64, ctypes.POINTER(ctypes.c_void_p))
        sandbox_init.restype = ctypes.c_int
        free_error = libc.sandbox_free_error
        free_error.argtypes = (ctypes.c_void_p,); free_error.restype = None
        error = ctypes.c_void_p()
        ctypes.set_errno(0)
        ret = sandbox_init(profile, 0, ctypes.byref(error))
        err = ctypes.get_errno()
        text = None
        if error.value:
            try:
                text = ctypes.string_at(error.value).decode('utf-8', 'replace')
            finally:
                free_error(error)
        if text and len(text.encode()) > MAX_ERROR_BYTES:
            row['status'] = 'ERROR_DIAGNOSTIC_OVERSIZE'
            row['inner'] = {'return': ret, 'errno': err, 'errorTextSha256': hashlib.sha256(text.encode()).hexdigest()}
            return row
        row['inner'] = {'return': ret, 'errno': err, 'errorText': text}
        if ret != 0:
            row['status'] = 'NESTED_CONTAINMENT_REJECTED'
            return row
        row['innerUnix'] = socket_probe(runtime, 'cbk-Post01')
        row['innerWriteDenied'] = denied_file(a.sentinel, write=True)
        if (not all(row['innerUnix'][k] for k in ('bind','connect','accept','listenersClosed'))
                or not row['innerWriteDenied']['denied']):
            row['status'] = 'NESTED_POSTCONTROL_FAILED'
        else:
            row['status'] = 'SYNTHETIC_NESTING_PATH_SUPPORTED_NOT_BROKER_QUALIFICATION'
    except BaseException as e:
        row['error'] = {'type': type(e).__name__, 'errno': getattr(e, 'errno', None)}
    return row


if __name__ == '__main__':
    try:
        value = main()
        print(json.dumps(value, sort_keys=True), flush=True)
        # This means diagnostic data were captured, never canary success.
        sys.exit(0 if value['status'] not in ('INCOMPLETE','OUTER_SYNTHETIC_CONTROL_FAILED',
                                             'NESTED_POSTCONTROL_FAILED','ERROR_DIAGNOSTIC_OVERSIZE',
                                             'UNEXPECTED_LOADER_ENVIRONMENT') else 2)
    except BaseException as e:
        if isinstance(e, SystemExit): raise
        print(json.dumps({'schema':'synthetic-broker-nesting-probe-v1','status':'INCOMPLETE',
                          'errorType':type(e).__name__,'canaryReady':False}), flush=True)
        sys.exit(2)

"""Lazy Darwin API access to an owned synthetic Mach service; no credential APIs."""
import ctypes
import copy
import os
import re


def api():
    lib = ctypes.CDLL('/usr/lib/libSystem.B.dylib', use_errno=True)
    uint = ctypes.c_uint
    bootstrap = uint.in_dll(lib, 'bootstrap_port').value
    task = uint.in_dll(lib, 'mach_task_self_').value
    for name, args in [('bootstrap_look_up', (uint, ctypes.c_char_p, ctypes.POINTER(uint))),
                       ('bootstrap_look_up_per_user', (uint, ctypes.c_char_p, uint, ctypes.POINTER(uint))),
                       ('bootstrap_register', (uint, ctypes.c_char_p, uint)),
                       ('mach_port_allocate', (uint, ctypes.c_int, ctypes.POINTER(uint))),
                       ('mach_port_insert_right', (uint, uint, uint, ctypes.c_uint)),
                       ('mach_port_type', (uint, uint, ctypes.POINTER(uint))),
                       ('mach_port_destroy', (uint, uint)),
                       ('mach_port_deallocate', (uint, uint))]:
        f = getattr(lib, name); f.argtypes = args; f.restype = ctypes.c_int
    return lib, bootstrap, task


def lookup(name, target_uid=None):
    lib, bootstrap, task = api(); port = ctypes.c_uint()
    if target_uid is None:
        ret = lib.bootstrap_look_up(bootstrap, name.encode(), ctypes.byref(port))
    else:
        ret = lib.bootstrap_look_up_per_user(bootstrap, name.encode(), target_uid, ctypes.byref(port))
    if ret == 0 and port.value:
        lib.mach_port_deallocate(task, port.value)
    return ret


def process_identity():
    return (os.getpid(), os.getuid(), os.geteuid())


def valid_port(value):
    return type(value) is int and 0 < value < 2**32 - 1


class OwnedService:
    """Single-use runner-owned receive right; APIs are injectable for pure tests."""
    def __init__(self, name, api_loader=None, identity=None):
        if re.fullmatch(r'org\.codex\.synthetic\.ncap\.[0-9]{8,16}\.[0-9a-f]{32}', name) is None:
            raise RuntimeError('synthetic_mach_name_invalid')
        self._api_loader = api_loader or api
        self._identity = identity or process_identity
        self._lib, bootstrap, task = self._api_loader()
        if not valid_port(bootstrap) or not valid_port(task):
            raise RuntimeError('synthetic_mach_context_invalid')
        self._owner = (*self._identity(), bootstrap, task, name)
        self._port = None
        self._rows = []
        self._errors = []
        self._register_attempted = False
        self._cleanup_attempted = False
        self._registered = False
        self._destroy_attempts = 0
        self._post_lookups = 0
        self._proof = {}

    def _require(self, condition, code):
        if not condition:
            self._errors.append(code)
            self._proof['qualified'] = False
            raise RuntimeError(code)

    def _call(self, label, function, *args):
        self._require(len(self._rows) < 10, 'mach_call_bound')
        row = {'label': label, 'complete': False}
        self._rows.append(row)
        try:
            row['return'] = int(function(*args))
            row['complete'] = True
            return row['return']
        except BaseException as exc:
            row['exceptionType'] = type(exc).__name__
            self._require(False, 'mach_call_incomplete_' + label)

    def _lookup(self, label):
        output = ctypes.c_uint(0)
        ret = self._call(label, self._lib.bootstrap_look_up,
                         self._owner[3], self._owner[5].encode(), ctypes.byref(output))
        self._rows[-1]['outputPort'] = output.value
        if ret == 0:
            self._require(valid_port(output.value), 'mach_lookup_invalid_success_port')
            released = self._call(label + '-release', self._lib.mach_port_deallocate,
                                  self._owner[4], output.value)
            self._require(released == 0, 'mach_lookup_reference_release_failed')
        return ret, output.value

    def register(self):
        self._require(not self._register_attempted and not self._cleanup_attempted,
                      'mach_register_already_attempted')
        self._register_attempted = True
        ret, output = self._lookup('initial-lookup')
        self._require(ret == 1102 and output == 0, 'mach_initial_not_exact_unknown')
        port = ctypes.c_uint(0)
        ret = self._call('allocate', self._lib.mach_port_allocate,
                         self._owner[4], 1, ctypes.byref(port))
        self._rows[-1]['outputPort'] = port.value
        self._require(ret == 0 and valid_port(port.value), 'mach_allocate_not_owned')
        self._port = port.value  # journal once, before any later native operation
        ret = self._call('insert-send', self._lib.mach_port_insert_right,
                         self._owner[4], self._port, self._port, 20)
        self._require(ret == 0, 'mach_insert_send_failed')
        ret = self._call('register', self._lib.bootstrap_register,
                         self._owner[3], self._owner[5].encode(), self._port)
        self._require(ret == 0, 'mach_register_failed')
        ret, output = self._lookup('positive-lookup')
        self._require(ret == 0 and output == self._port, 'mach_positive_identity_failed')
        self._registered = True
        return self.snapshot()

    def snapshot(self):
        return copy.deepcopy({
            'schema': 'owned-mach-lifecycle-v2', 'method': 'owned-receive-destruction',
            'owner': dict(zip(('pid','uid','euid','bootstrap','task','name'), self._owner)),
            'allocatedPort': self._port, 'registrationComplete': self._registered,
            'cleanupAttempted': self._cleanup_attempted,
            'nullRegistrationAttempted': False, 'destroyAttempts': self._destroy_attempts,
            'postDestroyLookups': self._post_lookups, 'calls': self._rows,
            'errors': self._errors, **self._proof})

    def cleanup(self):
        self._require(not self._cleanup_attempted, 'mach_cleanup_already_attempted')
        self._cleanup_attempted = True
        self._proof = {'qualified': False, 'ownedPortDestroyed': False}
        try:
            self._require(valid_port(self._port), 'mach_no_owned_allocation')
            _, bootstrap, task = self._api_loader()
            stable = (*self._identity(), bootstrap, task) == self._owner[:5]
            self._proof['ownerContextUnchanged'] = stable
            self._require(stable, 'mach_owner_context_changed')
            rights = ctypes.c_uint(0)
            ret = self._call('receive-type', self._lib.mach_port_type,
                             task, self._port, ctypes.byref(rights))
            self._rows[-1]['typeBits'] = rights.value
            self._require(ret == 0 and rights.value & (1 << 17)
                          and not rights.value & (1 << 20), 'mach_receive_right_not_proved')
            # No receive transfer or port-destroyed backup request exists in this helper.
            # Consume before calling: names can be recycled immediately after destroy.
            self._destroy_attempts = 1
            ret = self._call('destroy', self._lib.mach_port_destroy, task, self._port)
            self._proof['destroyReturn'] = ret
            self._proof['ownedPortDestroyed'] = ret == 0
            self._require(ret == 0, 'mach_destroy_failed')
            self._post_lookups = 1
            ret, output = self._lookup('post-destroy-lookup')
            self._proof['lookupAfter'] = ret
            self._proof['lookupAfterOutputPort'] = output
            self._require(ret == 1102 and output == 0, 'mach_post_not_exact_unknown')
            self._proof['qualified'] = self._registered and not self._errors
        except BaseException as exc:
            # Native exception strings/records are never exposed. All failures remain HOLD.
            if not self._errors:
                self._errors.append('mach_cleanup_exception_' + type(exc).__name__)
        return self.snapshot()

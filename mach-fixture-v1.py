"""Lazy Darwin API access to an owned synthetic Mach service; no credential APIs."""
import ctypes


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


def register(name):
    lib, bootstrap, task = api()
    if lookup(name) == 0: raise RuntimeError('synthetic_mach_name_preexists')
    port = ctypes.c_uint()
    ret = lib.mach_port_allocate(task, 1, ctypes.byref(port))  # MACH_PORT_RIGHT_RECEIVE
    if ret != 0: raise RuntimeError('synthetic_mach_allocate_failed')
    registered = False
    try:
        if lib.mach_port_insert_right(task, port.value, port.value, 20) != 0:
            raise RuntimeError('synthetic_mach_send_right_failed')  # MAKE_SEND
        ret = lib.bootstrap_register(bootstrap, name.encode(), port.value)
        if ret != 0: raise RuntimeError('synthetic_mach_registration_unavailable_' + str(ret))
        registered = True
        if lookup(name) != 0: raise RuntimeError('synthetic_mach_positive_control_failed')
        return port.value
    except BaseException:
        if registered: lib.bootstrap_register(bootstrap, name.encode(), 0)
        lib.mach_port_destroy(task, port.value)
        raise


def unregister(name, port):
    lib, bootstrap, task = api()
    removed = lib.bootstrap_register(bootstrap, name.encode(), 0)
    destroyed = lib.mach_port_destroy(task, port)
    return {'unregisterReturn': removed, 'destroyReturn': destroyed,
            'lookupAfter': lookup(name), 'ownedPortDestroyed': destroyed == 0}

"""Linux child-process network denial, applied before loading models or documents."""
import ctypes
import errno
import os
from pathlib import Path
import socket
import sys


def deny_network():
    if sys.platform != 'linux':
        raise RuntimeError('Linux sandbox requires Linux')
    lib = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise RuntimeError('Cannot restrict child privileges')
    class Compare(ctypes.Structure):
        _fields_ = [('arg', ctypes.c_uint), ('op', ctypes.c_int),
                    ('a', ctypes.c_uint64), ('b', ctypes.c_uint64)]
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                          ctypes.c_uint, ctypes.POINTER(Compare)]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    context = lib.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    if not context:
        raise RuntimeError('Cannot create network filter')
    try:
        # Allow local Unix IPC (LibreOffice/CUDA); deny every other socket family.
        for name in ('socket', 'socketpair'):
            call = lib.seccomp_syscall_resolve_name(name.encode())
            compare = Compare(0, 1, socket.AF_UNIX, 0)  # SCMP_CMP_NE
            if call < 0 or lib.seccomp_rule_add_array(context, 0x50000 | errno.EPERM,
                                                     call, 1, ctypes.byref(compare)) != 0:
                raise RuntimeError('Cannot install socket restriction')
        # No alternate asynchronous network path or nested 32-bit socketcall.
        for name in ('io_uring_setup', 'socketcall'):
            call = lib.seccomp_syscall_resolve_name(name.encode())
            if call >= 0 and lib.seccomp_rule_add_array(context, 0x50000 | errno.EPERM,
                                                       call, 0, None) != 0:
                raise RuntimeError('Cannot restrict alternate socket path')
        if lib.seccomp_load(context) != 0:
            raise RuntimeError('Cannot activate network filter')
    finally:
        lib.seccomp_release(context)
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            with socket.socket(family):
                raise RuntimeError('Network isolation probe failed')
        except PermissionError:
            pass


def sandbox_command(command):
    if sys.platform == 'linux':
        return [sys.executable, str(Path(__file__).resolve()), *command]
    return command


if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise SystemExit('Expected a child command')
    deny_network()
    os.execv(sys.argv[1], sys.argv[1:])

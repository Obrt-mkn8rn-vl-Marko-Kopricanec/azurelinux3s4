"""Final descriptor duplication/mutation refusal and nonmutating witnesses."""

import ctypes
import errno
import os


DESCRIPTOR_DENIED = ("dup", "dup2", "dup3")


def add_descriptor_rules(lib, context):
    if ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8:
        raise ValueError("unsupported descriptor native ABI")
    number = lib.seccomp_syscall_resolve_name(b"fcntl")
    if number == -1:
        raise ValueError("unknown syscall: fcntl")
    # Allow only exact F_GETFD=1/F_GETFL=3. Separate single-argument rules
    # avoid unsupported repeated comparisons on one argument. Full-width
    # comparisons also refuse high-bit aliases of kernel-truncated commands.
    for operation, value in ((2, 1), (4, 2), (6, 3)):  # LT1, EQ2, GT3.
        comparison = Comparison(1, operation, value, 0)
        checked(lib.seccomp_rule_add_array(context, 0x50000 | errno.EPERM,
                                           number, 1, ctypes.byref(comparison)))


def verify_descriptors(descriptors):
    if (len(descriptors) != 2
            or any(type(fd) is not int or not 0 <= fd <= 0x7fffffff for fd in descriptors)
            or len(set(descriptors)) != 2):
        raise ValueError("two distinct descriptor observations are required")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.dup.argtypes, libc.dup.restype = [ctypes.c_int], ctypes.c_int
    libc.dup2.argtypes, libc.dup2.restype = [ctypes.c_int, ctypes.c_int], ctypes.c_int
    libc.dup3.argtypes, libc.dup3.restype = [ctypes.c_int] * 3, ctypes.c_int
    libc.fcntl.argtypes, libc.fcntl.restype = [ctypes.c_int, ctypes.c_int, ctypes.c_long], ctypes.c_int
    # Invalid source FDs make all probes noncreating/nonmutating even when
    # a rule is absent. EBADF/EINVAL cannot certify the filter's EPERM.
    challenges = (
        ("dup", libc.dup, (-1,)),
        ("dup2", libc.dup2, (-1, -1)),
        ("dup3", libc.dup3, (-1, -1, 0)),
        ("fcntl-dupfd", libc.fcntl, (-1, 0, 0)),
        ("fcntl-setfd", libc.fcntl, (-1, 2, 0)),
        ("fcntl-setfl", libc.fcntl, (-1, 4, 0)),
        ("fcntl-dupfd-cloexec", libc.fcntl, (-1, 1030, 0)),
    )
    for name, operation, arguments in challenges:
        ctypes.set_errno(0)
        if operation(*arguments) != -1 or ctypes.get_errno() != errno.EPERM:
            raise RuntimeError("descriptor denial challenge failed: " + name)
    for descriptor in descriptors:
        flags = libc.fcntl(descriptor, 1, 0)
        status = libc.fcntl(descriptor, 3, 0)
        if flags not in (0, 1) or status < 0 or not status & os.O_NONBLOCK:
            raise RuntimeError("descriptor query/nonblocking state refused")

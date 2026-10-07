"""Checked child-only descriptor budgets and final resource-setter refusal."""

import ctypes
import errno
import platform
import resource


FD_STARTUP_LIMIT = 256
FD_FORWARD_LIMIT = 16
RESOURCE_DENIED = ("setrlimit",)


class ResourceLimit64(ctypes.Structure):
    _fields_ = [("current", ctypes.c_uint64), ("maximum", ctypes.c_uint64)]


def resource_abi():
    if (platform.machine() not in ("x86_64", "aarch64")
            or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_ulong) != 8
            or resource.RLIMIT_NOFILE != 7):
        raise ValueError("unsupported resource native ABI")


def bound_descriptors(ceiling, retained=()):
    resource_abi()
    if ceiling not in (FD_STARTUP_LIMIT, FD_FORWARD_LIMIT):
        raise ValueError("unsupported descriptor resource budget")
    if any(type(fd) is not int or not 0 <= fd <= 0x7fffffff for fd in retained):
        raise ValueError("invalid retained descriptor observation")
    observed = resource.getrlimit(resource.RLIMIT_NOFILE)
    if (not isinstance(observed, tuple) or len(observed) != 2
            or any(type(value) is not int or (value != resource.RLIM_INFINITY and not 0 <= value < 1 << 64)
                   for value in observed)):
        raise ValueError("descriptor resource observations refused")
    normalized = tuple((1 << 64) - 1 if value == resource.RLIM_INFINITY else value for value in observed)
    if normalized[0] > normalized[1]:
        raise ValueError("descriptor resource observations refused")
    expected = tuple(min(value, ceiling) for value in normalized)
    # RLIMIT_NOFILE does not close already-open high descriptors. The caller
    # scrubs extras first, and every kept channel must be below the new bound.
    if any(fd >= expected[0] for fd in retained):
        raise ValueError("retained descriptor exceeds resource budget")
    resource.setrlimit(resource.RLIMIT_NOFILE, expected)
    if resource.getrlimit(resource.RLIMIT_NOFILE) != expected:
        raise RuntimeError("descriptor resource limit was not observed")
    return expected


def add_resource_rules(lib, context):
    resource_abi()
    number = lib.seccomp_syscall_resolve_name(b"prlimit64")
    if number == -1:
        raise ValueError("unknown syscall: prlimit64")
    # NULL new_limit means query only. Compare pointer presence, never its
    # contents: every non-NULL update request is denied for every resource/PID.
    comparison = Comparison(2, 1, 0, 0)  # SCMP_CMP_NE, new_limit != NULL.
    checked(lib.seccomp_rule_add_array(context, 0x50000 | errno.EPERM,
                                       number, 1, ctypes.byref(comparison)))


def native_resource_api():
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        libc.prlimit64.argtypes = [ctypes.c_int, ctypes.c_int,
                                  ctypes.POINTER(ResourceLimit64), ctypes.POINTER(ResourceLimit64)]
        libc.prlimit64.restype = ctypes.c_int
        libc.syscall.argtypes, libc.syscall.restype = [ctypes.c_long], ctypes.c_long
    except AttributeError as error:
        raise ValueError("native resource interfaces unavailable") from error
    return libc


def verify_resource_limits(expected):
    resource_abi()
    if (not isinstance(expected, tuple) or len(expected) != 2
            or any(type(value) is not int for value in expected)
            or not 0 < expected[0] <= expected[1] <= FD_FORWARD_LIMIT):
        raise ValueError("invalid forwarding descriptor budget")
    if resource.getrlimit(resource.RLIMIT_NOFILE) != expected:
        raise RuntimeError("descriptor resource read-back refused")
    libc = native_resource_api()
    observed = ResourceLimit64()
    if (libc.prlimit64(0, 7, None, ctypes.byref(observed)) != 0
            or (observed.current, observed.maximum) != expected):
        raise RuntimeError("native descriptor resource query refused")
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_syscall_resolve_name.argtypes, lib.seccomp_syscall_resolve_name.restype = [ctypes.c_char_p], ctypes.c_int
    invalid = ResourceLimit64(0, 0)
    # Raw syscalls avoid libc setrlimit being redirected through prlimit64.
    # Resource -1 is invalid even if a filter rule is absent; no limit changes.
    probes = (
        ("setrlimit", (ctypes.c_long(-1), ctypes.byref(invalid))),
        ("prlimit64", (ctypes.c_long(0), ctypes.c_long(-1), ctypes.byref(invalid), ctypes.c_void_p())),
    )
    for name, arguments in probes:
        number = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
        if number == -1:
            raise ValueError("unknown resource syscall: " + name)
        ctypes.set_errno(0)
        if libc.syscall(ctypes.c_long(number), *arguments) != -1 or ctypes.get_errno() != errno.EPERM:
            raise RuntimeError("resource setter challenge failed: " + name)
    if (resource.getrlimit(resource.RLIMIT_NOFILE) != expected
            or libc.prlimit64(0, 7, None, ctypes.byref(observed)) != 0
            or (observed.current, observed.maximum) != expected):
        raise RuntimeError("descriptor resource budget changed during challenges")

"""Native MDWE admission and live challenges; no code bytes are executed."""

import ctypes
import errno
import os
import platform


def protect_memory():
    if (platform.machine() not in ("x86_64", "aarch64")
            or ctypes.sizeof(ctypes.c_void_p) != 8 or ctypes.sizeof(ctypes.c_long) != 8):
        raise ValueError("unsupported MDWE native architecture or ABI")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mmap.restype = ctypes.c_void_p
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.mprotect.restype = ctypes.c_int
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int
    state = libc.prctl(66, 0, 0, 0, 0)  # PR_GET_MDWE
    if state < 0:
        raise OSError(ctypes.get_errno(), "MDWE query refused")
    if state not in (0, 1):
        # Refuse NO_INHERIT/unknown flags; never weaken an inherited policy.
        raise ValueError("unsupported inherited MDWE mask")
    size = os.sysconf("SC_PAGE_SIZE")
    if not 4096 <= size <= 65536 or size & (size - 1):
        raise ValueError("unsupported MDWE challenge page size")
    failed = ctypes.c_void_p(-1).value
    writable = libc.mmap(None, size, 3, 0x22, -1, 0)  # Private anonymous R/W.
    if writable == failed:
        raise OSError(ctypes.get_errno(), "MDWE writable-page baseline refused")
    try:
        if libc.mprotect(writable, size, 3) != 0:
            raise OSError(ctypes.get_errno(), "MDWE writable-page baseline protection refused")
        if libc.prctl(65, 1, 0, 0, 0) != 0:  # PR_SET_MDWE/REFUSE_EXEC_GAIN, inheritable.
            raise OSError(ctypes.get_errno(), "MDWE installation refused")
        if libc.prctl(66, 0, 0, 0, 0) != 1:
            raise RuntimeError("MDWE protection mask was not observed")
        ctypes.set_errno(0)
        if libc.mprotect(writable, size, 5) != -1 or ctypes.get_errno() != errno.EACCES:
            raise RuntimeError("MDWE execute-gain challenge failed")
        ctypes.set_errno(0)
        created = libc.mmap(None, size, 7, 0x22, -1, 0)
        observed_errno = ctypes.get_errno()
        if created != failed:
            if libc.munmap(created, size) != 0:
                raise OSError(ctypes.get_errno(), "MDWE unexpected-page cleanup refused")
            raise RuntimeError("MDWE writable-executable challenge failed")
        if observed_errno != errno.EACCES:
            raise RuntimeError("MDWE writable-executable challenge failed")
        if libc.mprotect(writable, size, 3) != 0:
            raise OSError(ctypes.get_errno(), "MDWE data-page compatibility refused")
        if libc.prctl(66, 0, 0, 0, 0) != 1:
            raise RuntimeError("MDWE final protection mask was not observed")
    finally:
        if libc.munmap(writable, size) != 0:
            raise OSError(ctypes.get_errno(), "MDWE challenge cleanup refused")
    return 1

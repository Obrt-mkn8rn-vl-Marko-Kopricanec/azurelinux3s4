"""Owned native descriptor controls and explicit whole-worker omission models."""

import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import resource
import selectors
import socket
import sys


ROOT = Path(__file__).resolve().parents[1]


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def library():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.dup.argtypes, libc.dup.restype = [ctypes.c_int], ctypes.c_int
    libc.dup2.argtypes, libc.dup2.restype = [ctypes.c_int] * 2, ctypes.c_int
    libc.dup3.argtypes, libc.dup3.restype = [ctypes.c_int] * 3, ctypes.c_int
    libc.fcntl.argtypes, libc.fcntl.restype = [ctypes.c_int, ctypes.c_int, ctypes.c_long], ctypes.c_int
    libc.syscall.argtypes, libc.syscall.restype = [ctypes.c_long], ctypes.c_long
    return libc


def native(mode):
    worker, libc = load("Web/relay.py", "s4_descriptor_leaf"), library()
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    number = lib.seccomp_syscall_resolve_name(b"fcntl")
    assert number >= 0
    left, right = socket.socketpair()
    left.setblocking(False)
    right.setblocking(False)
    spare = os.dup(right.fileno())

    def snapshot():
        return {str(fd): {"device": os.fstat(fd).st_dev, "inode": os.fstat(fd).st_ino,
                          "fd_flags": libc.fcntl(fd, 1, 0), "status": libc.fcntl(fd, 3, 0)}
                for fd in (left.fileno(), right.fileno(), spare)}

    def alias(command):
        return libc.syscall(ctypes.c_long(number), ctypes.c_ulong(left.fileno()),
                            ctypes.c_ulong(command), ctypes.c_ulong(0))

    operations = (
        ("dup", lambda: libc.dup(left.fileno()), True),
        ("dup2", lambda: libc.dup2(left.fileno(), spare), False),
        ("dup3", lambda: libc.dup3(left.fileno(), spare, os.O_CLOEXEC), False),
        ("dupfd", lambda: libc.fcntl(left.fileno(), 0, 0), True),
        ("dupfd-cloexec", lambda: libc.fcntl(left.fileno(), 1030, 0), True),
        ("setfd-same", lambda: libc.fcntl(left.fileno(), 2, 1), False),
        ("setfl-same", lambda: libc.fcntl(left.fileno(), 4, libc.fcntl(left.fileno(), 3, 0)), False),
        ("high-dupfd", lambda: alias(1 << 32), True),
        ("high-dupfd-cloexec", lambda: alias((1 << 32) | 1030), True),
        ("high-query-fd", lambda: alias((1 << 32) | 1), False),
        ("high-query-status", lambda: alias((1 << 32) | 3), False),
    )
    before_baseline = snapshot()
    positives = {}
    for name, operation, allocated in operations:
        ctypes.set_errno(0)
        result = operation()
        assert result >= 0, (name, result, ctypes.get_errno())
        positives[name] = result
        if allocated: os.close(result)
        if name in ("dup2", "dup3"):
            assert libc.dup2(right.fileno(), spare) == spare
            assert libc.fcntl(spare, 2, 1) == 0
    assert before_baseline == snapshot()
    omitted = mode == "landlock-only-model"
    if omitted:
        worker.DENIED = tuple(name for name in worker.DENIED if name not in worker.DESCRIPTOR_DENIED)
        worker.add_descriptor_rules = lambda lib, context: None
    worker.restrict(True)
    worker.confine_filesystem()
    before = snapshot()
    outcomes = {}
    for name, operation, allocated in operations:
        ctypes.set_errno(0)
        result = operation()
        error = ctypes.get_errno()
        if omitted:
            assert result >= 0, (name, result, error)
            if allocated: os.close(result)
            if name in ("dup2", "dup3"):
                assert libc.dup2(right.fileno(), spare) == spare
                assert libc.fcntl(spare, 2, 1) == 0
        else:
            if result >= 0 and allocated: os.close(result)
            assert result == -1 and error == errno.EPERM, (name, result, error)
        outcomes[name] = {"result": result, "errno": error}
    if not omitted: worker.verify_descriptors((left.fileno(), right.fileno()))
    # Query flags, epoll registration and held-stream read/write still work.
    with selectors.DefaultSelector() as selector:
        selector.register(right.fileno(), selectors.EVENT_READ)
        assert os.write(left.fileno(), b"descriptor control") == 18
        assert selector.select(1)
        assert os.read(right.fileno(), 64) == b"descriptor control"
    after = snapshot()
    assert before == after == before_baseline
    os.close(spare)
    left.close()
    right.close()
    print(json.dumps({"mode": mode, "descriptor_control_omission_model": omitted,
                      "actual_positive_baselines": positives, "actual_outcomes": outcomes,
                      "before": before, "after": after, "epoll_read_write_usable": True,
                      "units_activated": False, "native_runtime_authenticated": False,
                      "installation_authorized": False, "server_ready": False}, sort_keys=True))
    return 0


def main():
    resource.setrlimit(resource.RLIMIT_CPU, (60, 70))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.argv[1] in ("sealed", "landlock-only-model"):
        return native(sys.argv[1])
    directory, mode = Path(sys.argv[1]), sys.argv[2]
    admission = load("Web.Tests/admission_probe.py", "s4_descriptor_admission")
    worker = admission.RELAY
    if mode in ("dup-open", "dup2-open", "dup3-open"):
        worker.DENIED = tuple(name for name in worker.DENIED if name != mode[:-5])
    elif mode in ("fcntl-low-open", "fcntl-mid-open", "fcntl-high-open"):
        omitted = {"fcntl-low-open": 2, "fcntl-mid-open": 4, "fcntl-high-open": 6}[mode]

        def delivered(lib, context):
            number = lib.seccomp_syscall_resolve_name(b"fcntl")
            assert number >= 0
            for operation, value in ((2, 1), (4, 2), (6, 3)):
                if operation != omitted:
                    comparison = worker.Comparison(1, operation, value, 0)
                    worker.checked(lib.seccomp_rule_add_array(context, 0x50000 | errno.EPERM,
                                                              number, 1, ctypes.byref(comparison)))

        worker.add_descriptor_rules = delivered
    elif mode == "missing-fcntl":
        original_cdll = worker.ctypes.CDLL

        def delivered_cdll(name, *args, **kwargs):
            lib = original_cdll(name, *args, **kwargs)
            if name == "libseccomp.so.2":
                resolve = lib.seccomp_syscall_resolve_name
                resolve.argtypes, resolve.restype = [ctypes.c_char_p], ctypes.c_int
                def delivered(value): return -1 if value == b"fcntl" else resolve(value)
                lib.seccomp_syscall_resolve_name = delivered
            return lib

        worker.ctypes.CDLL = delivered_cdll
    elif mode == "blocking-channel":
        original = worker.prepare_client

        def blocking(descriptor):
            stream = original(descriptor)
            stream.setblocking(True)  # Actual owned accepted FD state, before sealing.
            return stream

        worker.prepare_client = blocking
    else:
        raise ValueError("unknown descriptor worker model")
    sys.argv = ["admission-fixture", str(directory), "normal"]
    return admission.main()


if __name__ == "__main__":
    sys.exit(main())

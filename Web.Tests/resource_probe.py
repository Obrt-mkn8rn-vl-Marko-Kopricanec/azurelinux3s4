"""Owned native limit/exhaustion controls and explicit whole-worker models."""

import ctypes
import errno
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import resource
import select
import socket
import sys


ROOT = Path(__file__).resolve().parents[1]


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native(mode):
    worker = load("Web/relay.py", "s4_resource_leaf")
    libc = worker.native_resource_api()
    left, right = socket.socketpair()
    left.setblocking(False)
    right.setblocking(False)
    retained = (0, 1, 2, left.fileno(), right.fileno())
    if mode == "stronger": resource.setrlimit(resource.RLIMIT_NOFILE, (12, 12))
    startup = worker.bound_descriptors(worker.FD_STARTUP_LIMIT, retained)
    expected = worker.bound_descriptors(worker.FD_FORWARD_LIMIT, retained)
    assert expected == ((12, 12) if mode == "stronger" else (16, 16))
    raise_attempt = worker.ResourceLimit64(expected[0] + 1, expected[1] + 1)
    ctypes.set_errno(0)
    assert libc.prlimit64(0, 7, ctypes.byref(raise_attempt), None) == -1
    assert ctypes.get_errno() == errno.EPERM  # Actual unprivileged kernel hard ceiling.
    assert resource.getrlimit(resource.RLIMIT_NOFILE) == expected
    worker.restrict(True)
    worker.verify_resource_limits(expected)
    worker.confine_filesystem()
    before = {str(fd): (os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in retained}
    poller = select.epoll()
    poller.register(right.fileno(), select.EPOLLIN)
    allocated = []
    try:
        for unused in range(256):
            try:
                candidate = select.epoll()
            except OSError as error:
                assert error.errno == errno.EMFILE
                exhaustion_errno = error.errno
                break
            assert candidate.fileno() < expected[0]
            allocated.append(candidate)
        else:
            raise AssertionError("descriptor exhaustion was not bounded")
        assert allocated
        assert os.write(left.fileno(), b"held channel") == 12
        assert poller.poll(1)
        assert os.read(right.fileno(), 64) == b"held channel"
        assert resource.getrlimit(resource.RLIMIT_NOFILE) == expected
        worker.verify_resource_limits(expected)  # Queries/witnesses need no spare FD.
        retired = allocated.pop()
        retired.close()
        replacement = select.epoll()
        replacement_fd = replacement.fileno()
        assert replacement_fd < expected[0]
        replacement.close()
        after = {str(fd): (os.fstat(fd).st_dev, os.fstat(fd).st_ino) for fd in retained}
        assert before == after
    finally:
        for descriptor in reversed(allocated): descriptor.close()
        poller.close()
        left.close()
        right.close()
    print(json.dumps({"mode": mode, "startup_budget": startup, "forward_budget": expected,
                      "hard_raise_errno_before_filter": errno.EPERM, "exhaustion_errno": exhaustion_errno,
                      "replacement_fd_after_release": replacement_fd, "held_identity_before": before,
                      "held_identity_after": after, "held_epoll_read_write_usable_at_exhaustion": True,
                      "queries_and_invalid_resource_witnesses_at_exhaustion_passed": True,
                      "uid": os.getuid(), "kernel_or_limit_enforcement_substituted": False,
                      "units_activated": False, "native_runtime_authenticated": False,
                      "installation_authorized": False, "server_ready": False}, sort_keys=True))
    return 0


def main():
    resource.setrlimit(resource.RLIMIT_CPU, (60, 70))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.argv[1] in ("native", "stronger"):
        return native(sys.argv[1])
    directory, mode = Path(sys.argv[1]), sys.argv[2]
    admission = load("Web.Tests/admission_probe.py", "s4_resource_admission")
    worker = admission.RELAY
    if mode == "setter-open":
        worker.DENIED = tuple(name for name in worker.DENIED if name != "setrlimit")
    elif mode == "update-open":
        worker.add_resource_rules = lambda lib, context: None
    elif mode == "unapplied-final":
        original = worker.bound_descriptors
        worker.bound_descriptors = lambda ceiling, retained=(): ((16, 16) if ceiling == 16 else original(ceiling, retained))
    elif mode == "native-query-delivery":
        original = worker.native_resource_api

        def delivered():
            libc = original()
            query = libc.prlimit64

            def changed(pid, number, new, old):
                result = query(pid, number, new, old)
                if result == 0 and old is not None: old._obj.current += 1
                return result

            libc.prlimit64 = changed
            return libc

        worker.native_resource_api = delivered
    elif mode == "missing-prlimit":
        original = worker.ctypes.CDLL

        def delivered(name, *args, **kwargs):
            lib = original(name, *args, **kwargs)
            if name == "libseccomp.so.2":
                resolve = lib.seccomp_syscall_resolve_name
                resolve.argtypes, resolve.restype = [ctypes.c_char_p], ctypes.c_int
                def missing(value): return -1 if value == b"prlimit64" else resolve(value)
                lib.seccomp_syscall_resolve_name = missing
            return lib

        worker.ctypes.CDLL = delivered
    elif mode == "retained-high":
        original = worker.connect_backend

        def relocated(uid, gid):
            connection = original(uid, gid)
            try:
                descriptor = fcntl.fcntl(connection.fileno(), fcntl.F_DUPFD_CLOEXEC, 32)
                return socket.socket(fileno=descriptor)
            finally:
                connection.close()

        worker.connect_backend = relocated
    else:
        raise ValueError("unknown resource worker model")
    sys.argv = ["admission-fixture", str(directory), "normal"]
    return admission.main()


if __name__ == "__main__":
    sys.exit(main())

"""Disposable native MDWE leaves and explicit whole-worker failure deliveries."""

import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import resource
import sys


ROOT = Path(__file__).resolve().parents[1]


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def library():
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    libc.prctl.restype = ctypes.c_int
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
    libc.mmap.restype = ctypes.c_void_p
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.mprotect.restype = ctypes.c_int
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    libc.munmap.restype = ctypes.c_int
    return libc


def native(mode):
    memory, libc = load("Web/memory.py", "s4_memory"), library()
    size, failed = os.sysconf("SC_PAGE_SIZE"), ctypes.c_void_p(-1).value
    assert libc.prctl(66, 0, 0, 0, 0) == 0
    # Positive baselines in this disposable child only; never execute bytes.
    writable = libc.mmap(None, size, 3, 0x22, -1, 0)
    executable = libc.mmap(None, size, 7, 0x22, -1, 0)
    assert writable != failed and executable != failed
    assert libc.mprotect(writable, size, 5) == 0
    assert libc.mprotect(writable, size, 3) == 0
    assert libc.munmap(executable, size) == 0
    if mode == "inherited":
        assert libc.prctl(65, 1, 0, 0, 0) == 0
    assert memory.protect_memory() == 1
    assert libc.prctl(66, 0, 0, 0, 0) == 1
    outcomes = {}

    def denied(name, operation):
        ctypes.set_errno(0)
        result = operation()
        assert result == -1 and ctypes.get_errno() == errno.EACCES, (name, result, ctypes.get_errno())
        outcomes[name] = ctypes.get_errno()

    try:
        denied("rw_to_rx", lambda: libc.mprotect(writable, size, 5))
        denied("rw_to_rwx", lambda: libc.mprotect(writable, size, 7))
        assert libc.mprotect(writable, size, 1) == 0
        denied("r_to_rx", lambda: libc.mprotect(writable, size, 5))
        assert libc.mprotect(writable, size, 0) == 0
        denied("none_to_rx", lambda: libc.mprotect(writable, size, 5))
        assert libc.mprotect(writable, size, 3) == 0
        ctypes.memmove(writable, b"data", 4)
        assert ctypes.string_at(writable, 4) == b"data"
        for flags, name in ((0x22, "private_rwx"), (0x21, "shared_rwx")):
            ctypes.set_errno(0)
            created = libc.mmap(None, size, 7, flags, -1, 0)
            assert created == failed and ctypes.get_errno() == errno.EACCES, (name, created, ctypes.get_errno())
            outcomes[name] = ctypes.get_errno()
        # MDWE intentionally permits new RX, and keeps existing executable code.
        readable_executable = libc.mmap(None, size, 5, 0x22, -1, 0)
        assert readable_executable != failed
        assert libc.mprotect(readable_executable, size, 5) == 0
        assert libc.munmap(readable_executable, size) == 0
        ctypes.set_errno(0)
        assert libc.prctl(65, 0, 0, 0, 0) == -1 and ctypes.get_errno() == errno.EPERM
        assert libc.prctl(66, 0, 0, 0, 0) == 1
        # Fork is permitted only in this leaf fixture. The real final worker
        # filter denies it. Observe actual default protection inheritance.
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)
            ctypes.set_errno(0)
            result = libc.mprotect(writable, size, 5)
            proof = {"mask": libc.prctl(66, 0, 0, 0, 0), "result": result, "errno": ctypes.get_errno()}
            os.write(write_fd, json.dumps(proof).encode())
            os.close(write_fd)
            os._exit(0 if proof == {"mask": 1, "result": -1, "errno": 13} else 1)
        os.close(write_fd)
        forked = json.loads(os.read(read_fd, 4096))
        os.close(read_fd)
        waited, status = os.waitpid(child, 0)
        assert waited == child and os.waitstatus_to_exitcode(status) == 0
        assert forked == {"mask": 1, "result": -1, "errno": 13}
    finally:
        assert libc.munmap(writable, size) == 0
    record = {"mode": mode, "page_bytes": size, "positive_wx_and_execute_gain_baselines": True,
              "native_errno": outcomes, "mask": 1, "clearing_refused": True,
              "data_read_write_remains_usable": True, "new_rx_remains_allowed": True,
              "fork_observation": forked, "actual_fork_wait_exit": os.waitstatus_to_exitcode(status),
              "code_bytes_executed": False, "kernel_enforcement_substituted": False,
              "units_activated": False, "native_runtime_authenticated": False,
              "installation_authorized": False, "server_ready": False}
    print(json.dumps(record, sort_keys=True))
    return 0


def main():
    resource.setrlimit(resource.RLIMIT_CPU, (60, 70))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.argv[1] in ("fresh", "inherited"):
        return native(sys.argv[1])
    directory, mode = Path(sys.argv[1]), sys.argv[2]
    admission = load("Web.Tests/admission_probe.py", "s4_memory_admission")
    worker = admission.RELAY
    original = worker.protect_memory
    base_cdll = worker.ctypes.CDLL

    def delivered():
        libc = library()
        get_calls = []

        def prctl(option, mask, third, fourth, fifth):
            if option == 66:
                get_calls.append(option)
                if mode == "missing":
                    ctypes.set_errno(errno.EINVAL)
                    return -1
                if mode == "no-inherit": return 3
                if mode == "readback" and len(get_calls) > 1: return 0
                if mode == "unapplied": return 0 if len(get_calls) == 1 else 1
            if option == 65:
                if mode == "install-failure":
                    ctypes.set_errno(errno.EPERM)
                    return -1
                if mode == "unapplied": return 0
            return libc.prctl(option, mask, third, fourth, fifth)

        def mmap(address, size, protections, flags, fd, offset):
            if mode == "wx-delivery" and protections == 7:
                protections = 3  # Deliberately deliver a real new data page.
            return libc.mmap(address, size, protections, flags, fd, offset)

        class Delivered:
            def __getattr__(self, name): return getattr(libc, name)

        proxy = Delivered()
        proxy.prctl, proxy.mmap = prctl, mmap
        worker.ctypes.CDLL = lambda name, *args, **kwargs: proxy if name is None else base_cdll(name, *args, **kwargs)
        try:
            return original()
        finally:
            worker.ctypes.CDLL = base_cdll

    if mode not in ("missing", "no-inherit", "readback", "unapplied", "install-failure", "wx-delivery"):
        raise ValueError("unknown memory worker delivery")
    worker.protect_memory = delivered
    sys.argv = ["admission-fixture", str(directory), "normal"]
    return admission.main()


if __name__ == "__main__":
    sys.exit(main())

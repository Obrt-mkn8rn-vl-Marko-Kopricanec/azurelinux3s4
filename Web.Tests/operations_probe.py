"""Disposable native metadata/signal calls and nonallocating IPC probes.

The Landlock-only mode deliberately omits the final seccomp filter. Whole-worker
omission/old-resolver deliveries retain the accepted admission fixture and its
actual descriptor scrubber. No accounts, units or host policy are installed.
"""

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


def native(directory, mode):
    worker = load("Web/relay.py", "s4_operations")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.argtypes = [ctypes.c_long]
    libc.syscall.restype = ctypes.c_long
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    names = worker.METADATA_DENIED + worker.IPC_DENIED
    numbers = {name: lib.seccomp_syscall_resolve_name(name.encode()) for name in names}
    assert all(number >= 0 for number in numbers.values()), numbers
    seed, link = directory / "seed", directory / "alias"
    seed.write_bytes(b"private metadata baseline")
    link.symlink_to(seed.name)
    descriptor = os.open(seed, os.O_RDONLY | os.O_CLOEXEC)
    pidfd = os.pidfd_open(os.getpid())
    path, alias = ctypes.c_char_p(os.fsencode(seed)), ctypes.c_char_p(os.fsencode(link))
    attribute, value = ctypes.c_char_p(b"user.s4_operations"), ctypes.c_char_p(b"baseline")
    # Valid zero-signal queue information: SI_QUEUE, native 64-bit siginfo_t.
    info = (ctypes.c_int * 32)()
    info[2], info[4], info[5] = -1, os.getpid(), os.getuid()
    metadata = {
        "chmod": (path, 0o600), "fchmod": (descriptor, 0o600),
        "fchmodat": (-100, path, 0o600), "fchmodat2": (-100, path, 0o600, 0),
        "chown": (path, os.getuid(), os.getgid()),
        "fchown": (descriptor, os.getuid(), os.getgid()),
        "lchown": (alias, os.getuid(), os.getgid()),
        "fchownat": (-100, alias, os.getuid(), os.getgid(), 0x100),
        "utime": (path, 0), "utimes": (path, 0),
        "futimesat": (-100, path, 0), "utimensat": (-100, path, 0, 0),
        "setxattr": (path, attribute, value, 8, 0),
        "lsetxattr": (path, attribute, value, 8, 0),
        "fsetxattr": (descriptor, attribute, value, 8, 0),
        "removexattr": (path, attribute), "lremovexattr": (path, attribute),
        "fremovexattr": (descriptor, attribute),
    }
    ipc = {
        "kill": (os.getpid(), 0), "tkill": (os.getpid(), 0),
        "tgkill": (os.getpid(), os.getpid(), 0),
        "rt_sigqueueinfo": (os.getpid(), 0, ctypes.byref(info)),
        "rt_tgsigqueueinfo": (os.getpid(), os.getpid(), 0, ctypes.byref(info)),
        "pidfd_send_signal": (pidfd, 0, 0, 0),
        # No IPC_CREAT, no valid existing IDs/pointers and no allocated objects.
        "semget": (0, 0, 0), "semop": (-1, 0, 0), "semtimedop": (-1, 0, 0, 0),
        "semctl": (-1, 0, 0, 0), "msgget": (-1, 0),
        "msgsnd": (-1, 0, 1, 0x800), "msgrcv": (-1, 0, 1, 0, 0x800),
        "msgctl": (-1, 0, 0), "shmget": (0, 0, 0), "shmat": (-1, 0, 0),
        "shmdt": (0,), "shmctl": (-1, 0, 0),
        "mq_open": (ctypes.c_char_p(b"/"), 0, 0, 0),
        "mq_unlink": (ctypes.c_char_p(b"/"),),
        "mq_timedsend": (-1, 0, 0, 0, 0), "mq_timedreceive": (-1, 0, 0, 0, 0),
        "mq_notify": (-1, 0), "mq_getsetattr": (-1, 0, 0),
        "add_key": (0, 0, 0, 0, 0), "request_key": (0, 0, 0, 0),
        "keyctl": (-1, 0, 0, 0, 0),
    }

    def call(name, arguments):
        ctypes.set_errno(0)
        result = libc.syscall(ctypes.c_long(numbers[name]),
                              *(ctypes.c_long(arg) if isinstance(arg, int) else arg for arg in arguments))
        return {"result": result, "errno": ctypes.get_errno()}

    def snapshot():
        os.lseek(descriptor, 0, os.SEEK_SET)
        content = os.read(descriptor, 128).decode()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_size", "st_mtime_ns", "st_ctime_ns")
        return {"content": content, "seed": [getattr(seed.stat(), field) for field in fields],
                "link": [getattr(link.lstat(), field) for field in fields],
                "xattr": os.getxattr(descriptor, "user.s4_operations").decode()}

    try:
        baseline = {}
        for name, args in metadata.items():
            if "removexattr" in name:
                os.setxattr(descriptor, "user.s4_operations", b"baseline")
            baseline[name] = call(name, args)
            assert baseline[name] == {"result": 0, "errno": 0}, (name, baseline[name])
        os.setxattr(descriptor, "user.s4_operations", b"baseline")
        for name, args in ipc.items():
            baseline[name] = call(name, args)
            if name in worker.IPC_DENIED[:6]:
                assert baseline[name] == {"result": 0, "errno": 0}, (name, baseline[name])
            else:
                assert baseline[name]["result"] == -1, (name, baseline[name])
        before = snapshot()
        worker.restrict(False)
        if mode == "sealed":
            worker.restrict(True)
            worker.verify_operations()
            outcomes = {name: call(name, args) for name, args in (metadata | ipc).items()}
            assert all(item == {"result": -1, "errno": errno.EPERM} for item in outcomes.values()), outcomes
            after = snapshot()
            assert before == after
        elif mode == "landlock-only":
            worker.confine_filesystem()  # Actual accepted layer, no final filter.
            outcomes = {}
            for name, args in metadata.items():
                if "removexattr" in name:
                    os.setxattr(descriptor, "user.s4_operations", b"baseline")
                outcomes[name] = call(name, args)
                assert outcomes[name] == {"result": 0, "errno": 0}, (name, outcomes[name])
            outcomes["kill"] = call("kill", ipc["kill"])
            assert outcomes["kill"] == {"result": 0, "errno": 0}
            after = None  # Private metadata is deliberately changed by this model.
        else:
            raise ValueError("unknown native operations fixture")
        print(json.dumps({"mode": mode, "numbers": numbers, "baseline": baseline, "outcomes": outcomes,
                          "metadata_positive_baseline_names": list(metadata),
                          "zero_signal_baseline_names": list(worker.IPC_DENIED[:6]),
                          "before": before, "after": after, "ipc_objects_allocated": False,
                          "signal_delivery_performed": False, "landlock_only_model": mode == "landlock-only",
                          "units_activated": False, "installation_authorized": False, "server_ready": False}, sort_keys=True))
    finally:
        os.close(pidfd)
        os.close(descriptor)
    return 0


def main():
    resource.setrlimit(resource.RLIMIT_CPU, (60, 70))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    directory, mode = Path(sys.argv[1]), sys.argv[2]
    if mode in ("sealed", "landlock-only"):
        resource.setrlimit(resource.RLIMIT_CPU, (10, 15))
        return native(directory, mode)
    admission = load("Web.Tests/admission_probe.py", "s4_operations_admission")
    worker = admission.RELAY
    if mode.endswith("-open"):
        groups = {"metadata-open": worker.METADATA_DENIED,
                  "signals-open": worker.IPC_DENIED[:6], "sysv-open": worker.IPC_DENIED[6:18],
                  "mqueue-open": worker.IPC_DENIED[18:24], "keys-open": worker.IPC_DENIED[24:]}
        omitted = groups[mode]
        worker.DENIED = tuple(name for name in worker.DENIED if name not in omitted)
    elif mode == "old-resolver":
        original = worker.ctypes.CDLL

        def delivered(name, *args, **kwargs):
            library = original(name, *args, **kwargs)
            if name != "libseccomp.so.2":
                return library
            resolver = library.seccomp_syscall_resolve_name
            resolver.argtypes, resolver.restype = [ctypes.c_char_p], ctypes.c_int

            class LegacyNames:
                def __getattr__(self, key):
                    return getattr(library, key)

            # A function attribute accepts the production prototype assignments.
            proxy = LegacyNames()
            proxy.seccomp_syscall_resolve_name = lambda value: -1 if value == b"fchmodat2" else resolver(value)
            return proxy

        worker.ctypes.CDLL = delivered
    else:
        raise ValueError("unknown worker operations fixture")
    sys.argv = ["admission-fixture", str(directory), "normal"]
    return admission.main()


if __name__ == "__main__":
    sys.exit(main())

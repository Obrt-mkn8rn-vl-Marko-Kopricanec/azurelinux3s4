"""Disposable Landlock leaf and whole-worker failure projections.

Native leaf mode substitutes no filesystem path, syscall or enforcement. The
ABI3 mode substitutes only the version query, using the actual host kernel for
installation/challenges. Worker modes reuse the accepted admission fixture's
caller/root-FD/UID/GID/journal deliveries and inject one disclosed failure.
"""
import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import resource
import socket
import subprocess
import sys
import threading
import types

ROOT = Path(__file__).resolve().parents[1]


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def delivered(worker, mode):
    original = worker.confine_filesystem

    def confine():
        actual_cdll = worker.ctypes.CDLL
        libc = actual_cdll(None, use_errno=True)
        libc.syscall.argtypes = [ctypes.c_long]
        libc.syscall.restype = ctypes.c_long

        def syscall(number, *args):
            query = number.value == 444 and args[-1].value == 1
            if query and mode == "query-failure":
                ctypes.set_errno(errno.ENOSYS)
                return -1
            if query and mode in ("abi2", "abi3"):
                return 2 if mode == "abi2" else 3
            if number.value == 444 and not query and mode == "create-failure":
                ctypes.set_errno(errno.EIO)
                return -1
            if number.value == 446 and mode == "restrict-failure":
                ctypes.set_errno(errno.EACCES)
                return -1
            if number.value == 446 and mode == "unapplied":
                return 0  # API success without installation must fail the real challenge.
            return libc.syscall(number, *args)

        proxy = types.SimpleNamespace(syscall=syscall, prctl=libc.prctl)
        worker.ctypes.CDLL = lambda *args, **kwargs: proxy
        try:
            return original()
        finally:
            worker.ctypes.CDLL = actual_cdll
    return confine


def native(directory, mode):
    worker = load("Web/relay.py", "s4_filesystem_worker")
    seed, folder = directory / "seed", directory / "folder"
    payload = seed.read_bytes()
    held = os.open(seed, os.O_RDONLY | os.O_CLOEXEC)
    # Positive DAC/path/exec controls run before confinement. They leave the
    # existing leaf content/identity unchanged and remove temporary controls.
    for flags in (os.O_RDONLY, os.O_WRONLY):
        os.close(os.open(seed, flags))
    os.close(os.open(folder, os.O_RDONLY | os.O_DIRECTORY))
    created = directory / "creation-control"
    created.write_bytes(b"baseline")
    created.unlink()
    made = directory / "directory-control"
    made.mkdir()
    made.rmdir()
    stream = socket.socket(socket.AF_UNIX)
    stream.bind(str(directory / "socket-control"))
    stream.close()
    (directory / "socket-control").unlink()
    true = subprocess.run(["/usr/bin/true"], check=False)
    assert true.returncode == 0
    alias = f"/proc/self/fd/{held}"
    reopened = os.open(alias, os.O_RDONLY)
    assert os.fstat(reopened).st_ino == os.fstat(held).st_ino
    os.close(reopened)
    if mode == "abi3":
        worker.confine_filesystem = delivered(worker, mode)
    worker.restrict(False)  # Actual NNP/early socket filter, not the final exec-denying filter.
    abi, rights = worker.confine_filesystem()
    refused = {}

    def deny(name, operation):
        try:
            result = operation()
        except OSError as error:
            assert error.errno == errno.EACCES, (name, error)
            refused[name] = error.errno
        else:
            if hasattr(result, "close"):
                result.close()
            elif isinstance(result, int):
                os.close(result)
            raise AssertionError("Landlock allowed " + name)

    deny("read", lambda: os.open(seed, os.O_RDONLY))
    deny("write", lambda: os.open(seed, os.O_WRONLY))
    deny("readonly_truncate", lambda: os.open(seed, os.O_RDONLY | os.O_TRUNC))
    deny("truncate", lambda: os.truncate(seed, 0))
    deny("directory_read", lambda: os.open(folder, os.O_RDONLY | os.O_DIRECTORY))
    deny("create", lambda: os.open(directory / "new", os.O_WRONLY | os.O_CREAT, 0o600))
    deny("mkdir", lambda: os.mkdir(directory / "newdir"))
    deny("remove", lambda: os.unlink(seed))
    deny("rmdir", lambda: os.rmdir(folder))
    deny("rename", lambda: os.rename(seed, directory / "renamed"))
    deny("hardlink", lambda: os.link(seed, directory / "linked"))
    deny("symlink", lambda: os.symlink(seed, directory / "symlink"))
    deny("fifo", lambda: os.mkfifo(directory / "fifo"))
    new_stream = socket.socket(socket.AF_UNIX)
    try:
        deny("socket_bind", lambda: new_stream.bind(str(directory / "new.sock")))
    finally:
        new_stream.close()
    deny("kernel_fd_reopen", lambda: os.open(alias, os.O_RDONLY))
    # If exec were accidentally allowed, the child would exit without its
    # required JSON proof; it cannot become a passing assertion.
    deny("execute", lambda: os.execv("/usr/bin/true", ["true"]))
    assert os.read(held, len(payload) + 1) == payload  # Explicit existing-FD limit.
    os.close(held)
    path_only = os.open(seed, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
    assert os.fstat(path_only).st_size == len(payload)  # Explicit metadata/O_PATH limit.
    os.close(path_only)
    record = {"abi": abi, "handled_access_fs": rights, "native_errno": refused,
              "version_query_substituted": mode == "abi3", "kernel_enforcement_substituted": False,
              "preexisting_read_descriptor_remains_usable": True, "metadata_and_o_path_remain_available": True,
              "positive_true_baseline_executed": True, "final_exec_denial_filter_installed": False,
              "units_activated": False, "installation_authorized": False, "server_ready": False}
    print(json.dumps(record, sort_keys=True))
    return 0


def main():
    resource.setrlimit(resource.RLIMIT_CPU, (60, 70))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    directory, mode = Path(sys.argv[1]), sys.argv[2]
    if mode in ("native", "abi3"):
        resource.setrlimit(resource.RLIMIT_CPU, (10, 15))
        return native(directory, mode)
    admission = load("Web.Tests/admission_probe.py", "s4_filesystem_admission")
    event, thread = None, None
    if mode == "threaded":
        event = threading.Event()
        thread = threading.Thread(target=event.wait)
        thread.start()  # Before the actual final TSYNC process-creation filter.
    elif mode in ("query-failure", "abi2", "create-failure", "restrict-failure", "unapplied"):
        admission.RELAY.confine_filesystem = delivered(admission.RELAY, mode)
    else:
        raise ValueError("unknown filesystem fixture")
    sys.argv = ["admission-fixture", str(directory), "normal"]
    try:
        return admission.main()
    finally:
        if event is not None:
            event.set()
            thread.join(2)
            assert not thread.is_alive()


if __name__ == "__main__":
    sys.exit(main())

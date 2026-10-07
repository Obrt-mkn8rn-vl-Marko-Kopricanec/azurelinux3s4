"""Native file observations and disclosed local whole-worker refusal controls."""

import ctypes
import importlib.util
import json
import mmap
import os
from pathlib import Path
import resource
import signal
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]


def load(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def native():
    runtime = load("Web/runtime.py", "s4_native_runtime")
    ctypes.CDLL("libseccomp.so.2")
    with runtime.RuntimeStartup() as startup:
        proof = runtime.observe_runtime()
        startup.disarm()
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    assert signal.getsignal(signal.SIGALRM) == signal.SIG_DFL
    proof.update(startup_timer_retired=True, kernel_enforcement_substituted=False,
                 root_file_owner_or_path_substituted=False, units_activated=False)
    print(json.dumps(proof, sort_keys=True))
    return 0


def main():
    resource.setrlimit(resource.RLIMIT_CPU, (60, 70))
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.argv[1:] == ["native"]:
        return native()
    directory, mode = Path(sys.argv[1]), sys.argv[2]
    admission = load("Web.Tests/admission_probe.py", "s4_runtime_admission")
    worker = admission.RELAY
    temporary, mapped, mapped_path = None, None, None
    if mode in ("unstable-maps", "wrong-mapped-inode"):
        original = worker.runtime_maps
        calls = []

        def delivered(data=None):
            calls.append(None)
            records, images = original(data)
            if mode == "unstable-maps" and len(calls) == 2:
                records = records + ((1, 2, "r-xp", 0, (0, 0, 0), "[vdso]"),)
            elif mode == "wrong-mapped-inode":
                images = {(*key[:2], key[2] + 1): path for key, path in images.items()}
            return records, images

        worker.runtime_maps = delivered
    elif mode == "anonymous-exec":
        mapped = mmap.mmap(-1, 4096, flags=mmap.MAP_PRIVATE, prot=mmap.PROT_READ | mmap.PROT_EXEC)
        assert len(mapped) == 4096  # A setup failure must not become refusal evidence.
    elif mode == "unprotected-file-exec":
        temporary = tempfile.NamedTemporaryFile(dir="/tmp", prefix="s4-mapped-runtime-", delete=False)
        mapped_path = Path(temporary.name)
        temporary.write(b"private mapped fixture\n" * 256)
        temporary.flush()
        mapped = mmap.mmap(temporary.fileno(), 4096, prot=mmap.PROT_READ | mmap.PROT_EXEC)
        assert len(mapped) == 4096
        temporary.close()
        temporary = None  # The actual mapping survives; no backing FD exemption.
    elif mode == "blocked-alarm":
        signal.pthread_sigmask(signal.SIG_BLOCK, [signal.SIGALRM])
        assert signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK, ())
    elif mode == "startup-expiry":
        # Scale only the startup timer; run the actual final filter and actual
        # Landlock first, then let the kernel timer interrupt an ordinary sleep.
        worker.STARTUP_SECONDS = 2
        original = worker.confine_filesystem

        def delayed():
            result = original()
            libc = ctypes.CDLL(None)
            assert libc.prctl(21, 0, 0, 0, 0) == 2
            os.write(2, b"FIXTURE_FINAL_FILTER_LANDLOCK_READY\n")
            time.sleep(4)
            raise AssertionError("the actual startup timer did not expire")

        worker.confine_filesystem = delayed
    else:
        raise ValueError("unknown runtime worker fixture")
    sys.argv = ["admission-fixture", str(directory), "normal"]
    try:
        return admission.main()
    finally:
        if mapped is not None:
            mapped.close()
        if temporary is not None:
            temporary.close()
        if mapped_path is not None:
            mapped_path.unlink()


if __name__ == "__main__":
    sys.exit(main())

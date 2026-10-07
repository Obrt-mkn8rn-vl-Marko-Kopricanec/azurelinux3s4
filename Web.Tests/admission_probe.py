"""Local admission projection; no accounts, units, runtime or host policy install.

Only the root-fd, trusted root IDs, journal PATH and process-identity delivery
are substituted. Actual inherited stdio, O_PATH walk/connect, peer credentials,
inode/mount rechecks, native filters and forwarding use production functions.
"""

import importlib.util
import os
from pathlib import Path
import socket
import sys


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("s4_admission_relay", ROOT / "Web/relay.py")
RELAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELAY)


def main():
    directory, mode = Path(sys.argv[1]), sys.argv[2]
    RELAY.ROOT_UID = os.getuid()
    RELAY.ROOT_GID = os.getgid()
    RELAY.JOURNAL = str(directory / "journal.sock")
    RELAY.backend_root = lambda: os.open(directory, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    # This models a checked caller and dedicated account allocation ONLY.
    # The current Debian UID is also the fixture server; no native multi-UID
    # account, root/capability/NNP or PID1 authorization proof is inferred.
    context = (os.getuid() + 1, os.getuid(), os.getgid())
    RELAY.process_identity = lambda: context
    if mode == "extra-fd":
        calls, extras = [], []
        original = RELAY.close_runtime_extras

        def observed():
            calls.append(None)
            if len(calls) == 2:
                extras.append(socket.socket(socket.AF_UNIX))
            return context

        def scrubbed(backend):
            descriptor = extras[0].fileno()
            original(backend)
            try:
                os.fstat(descriptor)
            except OSError as error:
                import errno
                assert error.errno == errno.EBADF
            else:
                raise AssertionError("startup lookup descriptor survived")

        RELAY.process_identity = observed
        RELAY.close_runtime_extras = scrubbed
    elif mode == "changed-accounts":
        calls = []

        def changed():
            calls.append(None)
            return context if len(calls) == 1 else (context[0] + 1, *context[1:])

        RELAY.process_identity = changed
    elif mode == "replace-leaf":
        original = RELAY.backend_path
        calls = []
        replacement = socket.socket(socket.AF_UNIX)

        def replace(uid, gid):
            calls.append(None)
            if len(calls) == 2:
                path = directory / "run/azurelinux3s4-web/http.sock"
                path.rename(path.with_name("retained-original.sock"))
                replacement.bind(str(path))
                path.chmod(0o666)
                replacement.listen(1)
            return original(uid, gid)

        RELAY.backend_path = replace
    elif mode != "normal":
        raise ValueError("unknown admission fixture")
    sys.argv = ["worker"]
    return RELAY.main()


if __name__ == "__main__":
    sys.exit(main())

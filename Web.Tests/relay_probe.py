"""Local projection of the maintained relay; no unit or server activation.

The historical forwarding projection delivers a private PATH and substitutes
credential/journal/backend admission, optionally scales clocks or injects a
failure. It proves the accepted sealing/copy leaves, not the new admission.
New admission controls are maintained separately in test_web_admission.py.
"""

import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys


SPEC = importlib.util.spec_from_file_location("s4_relay", Path(__file__).resolve().parents[1] / "Web/relay.py")
RELAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELAY)


def refused(operation):
    try:
        value = operation()
    except OSError as error:
        if error.errno != errno.EPERM:
            raise
        return error.errno
    if hasattr(value, "close"):
        value.close()
    raise AssertionError("sealed operation allowed")


def native(descriptor):
    inherited = socket.socket(fileno=int(descriptor))
    positive = socket.socket(socket.AF_INET)
    positive.close()
    pair = socket.socketpair()
    pair[0].sendmsg([b"control"])
    assert pair[1].recvmsg(64)[0] == b"control"
    RELAY.restrict(False)
    try:
        value = socket.socket(socket.AF_INET)
    except OSError as error:
        assert error.errno == errno.EAFNOSUPPORT
    else:
        value.close()
        raise AssertionError("early IP socket creation allowed")
    RELAY.restrict(True)
    RELAY.verify_seal(inherited)
    result = {"scope": "actual Debian native relay seccomp leaves; no unit or nginx activation",
              "new_unix": refused(lambda: socket.socket(socket.AF_UNIX)),
              "new_pair": refused(socket.socketpair),
              "connect": refused(lambda: inherited.connect(inherited.getpeername())),
              "sendmsg": refused(lambda: pair[0].sendmsg([b"x"])),
              "recvmsg": refused(lambda: pair[1].recvmsg(64)),
              "sendto_fastopen": refused(lambda: inherited.sendto(b"x", socket.MSG_FASTOPEN,
                                                                   inherited.getpeername())),
              "setsockopt": refused(lambda: inherited.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)),
              "systemd_units_executed": False, "nginx_executed": False, "server_ready": False}
    libc = ctypes.CDLL(None, use_errno=True)
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    for name in ("io_uring_setup", "pidfd_getfd", "clone3", "execveat", "bpf"):
        number = lib.seccomp_syscall_resolve_name(name.encode())
        assert number != -1
        outcome = libc.syscall(number, 0, 0, 0, 0, 0, 0)
        assert outcome == -1 and ctypes.get_errno() == errno.EPERM, (name, outcome, ctypes.get_errno())
        result[name] = ctypes.get_errno()
    for name in ("new_unix", "connect", "recvmsg", "sendmsg", "sendto_fastopen"):
        assert result[name] == errno.EPERM
    pair[0].close()
    pair[1].close()
    assert os.read(inherited.fileno(), 64) == b"fixture request"
    os.write(inherited.fileno(), b"fixture response")
    inherited.close()
    print(json.dumps(result, sort_keys=True))


def main():
    mode, argument = sys.argv[1:3]
    if mode == "native":
        native(argument)
        return 0
    if mode == "close-fds":
        RELAY.close_inherited()
        try:
            os.fstat(int(argument))
        except OSError as error:
            assert error.errno == errno.EBADF
        else:
            raise AssertionError("extra inherited FD remains open")
        print(json.dumps({"extra_fd_closed": True}))
        return 0
    # Disclosed historical seccomp/forwarding projection: no production
    # credential, journal or backend ancestry acceptance follows from it.
    RELAY.process_identity = lambda: (os.getuid(), os.getuid(), os.getgid())
    RELAY.admit_logging = lambda: None

    def private_backend(uid, gid):
        connection = socket.socket(socket.AF_UNIX)
        try:
            connection.settimeout(5)
            connection.connect(argument)
            connection.setblocking(False)
            return connection
        except BaseException:
            connection.close()
            raise

    RELAY.connect_backend = private_backend
    if mode == "idle":
        RELAY.IDLE_SECONDS = 0.2
        RELAY.TOTAL_SECONDS = 2
    elif mode == "total":
        RELAY.IDLE_SECONDS = 2
        RELAY.TOTAL_SECONDS = 0.3
    elif mode == "filter-failure":
        original = RELAY.restrict

        def fail_final(final):
            if final:
                raise OSError("fixture final filter failure")
            original(final)

        RELAY.restrict = fail_final
    elif mode == "challenge-failure":
        def fail_challenge(connection):
            raise RuntimeError("fixture seal challenge failure")

        RELAY.verify_seal = fail_challenge
    elif mode != "forward":
        raise ValueError("unknown fixture mode")
    sys.argv = ["worker"]
    return RELAY.main()


if __name__ == "__main__":
    sys.exit(main())

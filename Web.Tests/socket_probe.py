"""Disposable native seccomp/socket projection, not systemd unit execution."""

import ctypes
import errno
import json
import socket
import sys


class Comparison(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                ("a", ctypes.c_uint64), ("b", ctypes.c_uint64)]


def checked(result):
    if result < 0:
        raise OSError(-result, "native seccomp operation refused")


def restrict(calls):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                          ctypes.c_ulong, ctypes.c_ulong]
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "cannot set no-new-privileges")
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                         ctypes.c_uint, ctypes.POINTER(Comparison)]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    context = lib.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW, native architecture only
    if not context:
        raise RuntimeError("seccomp_init failed")
    try:
        call = lib.seccomp_syscall_resolve_name(b"socket")
        # Match systemd v255's single AF_UNIX allow-list: below and above refuse.
        for op in (2, 6):  # SCMP_CMP_LT, SCMP_CMP_GT
            comparison = Comparison(0, op, socket.AF_UNIX, 0)
            checked(lib.seccomp_rule_add_array(context, 0x50000 | errno.EAFNOSUPPORT,
                                               call, 1, ctypes.byref(comparison)))
        for name in calls:
            number = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number < 0:
                raise RuntimeError("unknown native syscall: " + name)
            checked(lib.seccomp_rule_add_array(context, 0x50000 | errno.EPERM, number, 0, None))
        checked(lib.seccomp_load(context))
    finally:
        lib.seccomp_release(context)


def refused(function, expected):
    try:
        value = function()
        if hasattr(value, "close"):
            value.close()
    except OSError as error:
        if error.errno != expected:
            raise
        return error.errno
    raise AssertionError("operation was allowed")


def main():
    mode, target, listen_path, descriptor, reconnect_port, raw_calls = sys.argv[1:]
    calls = json.loads(raw_calls)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM):
        pass  # Positive unfiltered socket control on this kernel.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as baseline:
        baseline.connect(target)
    pair = socket.socketpair()
    pair[0].sendall(b"b")
    assert pair[1].recvmsg(1)[0] == b"b"  # Positive ancillary-call control.
    restrict(calls)
    result = {"scope": "native leaf seccomp/socket projection only",
              "systemd_units_executed": False, "private_network_verified": False,
              "new_inet": refused(lambda: socket.socket(socket.AF_INET), errno.EAFNOSUPPORT),
              "new_inet6": refused(lambda: socket.socket(socket.AF_INET6), errno.EAFNOSUPPORT),
              "new_netlink": refused(lambda: socket.socket(socket.AF_NETLINK), errno.EAFNOSUPPORT),
              "new_packet": refused(lambda: socket.socket(socket.AF_PACKET), errno.EAFNOSUPPORT)}
    if mode == "backend":
        with socket.socket(socket.AF_UNIX) as attempt:
            result["unix_connect"] = refused(lambda: attempt.connect(target), errno.EPERM)
        with socket.socket(socket.AF_UNIX) as listener:
            listener.settimeout(5)
            listener.bind(listen_path)
            listener.listen(1)
            with listener.accept()[0] as connection:
                connection.settimeout(5)
                message = connection.recv(4096)
                assert message == b"fixture request"
                connection.sendall(b"fixture response")
                result["unix_listener_response"] = True
    elif mode == "proxy":
        result["recvmsg"] = refused(lambda: pair[1].recvmsg(1), errno.EPERM)
        with socket.socket(fileno=int(descriptor)) as inherited:
            inherited.settimeout(5)
            with inherited.accept()[0] as connection:
                connection.settimeout(5)
                with socket.socket(socket.AF_UNIX) as backend:
                    backend.settimeout(5)
                    backend.connect(target)
                    backend.sendall(connection.recv(4096))
                    response = backend.recv(4096)
                    assert response == b"fixture response"
                    connection.sendall(response)
                result["inherited_tcp_unix_forwarding"] = True
                # Demonstrate why the candidate proxy still needs egress policy.
                # connect(AF_UNSPEC) disconnects an inherited IPv4 connection;
                # the address-family socket() filter does not police reuse.
                libc = ctypes.CDLL(None, use_errno=True)
                libc.connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
                address = ctypes.create_string_buffer(16)
                if libc.connect(connection.fileno(), address, 16) != 0:
                    raise OSError(ctypes.get_errno(), "AF_UNSPEC disconnect failed")
                connection.connect(("127.0.0.1", int(reconnect_port)))
                connection.sendall(b"fixture reconnect")
                assert connection.recv(4096) == b"fixture reconnect observed"
                result["inherited_tcp_reconnect_allowed"] = True
    else:
        raise ValueError("unknown fixture mode")
    for connection in pair:
        connection.close()
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()

"""One accepted TCP connection to one Unix backend; no reconnect after sealing.

Candidate worker only. Installation, systemd confinement, protected backend
identity/ancestry and native Azure runtime admission are separate prerequisites.
"""

import ctypes
import errno
import os
import platform
import resource
import selectors
import socket
import stat
import sys
import time


BACKEND = "/run/azurelinux3s4-web/http.sock"
BUFFER = 65536
IDLE_SECONDS = 30
TOTAL_SECONDS = 300
DENIED = (
    "socket", "socketpair", "connect", "accept", "accept4",
    # Fast Open through sendto/sendmsg is also a connection initiation route.
    # Forward through read/write only; never permit caller-controlled flags.
    "sendto", "sendmsg", "sendmmsg", "recvmsg", "recvmmsg", "setsockopt", "ioctl",
    "pidfd_getfd", "io_uring_setup", "io_uring_enter", "io_uring_register", "bpf",
    "execve", "execveat", "clone", "clone3", "fork", "vfork", "unshare", "setns",
    "ptrace", "process_vm_readv", "process_vm_writev",
)


class Comparison(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                ("a", ctypes.c_uint64), ("b", ctypes.c_uint64)]


def checked(result):
    if result < 0:
        raise OSError(-result, "relay seccomp operation refused")


def restrict(final):
    if platform.machine() not in ("x86_64", "aarch64"):
        raise ValueError("unsupported native architecture")
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                          ctypes.c_ulong, ctypes.c_ulong]
    if libc.prctl(38, 1, 0, 0, 0):  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "no-new-privileges refused")
    lib = ctypes.CDLL("libseccomp.so.2")
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                         ctypes.c_uint, ctypes.POINTER(Comparison)]
    lib.seccomp_attr_set.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint32]
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    context = lib.seccomp_init(0x7fff0000)  # ALLOW; native ABI only, bad ABI kills.
    if not context:
        raise RuntimeError("seccomp_init failed")
    try:
        checked(lib.seccomp_attr_set(context, 4, 1))  # CTL_TSYNC, all current threads
        checked(lib.seccomp_attr_set(context, 2, 0x80000000))  # ACT_BADARCH: KILL_PROCESS
        if final:
            for name in DENIED:
                number = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
                if number == -1:  # __NR_SCMP_ERROR; other negative values are pseudo IDs.
                    raise ValueError("unknown syscall: " + name)
                checked(lib.seccomp_rule_add_array(context, 0x50000 | errno.EPERM, number, 0, None))
        else:
            number = lib.seccomp_syscall_resolve_name(b"socket")
            if number == -1:
                raise ValueError("socket syscall unknown")
            for operation in (2, 6):  # SCMP_CMP_LT, GT: only AF_UNIX can be created.
                comparison = Comparison(0, operation, socket.AF_UNIX, 0)
                checked(lib.seccomp_rule_add_array(context, 0x50000 | errno.EAFNOSUPPORT,
                                                   number, 1, ctypes.byref(comparison)))
        checked(lib.seccomp_load(context))
        if libc.prctl(39, 0, 0, 0, 0) != 1 or libc.prctl(21, 0, 0, 0, 0) != 2:
            raise RuntimeError("kernel did not report NNP/filter mode")
    finally:
        lib.seccomp_release(context)


def verify_seal(connection):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.connect.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
    address = ctypes.create_string_buffer(16)  # Actual AF_UNSPEC disconnect challenge.
    if libc.connect(connection.fileno(), address, 16) != -1 or ctypes.get_errno() != errno.EPERM:
        raise RuntimeError("connect denial challenge failed")
    try:
        created = socket.socket(socket.AF_UNIX)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise
    else:
        created.close()
        raise RuntimeError("socket denial challenge failed")
    connection.getpeername()  # The challenge must leave the accepted connection intact.


def forward(client, backend):
    # At most two BUFFER-sized queues; half-close each destination only after
    # its queued data drains. No connection setup, recvmsg or flagged send calls.
    streams = {client.fileno(): backend.fileno(), backend.fileno(): client.fileno()}
    objects = {stream.fileno(): stream for stream in (client, backend)}
    buffers = {descriptor: bytearray() for descriptor in streams}
    readable = set(streams)
    write_open = set(streams)
    started = last_progress = time.monotonic()
    with selectors.DefaultSelector() as selector:
        registered = set()
        while readable or any(buffers.values()):
            now = time.monotonic()
            remaining = min(started + TOTAL_SECONDS - now, last_progress + IDLE_SECONDS - now)
            if remaining <= 0:
                raise TimeoutError("relay connection deadline reached")
            for descriptor, destination in streams.items():
                events = 0
                if descriptor in readable and len(buffers[destination]) < BUFFER:
                    events |= selectors.EVENT_READ
                if buffers[descriptor]:
                    events |= selectors.EVENT_WRITE
                if events:
                    if descriptor in registered:
                        selector.modify(descriptor, events)
                    else:
                        selector.register(descriptor, events)
                        registered.add(descriptor)
                elif descriptor in registered:
                    selector.unregister(descriptor)
                    registered.remove(descriptor)
            for key, events in selector.select(remaining):
                descriptor = key.fd
                destination = streams[descriptor]
                if events & selectors.EVENT_READ:
                    try:
                        data = os.read(descriptor, BUFFER - len(buffers[destination]))
                    except BlockingIOError:
                        pass
                    else:
                        if data:
                            buffers[destination].extend(data)
                            last_progress = time.monotonic()
                        else:
                            readable.remove(descriptor)
                if events & selectors.EVENT_WRITE:
                    try:
                        count = os.write(descriptor, buffers[descriptor])
                    except BlockingIOError:
                        pass
                    else:
                        if count <= 0:
                            raise OSError("relay write made no progress")
                        del buffers[descriptor][:count]
                        last_progress = time.monotonic()
            for source, destination in streams.items():
                if source not in readable and not buffers[destination] and destination in write_open:
                    objects[destination].shutdown(socket.SHUT_WR)
                    write_open.remove(destination)


def prepare_client(descriptor):
    connection = socket.socket(fileno=descriptor)
    try:
        if (connection.family not in (socket.AF_INET, socket.AF_INET6)
                or connection.type != socket.SOCK_STREAM
                or connection.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)):
            raise ValueError("an accepted IPv4/IPv6 stream is required")
        connection.getpeername()
        # Avoid implicit connection initiation from ordinary writes. Linux ABI:
        # TCP_FASTOPEN_CONNECT=30. An established socket cannot change this
        # option: observe zero, otherwise refuse. Sealing also denies setsockopt.
        if connection.getsockopt(socket.IPPROTO_TCP, 30) != 0:
            raise ValueError("Fast Open connect remains enabled")
        connection.setblocking(False)
        return connection
    except BaseException:
        connection.close()
        raise


def close_inherited():
    for descriptor in (1, 2):
        if stat.S_ISSOCK(os.fstat(descriptor).st_mode):
            stream = socket.socket(fileno=descriptor)
            try:
                if stream.family != socket.AF_UNIX:
                    raise ValueError("stdout/stderr cannot be inherited IP sockets")
            finally:
                stream.detach()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.close_range.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
    if libc.close_range(3, 0xffffffff, 0):
        raise OSError(ctypes.get_errno(), "cannot close extra inherited descriptors")


def main():
    try:
        if len(sys.argv) != 1:
            raise ValueError("no relay overrides are accepted")
        resource.setrlimit(resource.RLIMIT_CPU, (60, 70))
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        close_inherited()
        with prepare_client(0) as client:
            restrict(False)
            with socket.socket(socket.AF_UNIX) as backend:
                backend.settimeout(5)
                backend.connect(BACKEND)
                backend.setblocking(False)
                restrict(True)
                verify_seal(client)
                forward(client, backend)
    except (OSError, ValueError, RuntimeError, MemoryError) as error:
        print("Web relay refused: " + str(error), file=sys.stderr)
        return 75
    return 0


if __name__ == "__main__":
    sys.exit(main())

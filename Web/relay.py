"""One accepted TCP connection to one Unix backend; no reconnect after sealing.

Candidate worker only. Credential/path observations do not authenticate the
runtime, authorize a caller or establish systemd/LSM confinement.
"""

import ctypes
import errno
import grp
import os
import platform
import pwd
import resource
import selectors
import socket
import stat
import struct
import sys
import time


BACKEND_USER = "azurelinux3s4-web-backend"
PROXY_USER = "azurelinux3s4-web-proxy"
SHARED_GROUP = "azurelinux3s4-web"
ROOT_UID = 0
ROOT_GID = 0
JOURNAL = "/run/systemd/journal/stdout"
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


def peer_credentials(stream):
    # SO_PEERCRED is a connect/listen-time observation, not executable identity
    # or evidence that the currently executing process still has these IDs.
    data = stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    if len(data) != 12:
        raise ValueError("Unix peer credentials are incomplete")
    pid, uid, gid = struct.unpack("=iII", data)
    if pid <= 0 or uid == 0xffffffff or gid == 0xffffffff:
        raise ValueError("Unix peer credentials are unavailable")
    return pid, uid, gid


def process_identity():
    proxy = pwd.getpwnam(PROXY_USER)
    backend = pwd.getpwnam(BACKEND_USER)
    group = grp.getgrnam(SHARED_GROUP)
    if (proxy.pw_name != PROXY_USER or backend.pw_name != BACKEND_USER
            or group.gr_name != SHARED_GROUP
            or not 0 < proxy.pw_uid < 0xffffffff
            or not 0 < backend.pw_uid < 0xffffffff
            or proxy.pw_uid == backend.pw_uid
            or not 0 < group.gr_gid < 0xffffffff
            or pwd.getpwuid(proxy.pw_uid).pw_name != PROXY_USER
            or pwd.getpwuid(backend.pw_uid).pw_name != BACKEND_USER
            or grp.getgrgid(group.gr_gid).gr_name != SHARED_GROUP):
        raise ValueError("dedicated web account observations are inconsistent")
    if (os.getresuid() != (proxy.pw_uid,) * 3
            or os.getresgid() != (group.gr_gid,) * 3
            or not set(os.getgroups()) <= {group.gr_gid}):
        raise ValueError("web worker credentials differ from the dedicated identity")
    # Root, borrowed supplementary groups and retained capabilities are refused.
    # NSS/base/procfs are trusted inputs; this is not account creation/admission.
    with open("/proc/self/status", "rb") as stream:
        data = stream.read(16385)
    if len(data) > 16384:
        raise ValueError("process status exceeds the observation bound")
    records = {}
    for line in data.splitlines():
        key, separator, value = line.partition(b":")
        if separator and key in (b"Uid", b"Gid", b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb", b"NoNewPrivs"):
            if key in records:
                raise ValueError("duplicate process status observation")
            records[key] = value.split()
    if (records.get(b"Uid") != [str(proxy.pw_uid).encode()] * 4
            or records.get(b"Gid") != [str(group.gr_gid).encode()] * 4
            or records.get(b"NoNewPrivs") != [b"1"]):
        raise ValueError("process filesystem IDs or NNP observation refused")
    for key in (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"):
        values = records.get(key, [])
        if len(values) != 1 or len(values[0]) != 16 or values[0] != b"0" * 16:
            raise ValueError("process capability observation refused")
    return proxy.pw_uid, backend.pw_uid, group.gr_gid


def admit_logging():
    observations = []
    for descriptor in (1, 2):
        if not stat.S_ISSOCK(os.fstat(descriptor).st_mode):
            raise ValueError("only connected Unix journal logging descriptors are accepted")
        stream = socket.socket(fileno=descriptor)
        try:
            if (stream.family != socket.AF_UNIX or stream.type != socket.SOCK_STREAM
                    or stream.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
                    or stream.getpeername() != JOURNAL):
                raise ValueError("unexpected journal descriptor")
            peer = peer_credentials(stream)
            if peer[1:] != (ROOT_UID, ROOT_GID):
                raise ValueError("journal peer is not the expected root identity")
            observations.append(peer)
        finally:
            stream.detach()
    if observations[0] != observations[1]:
        raise ValueError("journal descriptors have different peers")


def inode_identity(value):
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def mount_identity(descriptor):
    with open(f"/proc/self/fdinfo/{descriptor}", "rb") as stream:
        data = stream.read(8193)
    if len(data) > 8192:
        raise ValueError("descriptor mount observation exceeds the bound")
    values = [line.split(b":", 1)[1].strip() for line in data.splitlines()
              if line.startswith(b"mnt_id:")]
    if len(values) != 1 or not values[0].isdigit():
        raise ValueError("descriptor mount identity is unavailable")
    return int(values[0])


def backend_root():
    return os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def backend_path(backend_uid, group_gid):
    # Fixed, alias-free path. O_PATH never opens a FIFO/device/socket for IO;
    # NOFOLLOW leaves symlinks as links so they cannot redirect this walk.
    descriptors = []
    try:
        root = backend_root()
        descriptors.append(root)
        trace = []
        for index, name in enumerate((None, "run", "azurelinux3s4-web", "http.sock")):
            if name is not None:
                descriptors.append(os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                                           dir_fd=descriptors[-1]))
            descriptor = descriptors[-1]
            value = os.fstat(descriptor)
            if index < 2:
                if not stat.S_ISDIR(value.st_mode) or value.st_uid != ROOT_UID or value.st_mode & 0o022:
                    raise ValueError("unprotected backend root or run ancestry")
            elif index == 2:
                if (not stat.S_ISDIR(value.st_mode) or value.st_uid != backend_uid
                        or value.st_gid != group_gid or stat.S_IMODE(value.st_mode) != 0o750):
                    raise ValueError("backend runtime directory identity or permissions refused")
            elif (not stat.S_ISSOCK(value.st_mode) or value.st_uid != backend_uid
                  or value.st_gid != group_gid or stat.S_IMODE(value.st_mode) != 0o666):
                raise ValueError("backend socket identity, kind or permissions refused")
            trace.append((inode_identity(value), mount_identity(descriptor)))
        # RuntimeDirectory may be a checked read-only bind in the worker. The
        # socket must be on that same mount; parent transitions are rechecked.
        if trace[-1][1] != trace[-2][1]:
            raise ValueError("backend socket has a separate mount")
        return descriptors, trace
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def connect_backend(backend_uid, group_gid):
    descriptors, before = backend_path(backend_uid, group_gid)
    connection = None
    try:
        connection = socket.socket(socket.AF_UNIX)
        connection.settimeout(5)
        # Resolve the held socket inode through the trusted kernel fd link,
        # rather than reopening its original pathname for connection setup.
        connection.connect(f"/proc/self/fd/{descriptors[-1]}")
        peer = peer_credentials(connection)
        if peer[1:] != (backend_uid, group_gid):
            raise ValueError("backend listener credentials do not match the socket owner")
        after_descriptors, after = backend_path(backend_uid, group_gid)
        try:
            if before != after or any(inode_identity(os.fstat(fd)) != item[0]
                                      or mount_identity(fd) != item[1]
                                      for fd, item in zip(descriptors, before)):
                raise ValueError("backend ancestry/socket changed during admission")
        finally:
            for descriptor in reversed(after_descriptors):
                os.close(descriptor)
        if peer_credentials(connection) != peer:
            raise ValueError("backend peer credentials changed during admission")
        connection.setblocking(False)
        return connection
    except BaseException:
        if connection is not None:
            connection.close()
        raise
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


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


def close_runtime_extras(backend):
    # NSS/native libraries may retain descriptors during startup. Keep only
    # stdio and the checked backend, even after the final account lookup.
    descriptor = backend.fileno()
    if descriptor < 3:
        raise ValueError("backend descriptor overlaps standard IO")
    before = inode_identity(os.fstat(descriptor))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.close_range.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
    for first, last in ((3, descriptor - 1), (descriptor + 1, 0xffffffff)):
        if first <= last and libc.close_range(first, last, 0):
            raise OSError(ctypes.get_errno(), "cannot close startup lookup/extra descriptors")
    if inode_identity(os.fstat(descriptor)) != before:
        raise ValueError("backend descriptor changed during extra descriptor closure")


def main():
    try:
        if len(sys.argv) != 1:
            raise ValueError("no relay overrides are accepted")
        resource.setrlimit(resource.RLIMIT_CPU, (60, 70))
        resource.setrlimit(resource.RLIMIT_AS, (128 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        credentials = process_identity()
        admit_logging()
        close_inherited()
        with prepare_client(0) as client:
            restrict(False)
            with connect_backend(credentials[1], credentials[2]) as backend:
                if process_identity() != credentials:
                    raise ValueError("web account observations changed during startup")
                close_runtime_extras(backend)
                restrict(True)
                verify_seal(client)
                forward(client, backend)
    except (OSError, ValueError, RuntimeError, MemoryError, KeyError) as error:
        print("Web relay refused: " + str(error), file=sys.stderr)
        return 75
    return 0


if __name__ == "__main__":
    sys.exit(main())

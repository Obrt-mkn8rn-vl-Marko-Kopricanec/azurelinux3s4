"""Observe loaded native file identities; no signature or memory attestation."""

import hashlib
import os
import platform
import re
import signal
import stat
import struct
import time


RUNTIME_OWNER = 0
RUNTIME_MAP_BYTES = 1024 * 1024
RUNTIME_IMAGES = 128
RUNTIME_IMAGE_BYTES = 64 * 1024 * 1024
RUNTIME_TOTAL_BYTES = 256 * 1024 * 1024
RUNTIME_OBSERVE_SECONDS = 30
STARTUP_SECONDS = 60


class RuntimeStartup:
    """A sole worker's startup timer; forwarding has its separate deadline."""

    def __init__(self):
        self.armed = False
        self.handler = self.expired

    def expired(self, number, frame):
        raise TimeoutError("relay startup deadline reached")

    def __enter__(self):
        if (signal.getsignal(signal.SIGALRM) != signal.SIG_DFL
                or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0)
                or signal.SIGALRM in signal.pthread_sigmask(signal.SIG_BLOCK, ())):
            raise ValueError("relay startup signal context refused")
        signal.signal(signal.SIGALRM, self.handler)
        try:
            signal.setitimer(signal.ITIMER_REAL, STARTUP_SECONDS)
        except BaseException:
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
            raise
        self.armed = True
        remaining, interval = signal.getitimer(signal.ITIMER_REAL)
        if signal.getsignal(signal.SIGALRM) is not self.handler or not 0 < remaining <= STARTUP_SECONDS or interval:
            self.disarm()
            raise RuntimeError("relay startup handler was not installed")
        return self

    def disarm(self):
        if not self.armed:
            return
        signal.setitimer(signal.ITIMER_REAL, 0)
        previous = signal.signal(signal.SIGALRM, signal.SIG_DFL)
        self.armed = False
        if (previous is not self.handler or signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0)
                or signal.getsignal(signal.SIGALRM) != signal.SIG_DFL):
            raise RuntimeError("relay startup timer retirement was not observed")

    def __exit__(self, *exception):
        self.disarm()


def runtime_path(path):
    if (not isinstance(path, str) or not path.startswith("/") or len(path.encode()) > 4096
            or not path.isascii() or any(ord(character) < 33 or ord(character) > 126 for character in path)
            or "\\" in path or path.endswith(" (deleted)")):
        raise ValueError("unsupported runtime image path")
    parts = path[1:].split("/")
    if len(parts) > 64 or any(part in ("", ".", "..") for part in parts):
        raise ValueError("noncanonical runtime image path")
    return parts


def runtime_maps(data=None):
    if data is None:
        descriptor = os.open("/proc/self/maps", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ValueError("runtime maps is not a regular proc observation")
            blocks, total = [], 0
            while block := os.read(descriptor, min(65536, RUNTIME_MAP_BYTES + 1 - total)):
                blocks.append(block)
                total += len(block)
                if total > RUNTIME_MAP_BYTES:
                    raise ValueError("runtime maps observation exceeds its bound")
            data = b"".join(blocks)
        finally:
            os.close(descriptor)
    if not isinstance(data, bytes) or not data or len(data) > RUNTIME_MAP_BYTES or not data.endswith(b"\n"):
        raise ValueError("runtime maps observation exceeds its bound or is truncated")
    records, images, paths, mapped_paths = [], {}, {}, {}
    lines = data.splitlines()
    if len(lines) > 4096:
        raise ValueError("runtime mapping inventory exceeds its bound")
    for line in lines:
        fields = line.split(None, 5)
        if len(fields) < 5:
            raise ValueError("malformed runtime mapping")
        address, permissions, offset, device, inode = fields[:5]
        raw_path = fields[5] if len(fields) == 6 else b""
        if (not re.fullmatch(rb"[0-9a-f]+-[0-9a-f]+", address)
                or not re.fullmatch(rb"[r-][w-][x-][ps]", permissions)
                or not re.fullmatch(rb"[0-9a-f]+", offset)
                or not re.fullmatch(rb"[0-9a-f]+:[0-9a-f]+", device)
                or not re.fullmatch(rb"[0-9]+", inode)):
            raise ValueError("malformed runtime mapping fields")
        start, end = (int(value, 16) for value in address.split(b"-"))
        major, minor = (int(value, 16) for value in device.split(b":"))
        identity = major, minor, int(inode)
        if not 0 <= start < end < 1 << 64 or any(value >= 1 << 64 for value in (*identity, int(offset, 16))):
            raise ValueError("runtime mapping integer bounds refused")
        if permissions[1:3] == b"wx":
            raise ValueError("writable executable runtime mapping refused")
        # Only executable image ranges are observed here. Read-only/writable
        # data mappings may split/merge during ordinary allocator activity.
        if permissions[2:3] != b"x":
            continue
        path = raw_path.decode("ascii")
        if "x" in permissions.decode() and identity[2] == 0:
            allowed = {"[vdso]", "[vsyscall]"} if platform.machine() == "x86_64" else {"[vdso]"}
            if path not in allowed:
                raise ValueError("anonymous executable runtime mapping refused")
            records.append((start, end, permissions.decode(), int(offset, 16), identity, path))
        if identity[2]:
            runtime_path(path)
            if path in paths and paths[path] != identity:
                raise ValueError("runtime path has ambiguous mapped identity")
            if identity in mapped_paths and mapped_paths[identity] != path:
                raise ValueError("runtime inode has ambiguous mapped paths")
            paths[path] = identity
            mapped_paths[identity] = path
            records.append((start, end, permissions.decode(), int(offset, 16), identity, path))
            images[identity] = path
            if len(paths) > RUNTIME_IMAGES:
                raise ValueError("runtime image inventory exceeds its bound")
        if len(records) > 4096:
            raise ValueError("runtime mapping inventory exceeds its bound")
    if not images:
        raise ValueError("runtime has no mapped executable image")
    return tuple(records), images


def runtime_root():
    return os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def runtime_mount(descriptor):
    with open(f"/proc/self/fdinfo/{descriptor}", "rb") as stream:
        data = stream.read(8193)
    values = [line.split(b":", 1)[1].strip() for line in data.splitlines() if line.startswith(b"mnt_id:")]
    if len(data) > 8192 or len(values) != 1 or not values[0].isdigit():
        raise ValueError("runtime descriptor mount identity unavailable")
    return int(values[0])


def runtime_identity(value):
    return value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid


def runtime_walk(path):
    descriptors, trace = [], []
    try:
        descriptors.append(runtime_root())
        parts = runtime_path(path)
        for index, name in enumerate((None, *parts)):
            if name is not None:
                descriptors.append(os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                                           dir_fd=descriptors[-1]))
            value = os.fstat(descriptors[-1])
            if value.st_uid != RUNTIME_OWNER or value.st_mode & 0o022:
                raise ValueError("unprotected runtime image ancestry or ownership")
            if index < len(parts):
                if not stat.S_ISDIR(value.st_mode):
                    raise ValueError("runtime image ancestry is not an alias-free directory")
            elif not stat.S_ISREG(value.st_mode):
                raise ValueError("runtime image leaf is not a regular file")
            trace.append((runtime_identity(value), runtime_mount(descriptors[-1])))
        return descriptors, trace
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def runtime_image(path, expected, deadline):
    descriptors, before = runtime_walk(path)
    opened = None
    try:
        leaf = os.fstat(descriptors[-1])
        if ((os.major(leaf.st_dev), os.minor(leaf.st_dev), leaf.st_ino) != expected
                or not 64 <= leaf.st_size <= RUNTIME_IMAGE_BYTES):
            raise ValueError("runtime image differs from mapped inode or size bound")
        opened = os.open(f"/proc/self/fd/{descriptors[-1]}", os.O_RDONLY | os.O_CLOEXEC)
        value = os.fstat(opened)
        if runtime_identity(value) != runtime_identity(leaf):
            raise ValueError("runtime hash descriptor differs from held inode")
        header = os.read(opened, 64)
        machine = {"x86_64": 62, "aarch64": 183}.get(platform.machine())
        if (len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01"
                or struct.unpack_from("<HHI", header, 16) not in ((2, machine, 1), (3, machine, 1))
                or struct.unpack_from("<H", header, 52)[0] != 64):
            raise ValueError("runtime image lacks the supported native ELF header")
        digest, total = hashlib.sha256(header), len(header)
        while block := os.read(opened, 1024 * 1024):
            total += len(block)
            if total > RUNTIME_IMAGE_BYTES or time.monotonic() >= deadline:
                raise ValueError("runtime image read exceeds its byte/time bound")
            digest.update(block)
        after = os.fstat(opened)
        content_identity = lambda item: (runtime_identity(item), item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if content_identity(value) != content_identity(after) or total != value.st_size:
            raise ValueError("runtime image changed while hashing")
        checked_descriptors, checked_trace = runtime_walk(path)
        try:
            if (checked_trace != before
                    or content_identity(os.fstat(checked_descriptors[-1])) != content_identity(after)
                    or any(runtime_identity(os.fstat(fd)) != entry[0] or runtime_mount(fd) != entry[1]
                           for fd, entry in zip(descriptors, before))):
                raise ValueError("runtime image path or mount changed during observation")
        finally:
            for descriptor in reversed(checked_descriptors):
                os.close(descriptor)
        return {"path": path, "mapped_identity": expected, "bytes": total,
                "sha256": digest.hexdigest(), "file_identity": content_identity(after), "ancestry": before}
    finally:
        if opened is not None:
            os.close(opened)
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def observe_runtime():
    if platform.machine() not in ("x86_64", "aarch64"):
        raise ValueError("unsupported runtime ELF architecture")
    # Warm the digest provider before taking the loaded-image snapshot.
    hashlib.sha256(b"").digest()
    deadline = time.monotonic() + RUNTIME_OBSERVE_SECONDS
    before, images = runtime_maps()
    executable = os.open("/proc/self/exe", os.O_PATH | os.O_CLOEXEC)  # Trusted kernel magic link.
    try:
        value = os.fstat(executable)
        identity = os.major(value.st_dev), os.minor(value.st_dev), value.st_ino
        path = os.readlink("/proc/self/exe")
        runtime_path(path)
        if identity not in images or images[identity] != path:
            raise ValueError("interpreter executable is not bound to mapped runtime")
        observations, total = [], 0
        for key, name in sorted(images.items()):
            if time.monotonic() >= deadline:
                raise ValueError("runtime observation deadline reached")
            observed = runtime_image(name, key, deadline)
            total += observed["bytes"]
            if total > RUNTIME_TOTAL_BYTES:
                raise ValueError("runtime image batch exceeds its byte bound")
            observations.append(observed)
        after, final_images = runtime_maps()
        if (before != after or images != final_images or os.readlink("/proc/self/exe") != path
                or runtime_identity(os.fstat(executable)) != runtime_identity(value)
                or time.monotonic() >= deadline):
            raise ValueError("loaded runtime changed during file observation")
        return {"images": observations, "interpreter_path": path, "interpreter_identity": identity,
                "total_bytes": total, "native_runtime_authenticated": False,
                "memory_contents_attested": False, "dependency_closure_complete": False,
                "installation_authorized": False, "server_ready": False}
    finally:
        os.close(executable)

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import stat
import sys

def private(path, limit):
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
            or not 0 < before.st_size <= limit):
        raise ValueError("capacity input is not a bounded private regular file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("capacity input changed before opening")
        data = source.read(limit + 1)
        after = os.fstat(source.fileno())
    if ((after.st_size, after.st_mtime_ns, after.st_ctime_ns) !=
            (before.st_size, before.st_mtime_ns, before.st_ctime_ns) or len(data) != before.st_size):
        raise ValueError("capacity input changed during reading")
    return data

def pathname(value):
    if (not isinstance(value, str) or not value.startswith("/") or "//" in value
            or len(value.encode("utf-8")) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or (value != "/" and value.endswith("/"))
            or any(part in (".", "..") for part in value.split("/"))):
        raise ValueError("signed destination path is not canonical")
    return value

def trusted(observed):
    if observed.st_uid not in (0, os.geteuid()) or observed.st_mode & 0o022:
        raise ValueError("capacity destination has untrusted writable ancestry")

def identity(observed):
    return (observed.st_dev, observed.st_ino, observed.st_mode, observed.st_uid, observed.st_gid)

def mount_id(fd):
    entries = re.findall(r"^mnt_id:\s*([0-9]+)$", Path(f"/proc/self/fdinfo/{fd}").read_text(), re.M)
    if len(entries) != 1:
        raise ValueError("descriptor mount identity could not be observed")
    return int(entries[0])

def dir_open(name, fd=None):
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                   dir_fd=fd)

held = []
try:
    resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_CPU, (240, 245))
    _, descriptor_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    descriptor_limit = min(256, descriptor_hard) if descriptor_hard > 0 else 256
    resource.setrlimit(resource.RLIMIT_NOFILE, (descriptor_limit, descriptor_hard))
    workspace, database = Path(sys.argv[1]), pathname(sys.argv[2])
    proof = json.loads(private(workspace / "result.json", 1024 * 1024))
    data = private(workspace / "inventory.json", 32 * 1024 * 1024)
    inventory = json.loads(data)
    receipt = proof["payload_inventory"]
    if (proof.get("test_passed") is not True or proof.get("installation_authorized") is not False
            or receipt.get("sha256") != hashlib.sha256(data).hexdigest() or receipt.get("bytes") != len(data)
            or set(inventory) != {"schema", "manifest_sha256", "artifacts"} or inventory["schema"] != 1
            or inventory["manifest_sha256"] != proof["manifest_sha256"]
            or not isinstance(inventory["artifacts"], list) or len(inventory["artifacts"]) > 128):
        raise ValueError("capacity inventory is not bound to the successful same-byte TEST")
    expected = {item["file"]: (item["sha256"], item["bytes"]) for item in proof["additions"]}
    if len(expected) != len(proof["additions"]) or len(expected) != len(inventory["artifacts"]):
        raise ValueError("capacity inventory batch count differs")
    files, header_bytes, payload_bytes, seen_packages, types = [], 0, 0, set(), {}
    for package in inventory["artifacts"]:
        if (set(package) != {"file", "sha256", "bytes", "header_bytes", "files"}
                or package["file"] in seen_packages
                or expected.get(package["file"]) != (package["sha256"], package["bytes"])
                or type(package["header_bytes"]) is not int or not 0 < package["header_bytes"] <= 8 * 1024 * 1024
                or not isinstance(package["files"], list)):
            raise ValueError("capacity inventory does not preserve the admitted package identity")
        seen_packages.add(package["file"])
        header_bytes += package["header_bytes"]
        seen_paths = set()
        for entry in package["files"]:
            if (set(entry) != {"path", "bytes", "mode", "flags", "link"}
                    or type(entry["bytes"]) is not int or not 0 <= entry["bytes"] <= 16 * 1024 ** 3
                    or type(entry["mode"]) is not int or not 0 <= entry["mode"] <= 65535
                    or type(entry["flags"]) is not int or not 0 <= entry["flags"] < 2 ** 32
                    or not isinstance(entry["link"], str) or len(entry["link"].encode("utf-8")) > 4096
                    or any(ord(c) < 32 or ord(c) == 127 for c in entry["link"])):
                raise ValueError("signed capacity file record is malformed")
            path = pathname(entry["path"])
            if path in seen_paths:
                raise ValueError("signed capacity inventory duplicates a package path")
            seen_paths.add(path)
            files.append(entry)
            payload_bytes += entry["bytes"]
            if not entry["flags"] & 64:  # Ghost entries have no packaged payload.
                kind = stat.S_IFMT(entry["mode"])
                if kind not in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK) or (path == "/" and kind != stat.S_IFDIR):
                    raise ValueError("capacity refuses special destination objects")
                layout = (kind, entry["link"] if kind == stat.S_IFLNK else "")
                if path in types and types[path] != layout:
                    raise ValueError("batch changes a shared destination kind or link")
                types[path] = layout
    if (len(files) != receipt.get("files") or len(files) > 131072
            or header_bytes > 64 * 1024 * 1024 or payload_bytes > 64 * 1024 ** 3):
        raise ValueError("capacity inventory exceeds its bounds")

    mount_data = Path("/proc/self/mountinfo").read_bytes()
    if not 0 < len(mount_data) <= 4 * 1024 * 1024:
        raise ValueError("mount inventory exceeds its bounds")
    mounts = {}
    for line in mount_data.decode("utf-8").splitlines():
        left, right = line.split(" - ", 1)
        fields, details = left.split(), right.split()
        number = int(fields[0])
        if number in mounts or len(fields) < 6 or len(details) != 3:
            raise ValueError("mount inventory is malformed")
        mounts[number] = {"device": tuple(map(int, fields[2].split(":"))), "fs": details[0],
                          "source": details[1], "options": set(fields[5].split(",") + details[2].split(","))}
    if not 0 < len(mounts) <= 4096:
        raise ValueError("mount count is unsupported")

    def forbidden(path):
        return any(path == prefix or path.startswith(prefix + "/") for prefix in
                   ("/dev", "/proc", "/sys", "/run", "/tmp", "/var/tmp", "/var/run", "/var/lock"))

    def resolve(path):
        # Traverse only directories. Never open a FIFO/device/socket as input.
        pending = list(PurePosixPath(path).parts[1:])
        if len(pending) > 64:
            raise ValueError("destination ancestry exceeds its depth bound")
        fd, parts, trace, missing, links = dir_open("/"), [], [], [], 0
        try:
            observed = os.fstat(fd)
            trusted(observed)
            trace.append(("/", identity(observed), mount_id(fd)))
            while pending:
                name = pending.pop(0)
                if name in ("", "."):
                    continue
                if name == "..":
                    raise ValueError("destination symlink contains unsupported parent traversal")
                current = "/" + "/".join(parts + [name])
                if forbidden(current):
                    raise ValueError("capacity destination is a runtime or special filesystem path")
                planned = types.get(current)
                if missing:
                    entry = None
                else:
                    try:
                        entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError:
                        entry = None
                if entry is None:
                    if planned and planned[0] != stat.S_IFDIR:
                        raise ValueError("batch creates a non-directory destination ancestor")
                    parts.append(name)
                    missing.append(current)
                    continue
                if stat.S_ISLNK(entry.st_mode):
                    if entry.st_uid not in (0, os.geteuid()):
                        raise ValueError("destination symlink owner is untrusted")
                    target = os.readlink(name, dir_fd=fd)
                    if planned and planned != (stat.S_IFLNK, target):
                        raise ValueError("batch changes a destination symlink ancestor")
                    links += 1
                    if links > 40 or not target or len(target.encode("utf-8")) > 4096:
                        raise ValueError("destination symlink traversal exceeds its bound")
                    trace.append((current, identity(entry), target))
                    if target.startswith("/"):
                        os.close(fd)
                        fd, parts = dir_open("/"), []
                    pending = list(PurePosixPath(target).parts[1:] if target.startswith("/")
                                   else PurePosixPath(target).parts) + pending
                    if len(parts) + len(pending) > 64:
                        raise ValueError("resolved destination ancestry exceeds its bound")
                    continue
                if not stat.S_ISDIR(entry.st_mode) or (planned and planned[0] != stat.S_IFDIR):
                    raise ValueError("destination ancestor is not a retained directory")
                trusted(entry)
                next_fd = dir_open(name, fd)
                if identity(os.fstat(next_fd)) != identity(entry):
                    os.close(next_fd)
                    raise ValueError("destination changed during descriptor traversal")
                trace.append((current, identity(entry), mount_id(next_fd)))
                os.close(fd)
                fd = next_fd
                parts.append(name)
            return fd, (tuple(trace), tuple(missing), "/" + "/".join(parts))
        except BaseException:
            os.close(fd)
            raise

    volumes, observations, missing_dirs = {}, {}, set()
    def availability(fd):
        value = os.fstatvfs(fd)
        if (value.f_flag & os.ST_RDONLY or any(type(getattr(value, key)) is not int for key in
                ("f_frsize", "f_bsize", "f_blocks", "f_bfree", "f_bavail", "f_files", "f_ffree", "f_favail"))
                or not 512 <= value.f_frsize <= 1024 * 1024 or value.f_frsize & (value.f_frsize - 1)
                or not 512 <= value.f_bsize <= 1024 * 1024 or value.f_bsize & (value.f_bsize - 1)
                or not 0 <= value.f_bavail <= value.f_bfree <= value.f_blocks or value.f_blocks <= 0
                or not 0 <= value.f_favail <= value.f_ffree <= value.f_files or value.f_files <= 0):
            raise ValueError("filesystem does not advertise bounded writable block/inode availability")
        return {"allocation": max(value.f_frsize, value.f_bsize), "unit": value.f_frsize,
                "blocks": value.f_blocks, "inodes": value.f_files,
                "available_bytes": value.f_bavail * value.f_frsize, "available_inodes": value.f_favail}

    def volume(fd):
        observed, number = os.fstat(fd), mount_id(fd)
        mount = mounts.get(number)
        if (not mount or mount["device"] != (os.major(observed.st_dev), os.minor(observed.st_dev))
                or mount["fs"] not in ("ext4", "xfs") or not mount["source"].startswith("/dev/")
                or "rw" not in mount["options"] or "ro" in mount["options"]
                or any("quota" in option and option != "noquota" or option.split("=", 1)[0] in
                       {"uquota", "gquota", "pquota", "uqnoenforce", "gqnoenforce", "pqnoenforce", "qnoenforce", "jqfmt"}
                       for option in mount["options"])):
            raise ValueError("capacity supports only local ext4/xfs without advertised quota options")
        current = availability(fd)
        device = observed.st_dev
        if device not in volumes:
            if len(volumes) >= 64:
                raise ValueError("capacity filesystem count exceeds its bound")
            volumes[device] = {"device": device, "filesystem": mount["fs"], "mount_ids": set(),
                               "required_bytes": 0, "required_inodes": 0, "initial": current, "fds": []}
        result = volumes[device]
        initial = result["initial"]
        if (result["filesystem"] != mount["fs"] or any(initial[k] != current[k] for k in
                ("allocation", "unit", "blocks", "inodes"))):
            raise ValueError("filesystem aliases advertise inconsistent capacity geometry")
        initial["available_bytes"] = min(initial["available_bytes"], current["available_bytes"])
        initial["available_inodes"] = min(initial["available_inodes"], current["available_inodes"])
        if number not in result["mount_ids"]:
            result["mount_ids"].add(number)
            duplicate = os.dup(fd)
            held.append(duplicate)
            result["fds"].append(duplicate)
        return result

    def charge(path, size, is_directory=False):
        if forbidden(path):
            raise ValueError("capacity destination is a runtime or special filesystem path")
        parent = path if is_directory else str(PurePosixPath(path).parent)
        fd, signature = resolve(parent)
        try:
            if parent in observations and observations[parent] != signature:
                raise ValueError("destination layout changed between inventory entries")
            observations[parent] = signature
            if len(observations) > 32768:
                raise ValueError("destination parent count exceeds its bound")
            result = volume(fd)
            if not is_directory and not signature[1]:
                try:
                    entry = os.stat(PurePosixPath(path).name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError:
                    entry = None
                if entry is not None:
                    # Ordinary symlink mode0777 is not an access permission.
                    # Check its owner; protected parent traversal and the kind,
                    # no-follow descriptor identity/mount checks still apply.
                    if stat.S_ISLNK(entry.st_mode):
                        if entry.st_uid not in (0, os.geteuid()):
                            raise ValueError("capacity destination symlink has an untrusted owner")
                    else:
                        trusted(entry)
                    if stat.S_IFMT(entry.st_mode) != types[path][0]:
                        raise ValueError("existing destination kind differs from the signed payload")
                    descriptor = os.open(PurePosixPath(path).name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                    try:
                        if identity(os.fstat(descriptor)) != identity(entry) or mount_id(descriptor) != mount_id(fd):
                            raise ValueError("destination is changed or a file mount")
                    finally:
                        os.close(descriptor)
            allocation = result["initial"]["allocation"]
            # No erasure/replacement, hardlink, sparse or doc-skip credit.
            # Two full incoming copies plus two metadata blocks per entry.
            result["required_bytes"] += 2 * ((size + allocation - 1) // allocation + 2) * allocation
            result["required_inodes"] += 2
            for missing in signature[1]:
                key = (result["device"], missing)
                if key not in missing_dirs:
                    missing_dirs.add(key)
                    result["required_bytes"] += 4 * allocation
                    result["required_inodes"] += 2
            if len(missing_dirs) > 65536:
                raise ValueError("new destination directory count exceeds its bound")
        finally:
            os.close(fd)

    skipped_ghosts = 0
    for entry in files:
        if entry["flags"] & 64:
            skipped_ghosts += 1
            continue
        charge(entry["path"], max(entry["bytes"], len(entry["link"].encode("utf-8"))),
               stat.S_ISDIR(entry["mode"]))

    boot_budget = boot_work_budget(files)
    initramfs_before = None
    existing_initramfs = initramfs_budget()
    if boot_budget["images"]:
        boot_fd, boot_signature = resolve("/boot")
        try:
            if boot_signature[1]:
                raise ValueError("boot-work destination directory is missing")
            if "/boot" in observations and observations["/boot"] != boot_signature:
                raise ValueError("boot-work destination layout changed")
            observations["/boot"] = boot_signature
            if len(observations) > 32768:
                raise ValueError("boot-work destination parent count exceeds its bound")
            boot_volume = volume(boot_fd)
            initramfs_before = initramfs_scan(boot_fd)
            existing_initramfs = initramfs_budget(initramfs_before)
            allocation = boot_volume["initial"]["allocation"]
            rounded = ((boot_budget["minimum_work_bytes"] + allocation - 1) // allocation) * allocation
            charged = rounded + 2 * allocation * boot_budget["minimum_work_inodes"]
            boot_volume["required_bytes"] += charged
            boot_volume["required_inodes"] += boot_budget["minimum_work_inodes"]
            boot_budget.update(filesystem_device=boot_volume["device"],
                               charged_bytes=charged, boot_directory_observed=True)
            extra = ((existing_initramfs["minimum_work_bytes"] + allocation - 1) // allocation) * allocation
            extra += 2 * allocation * existing_initramfs["minimum_work_inodes"]
            boot_volume["required_bytes"] += extra
            boot_volume["required_inodes"] += existing_initramfs["minimum_work_inodes"]
            existing_initramfs.update(filesystem_device=boot_volume["device"], charged_bytes=extra)
        finally:
            os.close(boot_fd)
    else:
        boot_budget.update(filesystem_device=None, charged_bytes=0, boot_directory_observed=False)
        existing_initramfs.update(filesystem_device=None, charged_bytes=0)

    def database_scan():
        fd, signature = resolve(database)
        rows, total = [], 0
        result = volume(fd)
        def walk(directory, prefix, depth):
            nonlocal total
            if depth > 8:
                raise ValueError("database directory depth exceeds its bound")
            for name in sorted(os.listdir(directory)):
                observed = os.stat(name, dir_fd=directory, follow_symlinks=False)
                trusted(observed)
                if observed.st_dev != result["device"]:
                    raise ValueError("database spans unsupported filesystem boundaries")
                path = prefix + "/" + name
                rows.append((path, identity(observed), observed.st_size, observed.st_mtime_ns, observed.st_ctime_ns))
                if len(rows) > 8192:
                    raise ValueError("database file count exceeds its bound")
                if stat.S_ISDIR(observed.st_mode):
                    child = dir_open(name, directory)
                    try:
                        if identity(os.fstat(child)) != identity(observed) or mount_id(child) != mount_id(directory):
                            raise ValueError("database directory changed or crosses a mount")
                        walk(child, path, depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(observed.st_mode) and observed.st_nlink == 1:
                    total += max(observed.st_size, observed.st_blocks * 512)
                    if total > 2 * 1024 ** 3:
                        raise ValueError("database allocation exceeds its inspection bound")
                else:
                    raise ValueError("database has an unsupported non-regular or linked object")
        try:
            if signature[1]:
                raise ValueError("installed database directory is missing")
            walk(fd, "", 0)
            if not rows:
                raise ValueError("installed database directory is empty")
            return result, (signature, rows, total)
        finally:
            os.close(fd)
    db_volume, db_before = database_scan()
    db_volume["required_bytes"] += 2 * db_before[2] + 4 * header_bytes + 64 * 1024 * 1024
    db_volume["required_inodes"] += 2 * len(db_before[1]) + 4 * len(expected) + 64

    for parent, before in observations.items():
        fd, after = resolve(parent)
        try:
            if after != before:
                raise ValueError("destination ancestry changed during capacity observation")
            volume(fd)
        finally:
            os.close(fd)
    _, db_after = database_scan()
    if initramfs_before is not None:
        fd, signature = resolve("/boot")
        try:
            if signature != observations["/boot"] or initramfs_scan(fd) != initramfs_before:
                raise ValueError("existing initramfs namespace changed during capacity observation")
            volume(fd)
        finally:
            os.close(fd)
    if db_after != db_before or Path("/proc/self/mountinfo").read_bytes() != mount_data:
        raise ValueError("database or mount layout changed during capacity observation")
    results = []
    for result in volumes.values():
        initial = result["initial"]
        available_bytes, available_inodes = initial["available_bytes"], initial["available_inodes"]
        for fd in result["fds"]:
            current = availability(fd)
            if any(current[key] != initial[key] for key in ("allocation", "unit", "blocks", "inodes")):
                raise ValueError("filesystem geometry changed during capacity observation")
            available_bytes = min(available_bytes, current["available_bytes"])
            available_inodes = min(available_inodes, current["available_inodes"])
        reserve_bytes = max(64 * 1024 * 1024, (initial["blocks"] * initial["unit"] + 19) // 20)
        reserve_inodes = max(256, (initial["inodes"] + 19) // 20)
        if (available_bytes < result["required_bytes"] + reserve_bytes
                or available_inodes < result["required_inodes"] + reserve_inodes):
            raise ValueError("advertised free blocks/inodes do not meet payload budget plus headroom")
        results.append({key: result[key] for key in ("device", "filesystem", "required_bytes", "required_inodes")}
                       | {"mount_ids": sorted(result["mount_ids"]), "available_bytes": available_bytes,
                          "available_inodes": available_inodes, "headroom_bytes": reserve_bytes,
                          "headroom_inodes": reserve_inodes})
    proof["payload_capacity_checked"] = True
    proof["capacity_observation"] = {"filesystems": sorted(results, key=lambda item: item["device"]),
        "boot_work_budget": boot_budget,
        "existing_initramfs_work": existing_initramfs,
        "inventory_sha256": receipt["sha256"], "skipped_ghost_entries": skipped_ghosts,
        "policy": "two gross incoming copies plus per-entry metadata; no removal/hardlink credit; database reserve; five-percent or fixed headroom",
        "space_reserved": False, "scripts_capacity_checked": False, "rollback_capacity_checked": False,
        "quota_enforcement_queried": False, "atomic_filesystem_snapshot": False,
        "observer_limits": {"address_space_bytes": 768 * 1024 * 1024,
                            "cpu_soft_seconds": 240, "descriptor_soft_limit": descriptor_limit}}
    print(json.dumps(proof, sort_keys=True))
except (ValueError, KeyError, TypeError, OSError, UnicodeError, IndexError, MemoryError) as error:
    print("azurelinux3s4: update payload capacity deferred: " + str(error), file=sys.stderr)
    sys.exit(75)
finally:
    for fd in held:
        os.close(fd)

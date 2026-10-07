import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import sys


TRUSTED_UID = 0
ORDINARY = (("prein", 1023, 1085), ("postin", 1024, 1086),
            ("preun", 1025, 1087), ("postun", 1026, 1088),
            ("pretrans", 1151, 1153), ("posttrans", 1152, 1154),
            ("verify", 1079, 1091))
TRIGGERS = (("trigger", 1065, 1092), ("filetrigger", 5066, 5067),
            ("transfiletrigger", 5076, 5077))


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def trusted(value):
    if value.st_uid != TRUSTED_UID or value.st_mode & 0o022:
        raise ValueError("interpreter file or directory has untrusted ownership/permissions")


def pathname(value):
    if (not isinstance(value, str) or not value.startswith("/") or value == "/"
            or "//" in value or value.endswith("/") or len(value.encode("utf-8")) > 4096
            or any(part in (".", "..") for part in value.split("/"))
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError("interpreter requires a canonical absolute path")
    return value


def mount_id(fd):
    entries = re.findall(r"^mnt_id:\s*([0-9]+)$", Path(f"/proc/self/fdinfo/{fd}").read_text(), re.M)
    if len(entries) != 1:
        raise ValueError("interpreter descriptor mount identity is unavailable")
    return int(entries[0])


def root_open():
    return os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def resolve(path):
    # Walk protected ancestors, including ordinary owned aliases, using checked
    # no-follow descriptors. No interpreter or script is executed.
    pending, parts, trace, links, steps = pathname(path).split("/")[1:], [], [], 0, 0
    fd = root_open()
    try:
        trusted(os.fstat(fd))
        trace.append(("/", identity(os.fstat(fd)), mount_id(fd)))
        while pending:
            steps += 1
            if steps > 1024 or len(parts) + len(pending) > 64:
                raise ValueError("interpreter traversal exceeds its finite bound")
            name = pending.pop(0)
            if name in ("", "."):
                continue
            if name == "..":
                # Re-walk the observed physical parent; never lexically collapse
                # an untraversed link/.. sequence into a different target.
                pending = parts[:-1] + pending
                parts = []
                os.close(fd)
                fd = root_open()
                trusted(os.fstat(fd))
                trace.append(("/", identity(os.fstat(fd)), mount_id(fd)))
                continue
            current = "/" + "/".join(parts + [name])
            if any(current == p or current.startswith(p + "/") for p in
                   ("/dev", "/proc", "/sys", "/run", "/tmp", "/var/tmp", "/var/run", "/var/lock")):
                raise ValueError("interpreter resolves through a special/runtime path")
            before = os.stat(name, dir_fd=fd, follow_symlinks=False)
            opened = os.open(name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            try:
                observed = os.fstat(opened)
                if identity(observed) != identity(before):
                    raise ValueError("interpreter path changed before descriptor acquisition")
                number = mount_id(opened)
                if stat.S_ISLNK(observed.st_mode):
                    # Ordinary symlink 0777 is not an access permission mask.
                    if observed.st_uid != TRUSTED_UID:
                        raise ValueError("interpreter symlink has an untrusted owner")
                    target = os.readlink("", dir_fd=opened)
                    links += 1
                    if (links > 40 or not target or len(target.encode("utf-8")) > 4096
                            or any(ord(c) < 32 or ord(c) == 127 for c in target)):
                        raise ValueError("interpreter symlink traversal is unsupported")
                    trace.append((current, identity(observed), number, target))
                    if target.startswith("/"):
                        parts = []
                        os.close(fd)
                        fd = root_open()
                        trusted(os.fstat(fd))
                        trace.append(("/", identity(os.fstat(fd)), mount_id(fd)))
                    pending = target.split("/") + pending
                    continue
                trusted(observed)
                trace.append((current, identity(observed), number))
                if pending:
                    if not stat.S_ISDIR(observed.st_mode):
                        raise ValueError("interpreter ancestor is not a directory")
                    next_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                                      os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=fd)
                    if identity(os.fstat(next_fd)) != identity(observed):
                        os.close(next_fd)
                        raise ValueError("interpreter directory changed during traversal")
                    os.close(fd)
                    fd = next_fd
                    parts.append(name)
                    continue
                if (not stat.S_ISREG(observed.st_mode) or not observed.st_mode & 0o111
                        or not 0 < observed.st_size <= 64 * 1024 * 1024):
                    raise ValueError("interpreter is not a bounded executable regular file")
                if os.fstatvfs(opened).f_flag & os.ST_NOEXEC:
                    raise ValueError("interpreter file mount is noexec")
                result = (current, identity(observed), tuple(trace))
                # Duplicate the checked regular inode, not the original path.
                # Reading through this kernel fd link cannot reopen a raced
                # FIFO/device/symlink in the operator's filesystem namespace.
                reader = os.open(f"/proc/self/fd/{opened}", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
                if identity(os.fstat(reader)) != identity(observed):
                    os.close(reader)
                    raise ValueError("interpreter read descriptor differs from its observed inode")
                return reader, result
            finally:
                os.close(opened)
        raise ValueError("interpreter path did not resolve to a regular file")
    finally:
        os.close(fd)


def declarations(owner):
    tags = owner["tags"]
    if not isinstance(tags, list) or len(tags) > 44:
        raise ValueError("interpreter metadata exceeds its catalog bound")
    by_tag = {}
    for entry in tags:
        if (type(entry["tag"]) is not int or entry["tag"] in by_tag
                or type(entry["count"]) is not int or not 0 < entry["count"] <= 4096
                or not isinstance(entry["values"], list) or len(entry["values"]) != entry["count"]):
            raise ValueError("interpreter metadata is malformed or duplicated")
        by_tag[entry["tag"]] = entry
    for family, body, program in ORDINARY:
        if body in by_tag or program in by_tag:
            values = by_tag[program]["values"] if program in by_tag else ["/bin/sh"]
            yield family, 0, values, program not in by_tag
    for family, body, program in TRIGGERS:
        if body not in by_tag and program not in by_tag:
            continue
        if (body not in by_tag or program not in by_tag
                or by_tag[body]["count"] != by_tag[program]["count"]):
            raise ValueError("trigger body/program arrays require matching declared entries")
        for index, value in enumerate(by_tag[program]["values"]):
            yield family, index, [value], False


def observe(proof):
    audit = proof["effects"]
    if (proof.get("schema") != 1 or proof.get("test_passed") is not True
            or not re.fullmatch(r"[0-9a-f]{64}", proof["manifest_sha256"])
            or any(proof.get(name) is not False for name in
                   ("installation_authorized", "scripts_executed", "installs_performed",
                    "storage_capacity_checked", "freshness_proven"))
            or audit.get("schema") != 1 or audit.get("script_metadata_observed") is not True
            or audit.get("removals_bound_to_installed_instances") is not True
            or audit["installed_headers_observed"] != proof["baseline"]["headers"]
            or any(audit.get(name) is not False for name in
                   ("installed_headers_authenticated", "trigger_selection_complete",
                    "script_execution_plan_complete", "script_policy_satisfied",
                    "removal_policy_satisfied", "rollback_policy_satisfied"))):
        raise ValueError("interpreter input lacks the qualified fresh same-byte effects TEST")
    incoming, installed = audit["incoming"], audit["installed_script_owners"]
    if (not isinstance(incoming, list) or len(incoming) > 128
            or not isinstance(installed, list) or len(installed) > 32768
            or len(incoming) != len(proof["additions"])):
        raise ValueError("interpreter owner inventory is unsupported")
    expected = {(p["file"], p["sha256"], p["bytes"], p["nevra"]) for p in proof["additions"]}
    if len(expected) != len(incoming) or expected != {
            (p["file"], p["sha256"], p["bytes"], p["nevra"]) for p in incoming}:
        raise ValueError("interpreter incoming identities differ from the admitted TEST inputs")
    refs, files, receipts, seen_instances, total = [], {}, {}, set(), 0
    for source, owners in (("incoming", incoming), ("installed", installed)):
        for owner in owners:
            if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+._-]{0,255}", owner["name"])
                    or not isinstance(owner["nevra"], str) or not 0 < len(owner["nevra"]) <= 1024
                    or not re.fullmatch(r"[0-9a-f]{64}", owner["header_sha256"])):
                raise ValueError("interpreter owner identity is malformed")
            binding = {name: owner[name] for name in ("name", "nevra", "header_sha256")}
            if source == "installed":
                instance = owner["instance"]
                if type(instance) is not int or instance <= 0 or instance in seen_instances:
                    raise ValueError("interpreter installed instance is missing or duplicated")
                seen_instances.add(instance)
                binding["instance"] = instance
            else:
                binding.update({name: owner[name] for name in ("file", "sha256", "bytes")})
            for family, index, argv, default in declarations(owner):
                if (not argv or any(not isinstance(arg, str) or not arg or len(arg.encode("utf-8")) > 4096
                                    or any(ord(c) < 32 or ord(c) == 127 for c in arg) for arg in argv)):
                    raise ValueError("declared interpreter argv is unsupported")
                command = argv[0]
                kind = "embedded-lua" if command == "<lua>" else "external-file"
                if kind == "external-file":
                    pathname(command)
                    if command not in files:
                        if len(files) >= 64:
                            raise ValueError("unique interpreter file count exceeds its bound")
                        fd, receipt = resolve(command)
                        with os.fdopen(fd, "rb") as stream:
                            before = os.fstat(stream.fileno())
                            digest, size = hashlib.sha256(), 0
                            while block := stream.read(1024 * 1024):
                                digest.update(block)
                                size += len(block)
                                if size > 64 * 1024 * 1024:
                                    raise ValueError("interpreter grew beyond its read bound")
                            if identity(os.fstat(stream.fileno())) != identity(before) or size != before.st_size:
                                raise ValueError("interpreter file changed during hashing")
                        total += size
                        if total > 256 * 1024 * 1024:
                            raise ValueError("interpreter bytes exceed the aggregate bound")
                        receipts[command] = receipt
                        files[command] = {"path": command, "resolved_path": receipt[0], "bytes": size,
                                          "sha256": digest.hexdigest(), "device": before.st_dev,
                                          "inode": before.st_ino, "mode": before.st_mode, "uid": before.st_uid,
                                          "mount_id": receipt[2][-1][2], "mount_noexec": False}
                refs.append({"source": source, "owner": binding, "family": family, "index": index,
                             "argv": argv, "default_program": default, "kind": kind})
                if len(refs) > 65536:
                    raise ValueError("declared interpreter references exceed their bound")
    for command, receipt in receipts.items():
        fd, after = resolve(command)
        os.close(fd)
        if after != receipt:
            raise ValueError("interpreter path or file changed during the observation")
    proof["interpreters"] = {
        "schema": 1, "references": refs, "files": [files[p] for p in sorted(files)],
        "external_files_observed": True, "embedded_lua_declarations": sum(r["kind"] == "embedded-lua" for r in refs),
        "scope": "all-declared-incoming-and-installed; selection is unproved",
        "runtime_files_authenticated": False, "embedded_engines_tested": False,
        "interpreter_loadability_checked": False, "interpreter_dependencies_checked": False,
        "execution_tested": False, "execution_policy_satisfied": False,
        "trigger_selection_complete": False, "installation_authorized": False,
    }
    return proof


def main():
    try:
        resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (240, 245))
        path = Path(sys.argv[1]) / "result.json"
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != 0o600 or not 0 < before.st_size <= 32 * 1024 * 1024):
            raise ValueError("interpreter proof is not a bounded private regular file")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            if identity(os.fstat(stream.fileno())) != identity(before):
                raise ValueError("interpreter proof changed before opening")
            data = stream.read(32 * 1024 * 1024 + 1)
            if identity(os.fstat(stream.fileno())) != identity(before) or len(data) != before.st_size:
                raise ValueError("interpreter proof changed during reading")
        encoded = json.dumps(observe(json.loads(data)), sort_keys=True)
        if len(encoded.encode("utf-8")) > 64 * 1024 * 1024:
            raise ValueError("interpreter observations exceed their output bound")
        print(encoded)
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, OverflowError, IndexError) as error:
        print("Update interpreter observation deferred: " + str(error), file=sys.stderr)
        return 75


if __name__ == "__main__":
    sys.exit(main())

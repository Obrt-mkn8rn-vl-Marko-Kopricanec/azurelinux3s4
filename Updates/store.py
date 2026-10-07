import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

try:
    action, root, fingerprint = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
    marker = b"azurelinux3s4-update-slot-v1\n"

    def inspect(path, directory=False, private=True):
        value = path.lstat()
        if (not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))
                or value.st_uid != os.geteuid() or value.st_mode & (0o077 if private else 0o022)
                or (not directory and value.st_nlink != 1)):
            raise ValueError("update store contains an unsafe object: " + str(path))
        return value

    def read(path, maximum=1048576):
        inspect(path)
        with path.open("rb") as stream:
            data = stream.read(maximum + 1)
        if len(data) > maximum:
            raise ValueError("update record exceeds its bound")
        return data

    def flush(path):
        inspect(path, path.is_dir())
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def barrier(*paths):
        subprocess.run(["sync", "-f", "--", *map(str, paths)], stdin=subprocess.DEVNULL,
                       check=True, timeout=30)

    def write(path, data, mode):
        if path.exists() or path.is_symlink():
            inspect(path)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, mode)
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(data)
            output.flush()
            os.fsync(output.fileno())

    def inventory(slot):
        inspect(slot, True)
        names = {entry.name for entry in slot.iterdir()}
        if not names <= {"owner", "manifest.json", "packages"}:
            raise ValueError("refusing foreign slot contents")
        if "owner" not in names:
            if names:
                raise ValueError("nonempty slot has no ownership record")
            return []
        identity = read(slot / "owner", 128)
        if identity != marker:
            # Initial creation can be interrupted before the complete marker is
            # written. Only its bounded prefix in an otherwise empty slot is
            # recognized; foreign data and every wrong-kind object remain refused.
            if names == {"owner"} and marker.startswith(identity):
                return []
            raise ValueError("slot ownership record is foreign")
        if "manifest.json" in names:
            inspect(slot / "manifest.json")
        files = []
        if "packages" in names:
            inspect(slot / "packages", True)
            files = list((slot / "packages").iterdir())
            if len(files) > 128:
                raise ValueError("slot contains too many package objects")
            for path in files:
                if not re.fullmatch(r"(?:0|[1-9][0-9]{0,2})\.rpm", path.name) or int(path.stem) > 127:
                    raise ValueError("refusing foreign package name")
                inspect(path)
        return files

    def validate(pointer, persist):
        if (not isinstance(pointer, dict) or set(pointer) != {"schema", "slot", "manifest_sha256"}
                or pointer["schema"] != 1 or pointer["slot"] not in ("0", "1")
                or not re.fullmatch(r"[0-9a-f]{64}", str(pointer["manifest_sha256"]))):
            raise ValueError("current update pointer is malformed")
        slot = root / ("slot" + pointer["slot"])
        files = inventory(slot)
        material = read(slot / "manifest.json")
        if hashlib.sha256(material).hexdigest() != pointer["manifest_sha256"]:
            raise ValueError("current update manifest does not match its pointer")
        proof = json.loads(material)
        if (set(proof) != {"schema", "vendor_fingerprint", "packages", "installs_performed", "freshness_proven"}
                or proof["schema"] != 1 or proof["vendor_fingerprint"] != fingerprint
                or proof["installs_performed"] is not False or proof["freshness_proven"] is not False
                or not isinstance(proof["packages"], list) or len(proof["packages"]) > 128):
            raise ValueError("current update manifest policy is unsupported")
        expected, total = [], 0
        for index, record in enumerate(proof["packages"]):
            path = slot / "packages" / (str(index) + ".rpm")
            if (not isinstance(record, dict) or set(record) != {"file", "bytes", "sha256"}
                    or record["file"] != "packages/" + path.name or type(record["bytes"]) is not int
                    or not 0 < record["bytes"] <= 512 * 1024 * 1024
                    or not re.fullmatch(r"[0-9a-f]{64}", str(record["sha256"]))):
                raise ValueError("current update package record is malformed")
            value = inspect(path)
            if value.st_mode & 0o777 != 0o400 or value.st_size != record["bytes"]:
                raise ValueError("retained update package mode/size changed")
            digest = hashlib.sha256()
            with path.open("rb") as source:
                while block := source.read(1024 * 1024):
                    digest.update(block)
            if digest.hexdigest() != record["sha256"]:
                raise ValueError("retained update package bytes changed")
            total += record["bytes"]
            expected.append(path)
            if persist:
                flush(path)
        if total > 1024 * 1024 * 1024 or set(files) != set(expected):
            raise ValueError("retained batch size/contents differ from its manifest")
        if persist:
            for path in (slot / "owner", slot / "manifest.json", slot / "packages", slot, root / "current.json", root):
                flush(path)
            barrier(slot, root, root.parent)
            if json.loads(read(root / "current.json")) != pointer:
                raise ValueError("current pointer changed after its persistence barrier")
        return slot

    inspect(root, True)
    current = root / "current.json"
    pointer = json.loads(read(current)) if current.exists() or current.is_symlink() else None
    if action == "begin":
        if pointer is not None:
            validate(pointer, True)
        name = "slot1" if pointer and pointer["slot"] == "0" else "slot0"
        slot = root / name
        if slot.exists() or slot.is_symlink():
            files = inventory(slot)
            # Only the recognized private slot and its bounded regular files
            # are reusable; ordinary foreign/wrong-kind objects are preserved.
            for path in files:
                path.unlink()
            if (slot / "manifest.json").exists():
                (slot / "manifest.json").unlink()
            # Keep the ownership record and empty package directory throughout
            # recycling. An interruption must not create an unrecognized slot.
        else:
            slot.mkdir(mode=0o700)
        if not (slot / "owner").exists() or read(slot / "owner", 128) != marker:
            write(slot / "owner", marker, 0o600)
        (slot / "packages").mkdir(mode=0o700, exist_ok=True)
        flush(slot)
        barrier(slot, root, root.parent)
        print(slot)
    elif action == "list":
        incoming = Path(sys.argv[4])
        inspect(incoming, True)
        files = sorted(incoming.iterdir())
        sizes = [inspect(path, private=False) for path in files]
        if (len(files) > 128 or any(not path.name.endswith(".rpm") for path in files)
                or any(not 0 < value.st_size <= 512 * 1024 * 1024 for value in sizes)
                or sum(value.st_size for value in sizes) > 1024 * 1024 * 1024):
            raise ValueError("download batch is not bounded regular RPM files")
        for path in files:
            sys.stdout.buffer.write(os.fsencode(path) + b"\0")
    elif action == "commit":
        slot = Path(sys.argv[4])
        if slot not in (root / "slot0", root / "slot1") or (pointer and slot.name == "slot" + pointer["slot"]):
            raise ValueError("candidate slot is not independent of the current slot")
        inventory(slot)
        receipt = json.loads(read(Path(sys.argv[5])))
        if (receipt.get("schema") != 1 or receipt.get("vendor_fingerprint") != fingerprint
                or receipt.get("snapshots_retained") is not True or receipt.get("installs_performed") is not False
                or receipt.get("freshness_proven") is not False or not isinstance(receipt.get("artifacts"), list)):
            raise ValueError("retained admission evidence is malformed")
        records = [{"file": "packages/" + str(index) + ".rpm", "bytes": value["bytes"], "sha256": value["sha256"]}
                   for index, value in enumerate(receipt["artifacts"])]
        for path in inventory(slot):
            path.chmod(0o400)
        manifest = json.dumps({"schema": 1, "vendor_fingerprint": fingerprint, "packages": records,
                               "installs_performed": False, "freshness_proven": False}, sort_keys=True).encode() + b"\n"
        write(slot / "manifest.json", manifest, 0o400)
        new = {"schema": 1, "slot": slot.name[-1], "manifest_sha256": hashlib.sha256(manifest).hexdigest()}
        # Validate bytes against the same admission receipt BEFORE publication.
        validate(new, False)
        for path in [*inventory(slot), slot / "owner", slot / "manifest.json", slot / "packages", slot]:
            flush(path)
        barrier(slot, root, root.parent)
        temporary = root / "current.next"
        write(temporary, json.dumps(new, sort_keys=True).encode() + b"\n", 0o600)
        temporary.replace(current)
        flush(root)
        barrier(root, root.parent)
        validate(new, True)
        print(json.dumps(new, sort_keys=True))
    elif action in ("verify", "plan"):
        if pointer is None:
            raise ValueError("no signed update batch is prepared")
        slot = validate(pointer, True)
        if action == "plan":
            proof = json.loads(read(slot / "manifest.json"))
            print(json.dumps({"schema": 1, "manifest_sha256": pointer["manifest_sha256"],
                              "packages": [{**record, "path": str(slot / record["file"])}
                                           for record in proof["packages"]]}, sort_keys=True))
    else:
        raise ValueError("unknown update-store operation")
except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
    print("azurelinux3s4: update preparation deferred: " + str(error), file=sys.stderr)
    sys.exit(75)

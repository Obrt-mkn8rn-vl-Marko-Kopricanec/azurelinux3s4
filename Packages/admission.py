import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import stat
import subprocess
import sys
import tempfile

try:
    root = Path(sys.argv[1])
    home, database = root / "home", root / "rpmdb"
    home.mkdir(mode=0o700)
    database.mkdir(mode=0o700)
    environment = {"PATH": os.environ["PATH"], "HOME": str(home), "LC_ALL": "C", "LANG": "C"}
    common = ["--noplugins", "--dbpath", str(database), "--define", "_keyring rpmdb",
              "--define", "_pkgverify_level all", "--define", "_pkgverify_flags 0"]

    def command_limits():
        # This child-only limit bounds diagnostics/database files without
        # limiting the parent copying a large, bounded package snapshot.
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))

    def run(tool, *arguments, limit=30):
        # A malformed RPM cannot make diagnostics consume unbounded RAM/disk.
        with tempfile.TemporaryFile(dir=root) as output:
            result = subprocess.run([tool, *common, *arguments], stdin=subprocess.DEVNULL,
                                    stdout=output, stderr=output, env=environment, timeout=limit,
                                    preexec_fn=command_limits)
            output.seek(0)
            data = output.read(65537)
        if result.returncode or len(data) > 65536:
            raise ValueError(tool + " did not provide bounded successful evidence")
        return data.decode("ascii")

    def snapshot(source, target, maximum):
        source = Path(source)
        if not source.is_absolute() or len(os.fsencode(source)) > 4096:
            raise ValueError("artifact path is not a bounded absolute path")
        observed = source.lstat()
        if not stat.S_ISREG(observed.st_mode):
            raise ValueError("input is not a regular file before opening")
        descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode)
                    or (before.st_dev, before.st_ino) != (observed.st_dev, observed.st_ino)
                    or before.st_uid not in (0, os.geteuid())
                    or before.st_mode & 0o022 or not 0 < before.st_size <= maximum):
                raise ValueError("input is not an admissible bounded regular file")
            digest = hashlib.sha256()
            total = 0
            with target.open("xb") as destination:
                target.chmod(0o600)
                while block := stream.read(1024 * 1024):
                    total += len(block)
                    if total > maximum:
                        raise ValueError("input grew beyond its admission bound")
                    digest.update(block)
                    destination.write(block)
            after = os.fstat(stream.fileno())
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                                      value.st_mtime_ns, value.st_ctime_ns)
            if identity(before) != identity(after) or total != before.st_size:
                raise ValueError("input changed while its private snapshot was copied")
        return digest.hexdigest(), total

    key = root / "vendor.asc"
    digest, size = snapshot(sys.argv[2], key, 983)
    if size != 983 or digest != sys.argv[3]:
        raise ValueError("private admission key differs from its vetted pin")
    run("rpm", "--initdb")
    run("rpm", "--import", str(key))
    names = run("rpm", "-qa", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}\\n").splitlines()
    if names != ["gpg-pubkey-3135ce90-5e6fda74"]:
        raise ValueError("private RPM database contains a missing or additional identity")
    packets = run("rpm", "-q", "--qf", "[%{PUBKEYS}\\n]", names[0])
    decoded = base64.b64decode("".join(packets.splitlines()), validate=True)
    if hashlib.sha256(decoded).hexdigest() != "38ced48482bda02f404a772c09c3572440a3f597bf15cc3b7abadaef60be2e81":
        raise ValueError("actual private RPM key packets differ from the vetted identity")

    signature = re.compile(r"Header V[34] RSA/SHA(?:256|384|512) Signature, key ID 3135ce90: OK")
    package_signature = re.compile(r"V[34] RSA/SHA(?:256|384|512) Signature, key ID 3135ce90: OK")
    strong_header = re.compile(r"Header SHA(?:256|384|512) digest: OK")
    strong_payload = re.compile(r"Payload SHA(?:256|384|512) digest: OK")
    additional = {"Header SHA1 digest: OK", "MD5 digest: OK"}
    admitted, total = [], 0
    destination = Path(sys.argv[5]) if sys.argv[5] else root
    if destination != root:
        observed = destination.lstat()
        if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid not in (0, os.geteuid())
                or observed.st_mode & 0o077 or any(destination.iterdir())):
            raise ValueError("retained snapshot directory is not private and empty")
    for index, name in enumerate(sys.argv[6:]):
        artifact = destination / (str(index) + ".rpm")
        digest, size = snapshot(name, artifact, 512 * 1024 * 1024)
        total += size
        if total > 1024 * 1024 * 1024:
            raise ValueError("artifact batch exceeds its one-GiB bound")
        lines = run("rpmkeys", "--checksig", "--verbose", str(artifact), limit=120).splitlines()
        if not lines or lines[0] != str(artifact) + ":":
            raise ValueError("native verifier did not identify the private artifact")
        records = [line.strip() for line in lines[1:]]
        if (not any(signature.fullmatch(line) for line in records)
                or not any(strong_header.fullmatch(line) for line in records)
                or not any(strong_payload.fullmatch(line) for line in records)
                or any(not (signature.fullmatch(line) or package_signature.fullmatch(line) or strong_header.fullmatch(line)
                            or strong_payload.fullmatch(line) or line in additional) for line in records)):
            raise ValueError("native evidence lacks a pinned signature and strong header/payload digests")
        admitted.append({"path": name, "sha256": digest, "bytes": size})
    print(json.dumps({"schema": 1, "vendor_fingerprint": sys.argv[4], "artifacts": admitted,
                      "installs_performed": False, "snapshots_retained": destination != root,
                      "freshness_proven": False}, sort_keys=True))
except (ValueError, OSError, UnicodeError, subprocess.SubprocessError) as error:
    print("azurelinux3s4: package admission deferred: " + str(error), file=sys.stderr)
    sys.exit(75)

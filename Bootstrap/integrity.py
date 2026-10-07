import collections
import re
import stat
import subprocess
import sys

def rpm(*args):
    return subprocess.run(["rpm", *args], stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, timeout=15)

try:
    pending = collections.deque(["tdnf-plugin-repogpgcheck", "tdnf", "gnupg2"])
    seen, providers, broken = set(), {}, set()
    while pending:
        package = pending.popleft()
        if package in seen:
            continue
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9+_.-]{0,127}", package):
            raise ValueError("invalid RPM package identity")
        seen.add(package)
        if len(seen) > 128:
            raise ValueError("RPM dependency closure exceeds the verification bound")
        requirements = rpm("-q", "--requires", package)
        if requirements.returncode:
            raise ValueError("RPM requirements could not be queried for " + package)
        for requirement in requirements.stdout.splitlines():
            if requirement.startswith("rpmlib("):
                continue
            capability = requirement.split(" ", 1)[0]
            if capability not in providers:
                if len(providers) >= 1024:
                    raise ValueError("too many RPM dependency capabilities")
                result = rpm("-q", "--whatprovides", "--qf", "%{NAME}\n", capability)
                if result.returncode or not result.stdout.strip():
                    raise ValueError("RPM dependency has no installed provider: " + requirement)
                providers[capability] = result.stdout.splitlines()
            pending.extend(providers[capability])
        # rpm verification retains dependency/version checking as well as files.
        result = rpm("-V", "--noscripts", "--noconfig", package)
        if result.returncode == 0 and not result.stdout and not result.stderr:
            continue
        manifest = rpm("-q", "--qf", "[%{FILENAMES}\t%{FILEMODES}\t%{FILEFLAGS}\n]", package)
        if manifest.returncode:
            raise ValueError("RPM file manifest could not be queried for " + package)
        files = {}
        for entry in manifest.stdout.splitlines():
            name, mode, flags = entry.split("\t")
            files[name] = (int(mode), int(flags))
        def excluded(line):
            if " /" not in line:
                return False
            prefix, name = line.split(" /", 1)
            name = "/" + name
            if not re.fullmatch(r"(?:[.SM5DLUGTP?]{9}|missing)\s+[cdglr]?\s*", prefix):
                return False
            if name not in files:
                return False
            mode, flags = files[name]
            # RPM CONFIG/DOC/GHOST/LICENSE/README flags, directories, omitted
            # translations, and mutable logs/cache/runtime state are not code.
            # Critical write/executable ancestry is checked separately.
            return (bool(flags & (1 | 2 | 64 | 128 | 256)) or stat.S_ISDIR(mode)
                    or name.startswith(("/usr/share/locale/", "/var/log/", "/var/cache/", "/run/")))
        lines = result.stdout.splitlines()
        mutable_assets = (result.returncode == 1 and not result.stderr and bool(lines)
                          and all(excluded(line) for line in lines))
        if not mutable_assets:
            broken.add(package)
    for package in sorted(broken):
        print(package)
except (ValueError, OSError, subprocess.SubprocessError) as error:
    print("azurelinux3s4: verifier integrity query failed: " + str(error), file=sys.stderr)
    sys.exit(1)

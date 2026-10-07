import hashlib
import os
from pathlib import Path
import selectors
import stat
import subprocess
import sys
import tempfile
import time

try:
    # Read a bounded snapshot; GnuPG imports that snapshot, not a second read of
    # a potentially replaced source key. The SHA-256 pins all keyblock packets.
    with open(sys.argv[2], "rb") as source:
        key = source.read(65537)
    if len(key) > 65536 or hashlib.sha256(key).hexdigest() != sys.argv[3]:
        raise ValueError("Azure Linux vendor key does not match the vetted keyblock")
    with tempfile.TemporaryDirectory(prefix="transaction.", dir=sys.argv[1]) as directory:
        root = Path(directory)
        home = root / "gnupg"
        home.mkdir(mode=0o700)
        (home / "gpg.conf").write_text(
            "no-autostart\ndisable-dirmngr\nno-auto-key-retrieve\nno-auto-key-import\n")
        snapshot = root / "vendor.asc"
        snapshot.write_bytes(key)
        environment = dict(os.environ, GNUPGHOME=str(home), LC_ALL="C")
        environment.pop("GPG_AGENT_INFO", None)
        gpg = ["gpg2", "--no-options", "--homedir", str(home), "--batch", "--no-tty",
               "--no-autostart", "--disable-dirmngr", "--no-auto-key-retrieve", "--no-auto-key-import"]
        def run(*arguments, **options):
            return subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True,
                                  text=True, env=environment, **options)
        imported = run(*gpg, "--import", str(snapshot), timeout=15)
        if imported.returncode:
            raise ValueError("vetted vendor key could not be imported into its private keyring")
        listed = run(*gpg, "--with-colons", "--list-keys", timeout=15)
        records = [line.split(":") for line in listed.stdout.splitlines()]
        public = [record for record in records if record[0] == "pub"]
        fingerprints = [record[9] for record in records if record[0] == "fpr" and len(record) > 9]
        if (listed.returncode or len(public) != 1 or len(public[0]) < 10
                or fingerprints != [sys.argv[4]] or public[0][1] in ("r", "e", "d")
                or any(record[0] in ("sec", "ssb") for record in records)):
            raise ValueError("private metadata keyring did not prove the exact vendor identity")
        # Verbose loader evidence is mandatory for this actual operation as well
        # as the separate integrity/invalid-signature challenge before it.
        command = ["tdnf", "-v", "-c", sys.argv[5], "--releasever=3.0", "--refresh", "-y",
                   "--disableplugin=*", "--enableplugin=tdnfrepogpgcheck", *sys.argv[8:]]
        if sys.argv[7]:
            incoming = Path(sys.argv[7])
            observed = incoming.lstat()
            if (not stat.S_ISDIR(observed.st_mode) or observed.st_uid != os.geteuid()
                    or observed.st_mode & 0o077 or any(incoming.iterdir())
                    or any(character not in "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
                           for character in str(incoming) + str(root))):
                raise ValueError("download workspace is not an empty private directory")
            cache = root / "cache"
            cache.mkdir(mode=0o700)
            configuration = Path(sys.argv[5]).read_text()
            lines = configuration.splitlines()
            if sum(line.startswith("cachedir=") for line in lines) != 1:
                raise ValueError("download cache policy is ambiguous")
            (root / "download.conf").write_text("\n".join(
                "cachedir=" + str(cache) if line.startswith("cachedir=") else line
                for line in lines) + "\n")
            command[3] = str(root / "download.conf")
            unit = "azurelinux3s4-download-" + root.name.removeprefix("transaction.") + ".service"
            probe = """import os, sys
status = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
if any(int(status[name].strip(), 16) for name in ('CapEff', 'CapPrm', 'CapBnd', 'CapAmb')) or status['NoNewPrivs'].strip() != '1':
    raise SystemExit('download sandbox lacks its privilege restriction')
for path in ('/', '/etc', '/usr', '/var/lib', '/var/lib/rpm'):
    if not os.statvfs(path).f_flag & os.ST_RDONLY:
        raise SystemExit('download sandbox lacks read-only system protection: ' + path)
for path in ('/run/systemd/private', '/run/dbus/system_bus_socket'):
    if os.access(path, os.R_OK | os.W_OK):
        raise SystemExit('download sandbox exposes a privileged manager socket')
print('S4_DOWNLOAD_SANDBOX_VERIFIED', flush=True)
os.execvp(sys.argv[1], sys.argv[1:])
"""
            sandbox = ["systemd-run", "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec",
                       "--unit=" + unit, "--property=RuntimeMaxSec=14min", "--property=TimeoutStopSec=15s",
                       "--property=KillMode=control-group", "--property=ProtectSystem=strict",
                       "--property=ReadWritePaths=" + str(root) + " " + str(incoming),
                       "--property=ProtectHome=yes", "--property=PrivateTmp=yes", "--property=PrivateDevices=yes",
                       "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
                       "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes",
                       "--property=ProtectKernelLogs=yes", "--property=ProtectControlGroups=yes",
                       "--property=RestrictNamespaces=yes", "--property=RestrictRealtime=yes",
                       "--property=LockPersonality=yes", "--property=UMask=0077",
                       "--property=InaccessiblePaths=/run/systemd/private /run/dbus/system_bus_socket",
                       "--property=LimitFSIZE=536870912", "--property=MemoryMax=768M",
                       "--property=UnsetEnvironment=RPM_CONFIGDIR RPM_POPTEXEC_PATH GPG_AGENT_INFO LD_PRELOAD LD_LIBRARY_PATH",
                       "--setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin", "--setenv=LC_ALL=C", "--setenv=LANG=C",
                       "--setenv=HOME=" + str(home), "--setenv=GNUPGHOME=" + str(home), "--",
                       "python3", "-I", "-c", probe, *command]
            # Stream diagnostics into a bounded buffer. Watch the flat incoming
            # directory while tdnf runs, rather than admitting a huge completed download.
            process = subprocess.Popen(sandbox, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, env=environment)
            completed = False
            try:
                output = bytearray()
                deadline = time.monotonic() + 800
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ)
                    while selector.get_map():
                        if time.monotonic() >= deadline:
                            raise ValueError("download deadline expired")
                        entries = list(incoming.iterdir())
                        sizes = [entry.lstat() for entry in entries]
                        if (len(entries) > 128 or any(not stat.S_ISREG(value.st_mode)
                                or value.st_size > 512 * 1024 * 1024 for value in sizes)
                                or sum(value.st_size for value in sizes) > 1024 * 1024 * 1024):
                            raise ValueError("download exceeded its regular-file/count/size bounds")
                        for event, _ in selector.select(0.2):
                            data = os.read(event.fd, 65536)
                            if not data:
                                selector.unregister(event.fileobj)
                            else:
                                output.extend(data)
                                if len(output) > 1024 * 1024:
                                    raise ValueError("download diagnostics exceeded their bound")
                code = process.wait(timeout=max(1, deadline - time.monotonic()))
                completed = True
                transaction = subprocess.CompletedProcess(sandbox, code, output.decode("utf-8", "strict"), "")
                if "S4_DOWNLOAD_SANDBOX_VERIFIED\n" not in transaction.stdout:
                    raise ValueError("download sandbox enforcement was not positively observed")
            finally:
                if not completed:
                    stopped = subprocess.run(["systemctl", "stop", unit], stdin=subprocess.DEVNULL,
                                             capture_output=True, timeout=30)
                    process.kill()
                    process.wait(timeout=15)
                    if stopped.returncode:
                        raise ValueError("download service shutdown could not be confirmed")
        else:
            transaction = run(*command, timeout=240)
        print(transaction.stdout, end="")
        print(transaction.stderr, end="", file=sys.stderr)
        output = transaction.stdout + transaction.stderr
        if transaction.returncode:
            sys.exit(transaction.returncode if 0 < transaction.returncode < 126 else 75)
        if "Loaded plugin: tdnfrepogpgcheck" not in output or "Error loading plugin" in output:
            raise ValueError("native metadata verifier participation was not observed")
except (ValueError, OSError, UnicodeError, subprocess.SubprocessError) as error:
    print("azurelinux3s4: trusted metadata transaction deferred: " + str(error), file=sys.stderr)
    sys.exit(75)

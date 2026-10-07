import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import socket
import shutil
import stat
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "azurelinux3s4.sh"


class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cache = Path.home() / ".cache"
        cache.mkdir(mode=0o700, exist_ok=True)
        cls.compiled = tempfile.TemporaryDirectory(prefix="azurelinux3s4-elf-", dir=cache)
        cls.addClassCleanup(cls.compiled.cleanup)
        root = Path(cls.compiled.name)
        cls.dependency = root / "libfixturedependency.so"
        cls.library = root / "libtdnfrepogpgcheck.so"
        subprocess.run(["cc", "-shared", "-fPIC", "-x", "c", "-", "-o", str(cls.dependency)],
                       input="void fixture_dependency(void) {}\n", text=True, check=True, capture_output=True)
        subprocess.run(["cc", "-shared", "-fPIC", "-x", "c", "-", "-L", str(root),
                        "-lfixturedependency", "-Wl,-rpath,$ORIGIN", "-o", str(cls.library)],
                       input="""#include <stdint.h>
extern void fixture_dependency(void);
uint32_t TDNFPluginLoadInterface(void **functions) {
    fixture_dependency();
    for (int i=0; i<5; i++) functions[i] = fixture_dependency;
    return 0;
}
""", text=True, check=True, capture_output=True)

    def setUp(self):
        original_umask = os.umask(0o077)
        self.addCleanup(os.umask, original_umask)
        # Use a private, non-writable ancestry rather than a shared /tmp tree.
        cache = Path.home() / ".cache"
        cache.mkdir(mode=0o700, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="azurelinux3s4-test-", dir=cache)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ("state", "state/components", "state/repos", "run", "runner", "units", "systemd",
                     "bin", "plugin", "pluginconf", "rpmdb"):
            (self.root / name).mkdir(mode=0o700)
        material = (SCRIPT.parent / "tests/fixtures/azurelinux-rpm-key.asc").read_bytes()
        (self.root / "rpm-key").write_bytes(material)
        packets = base64.b64decode("".join(line for line in material.decode('ascii').splitlines()
            if line and not line.startswith(("-----", "Version:", "="))), validate=True)
        bundle = next(path for path in (Path('/etc/ssl/certs/ca-certificates.crt'),
            Path('/etc/pki/tls/certs/ca-bundle.crt')) if path.exists())
        (self.root / 'ca-bundle').write_bytes(bundle.read_bytes())
        self.plugin = self.root / "plugin/libtdnfrepogpgcheck.so"
        self.plugin_dependency = self.root / "plugin/libfixturedependency.so"
        shutil.copyfile(self.library, self.plugin)
        shutil.copyfile(self.dependency, self.plugin_dependency)
        self.plugin_config = self.root / "pluginconf/tdnfrepogpgcheck.conf"
        self.plugin_config.write_text('[main]\nenabled=1\n')
        self.database = {"files": {"tdnf-plugin-repogpgcheck": {str(self.plugin): self.digest(self.plugin)},
                                   "plugin-dependency": {str(self.plugin_dependency): self.digest(self.plugin_dependency)}},
                         "verification": {}, "vendor_packets": [base64.b64encode(packets).decode('ascii')]}
        self.write_database()
        (self.root / "units/azurelinux3s4-repair.timer").write_text("fixture timer\n")
        (self.root / "units/azurelinux3s4-finalization-recovery.timer").write_text("fixture recovery timer\n")
        (self.root / "units/azurelinux3s4-repair.service").write_text("fixture worker\n")
        shutil.copyfile(SCRIPT, self.root / "runner/azurelinux3s4.sh")
        (self.root / "runner/azurelinux3s4.sh").chmod(0o700)
        self.command("systemctl", r'''
import os
from pathlib import Path
import sys
root = Path(os.environ["S4_FIXTURE_ROOT"])
args = sys.argv[1:]
with (root / "events").open("a") as log:
    log.write(" ".join(args) + "\n")
unit = args[-1]
kind = "recovery" if unit == "azurelinux3s4-finalization-recovery.timer" else "update" if unit == "azurelinux3s4-update-preparation.timer" else "timer"
enabled, active = root / ("run/" + kind + "-enabled"), root / ("run/" + kind + "-active")
link = root / "units/timers.target.wants" / unit
prefix = "S4_RECOVERY_" if kind == "recovery" else "S4_PRIMARY_"
def setting(name, default="0"):
    return os.environ.get(prefix + name, os.environ.get("S4_" + name, default))
if args[0] == "daemon-reload":
    sys.exit(int(os.environ.get("S4_DAEMON_FAILURE", "0")))
if args[0] == "enable":
    if setting("ENABLE_FAILURE") != "0": sys.exit(int(setting("ENABLE_FAILURE")))
    enabled.touch(); active.touch()
    sys.exit(0)
if args[0] == "disable":
    enabled.unlink(missing_ok=True); active.unlink(missing_ok=True)
    link.unlink(missing_ok=True)
    if os.environ.get("S4_REMOVE_EMPTY_WANTS") and not any(link.parent.iterdir()): link.parent.rmdir()
    sys.exit(int(setting("DISABLE_FAILURE")))
if args[0] == "show":
    if setting("QUERY_FAILURE") != "0":
        print("manager query failed", file=sys.stderr)
        sys.exit(int(setting("QUERY_FAILURE")))
    print("LoadState=" + setting("LOAD_STATE", "loaded"))
    print("UnitFileState=" + setting("FILE_STATE", "enabled" if link.is_symlink() else "disabled"))
    print("ActiveState=" + setting("ACTIVE_STATE", "active" if active.exists() else "inactive"))
    sys.exit(0)
sys.exit(99)
''')
        # Keep ordinary command fixtures within their private tree. The native
        # Azure VM exercises real syncfs; these tests use file/directory fsync.
        self.command("sync", r'''
import os
from pathlib import Path
import sys
root = Path(os.environ["S4_FIXTURE_ROOT"])
if os.environ.get("S4_SYNC_ERROR_PATH") in sys.argv[1:]: sys.exit(42)
for name in sys.argv[1:]:
    if name in ("-f", "--"): continue
    path = Path(name)
    path.relative_to(root)
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
''')
        self.command("rpm", r'''
import hashlib
import json
import os
from pathlib import Path
import sys
data = json.loads((Path(os.environ["S4_FIXTURE_ROOT"]) / "rpm-database.json").read_text())
args, package = sys.argv[1:], sys.argv[-1]
root = Path(os.environ["S4_FIXTURE_ROOT"])
if args[0] == "--eval":
    if os.environ.get("S4_RPM_EVAL_ERROR"): sys.exit(42)
    print(os.environ.get("S4_RPM_KEYRING", "rpmdb") if args[1] == "%{?_keyring}" else os.environ.get("S4_RPM_DATABASE", str(root / "rpmdb")))
    sys.exit(0)
if args[0] == "--import":
    with (root / "rpm-imports").open("a") as log: log.write(package + "\n")
    if os.environ.get("S4_RPM_IMPORT_ERROR"): sys.exit(42)
    if not os.environ.get("S4_RPM_IMPORT_NOOP"):
        lines=Path(package).read_text().splitlines()
        data["vendor_packets"]=["".join(line for line in lines if line and not line.startswith(("-----", "Version:", "=")))]
        (root / "rpm-database.json").write_text(json.dumps(data))
    sys.exit(0)
if "%{PUBKEYS}" in " ".join(args):
    if os.environ.get("S4_RPM_KEY_QUERY_ERROR"): sys.exit(42)
    if not data.get("vendor_packets"): sys.exit(1)
    print("\n".join(data["vendor_packets"]))
    sys.exit(0)
packages = {"tdnf-plugin-repogpgcheck", "tdnf", "gnupg2", "plugin-dependency"}
if "--requires" in args:
    if package not in packages: sys.exit(1)
    if package == "tdnf-plugin-repogpgcheck":
        print("plugin-dependency >= 1\nrpmlib(PayloadIsZstd) <= 5.4.18-1")
    if package == "tdnf": print("config(tdnf) = 3.5.8")
    sys.exit(0)
if "--whatprovides" in args:
    if package == "config(tdnf)": package = "tdnf"
    if package not in packages: sys.exit(1)
    print(package); sys.exit(0)
if "--qf" in args:
    for name in data["files"].get(package, {}):
        print(name + "\t33188\t0")
    for name, mode, flags in data.get("manifest", {}).get(package, []):
        print(f"{name}\t{mode}\t{flags}")
    sys.exit(0)
if args[0] == "-V":
    if package in data["verification"]:
        result = data["verification"][package]
        print(result.get("stdout", ""), end="")
        print(result.get("stderr", ""), end="", file=sys.stderr)
        sys.exit(result["exit"])
    for name, digest in data["files"].get(package, {}).items():
        path = Path(name)
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            print("..5......   " + name); sys.exit(1)
    sys.exit(0)
if args[0] == "-q": sys.exit(0)
sys.exit(99)
''')
        self.command("gpg2", r'''
import os
import shutil
import sys
os.execv(shutil.which("gpg"), ["gpg", *sys.argv[1:]])
''')
        # The host has no native Azure tdnf. This command fixture exercises the
        # probe's control and evidence rules and actually loads the ELF fixtures.
        # Native tdnf participation is also validated separately in the local VM.
        self.command("tdnf", r'''
import ctypes
import gzip
import os
from pathlib import Path
import sys
import time
import xml.etree.ElementTree as ET
args = sys.argv[1:]
config = dict(line.split("=", 1) for line in Path(args[args.index("-c")+1]).read_text().splitlines() if "=" in line)
home = Path(os.environ.get("GNUPGHOME", ""))
repo = Path(config["repodir"]) / "probe.repo"
if repo.exists() and home != Path(config["persistdir"]).parent / "gnupg": sys.exit(98)
if not repo.exists() and not home.parent.name.startswith("transaction."): sys.exit(98)
if home.stat().st_mode & 0o777 != 0o700: sys.exit(98)
if "no-autostart\ndisable-dirmngr\n" not in (home / "gpg.conf").read_text(): sys.exit(98)
if repo.exists():
    metadata = Path(dict(line.split("=", 1) for line in repo.read_text().splitlines() if "=" in line)["baseurl"].removeprefix("file://"))
    ET.fromstring((metadata / "repodata/repomd.xml").read_bytes())
    ET.fromstring(gzip.decompress((metadata / "repodata/primary.xml.gz").read_bytes()))
else:
    if not (home / "pubring.kbx").is_file(): sys.exit(98)
    if "GPG_AGENT_INFO" in os.environ: sys.exit(98)
    with (Path(os.environ["S4_FIXTURE_ROOT"]) / "native-transactions").open("a") as log:
        import json
        log.write(json.dumps({"args": args, "home": str(home), "stdin": sys.stdin.read()}) + "\n")
if "--noplugins" in args: sys.exit(int(os.environ.get("S4_CONTROL_FAILURE", "0")))
mode = os.environ.get("S4_TDNF_MODE", "verified")
if mode == "hang": time.sleep(100)
if mode == "bypass": sys.exit(0)
try:
    library = ctypes.CDLL(str(Path(config["pluginpath"]) / "libtdnfrepogpgcheck.so"))
    interface = library.TDNFPluginLoadInterface
    functions = (ctypes.c_void_p * 5)()
    interface.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
    interface.restype = ctypes.c_uint32
    if interface(functions) or not all(functions): sys.exit(0)
except (OSError, AttributeError):
    print("Error loading plugin")
    sys.exit(0)  # upstream tdnf's fail-open behavior
print("Loaded plugin: tdnfrepogpgcheck")
if not repo.exists():
    if os.environ.get("S4_NETWORK_FAILURE"): sys.exit(int(os.environ["S4_NETWORK_FAILURE"]))
    print("Refreshing repo: azurelinux3s4-base\nRefreshing repo: azurelinux3s4-extended")
    sys.exit(0)
if mode == "load-only": sys.exit(1)
if mode == "engine-error":
    print("gpg verify failed: Invalid crypto engine\nError: TDNFVerifySignature 2003")
else:
    print("gpg verify failed: No data\nError: TDNFVerifySignature 2003")
sys.exit(1)
''')
        self.header = f"""
source {shlex.quote(str(SCRIPT))}
S4_STATE={shlex.quote(str(self.root / 'state'))}
S4_RUN={shlex.quote(str(self.root / 'run'))}
S4_INSTALL_DIR={shlex.quote(str(self.root / 'runner'))}
S4_SYSTEMD_DIR={shlex.quote(str(self.root / 'units'))}
S4_OS_RELEASE={shlex.quote(str(self.root / 'os-release'))}
S4_SYSTEMD_RUNTIME={shlex.quote(str(self.root / 'systemd'))}
S4_GPG_KEY={shlex.quote(str(self.root / 'rpm-key'))}
S4_CA_BUNDLE={shlex.quote(str(self.root / 'ca-bundle'))}
S4_PLUGIN_LIBRARY={shlex.quote(str(self.plugin))}
S4_PLUGIN_CONFIG={shlex.quote(str(self.plugin_config))}
export S4_FIXTURE_ROOT={shlex.quote(str(self.root))}
export PATH={shlex.quote(str(self.root / 'bin'))}:$PATH
S4_ARCH=x86_64
S4_NOW=1000000
S4_COMPONENTS=(bootstrap)
update-ca-trust() {{ return 0; }}
"""

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write_database(self):
        (self.root / "rpm-database.json").write_text(json.dumps(self.database))

    def command(self, name, program):
        path = self.root / "bin" / name
        path.write_text("#!/usr/bin/python3\n" + program.lstrip())
        path.chmod(0o700)

    def shell(self, body, expected=0, timeout=30):
        result = subprocess.run(
            ["bash", "-c", self.header + "\n" + body],
            text=True,
            capture_output=True,
            timeout=timeout,
        )
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def state(self):
        return dict(line.split("=", 1) for line in (self.root / "state/components/bootstrap").read_text().splitlines())

    def durability_model(self):
        # Model /etc, /usr and /var as separate filesystems. Only successful -f
        # barriers commit their snapshots. An adverse reboot drops all remaining
        # changes, including visible renames/links and newly created ancestry.
        # This is a control-flow/persistence model, not physical power-loss proof.
        self.command("sync", r'''
import base64
import json
import os
from pathlib import Path
import stat
import sys
root = Path(os.environ["S4_FIXTURE_ROOT"])
args = sys.argv[1:]
operands = [Path(name) for name in args if name not in ("-f", "--")]
for path in operands: path.relative_to(root)
wants = root / "units/timers.target.wants"
failed = bool(os.environ.get("S4_SYNC_FAIL_WANTS") and wants in operands)
failed |= bool(os.environ.get("S4_SYNC_FAIL_PARENT") and root / "units" in operands)
failed |= bool(os.environ.get("S4_SYNC_FAIL_RUNNER") and root / "runner" in operands)
completion = root / "state/finalization"
failed |= bool(os.environ.get("S4_SYNC_FAIL_COMPLETION") and root / "state" in operands
               and completion.exists() and completion.read_text() == "status=complete\n")
if os.environ.get("S4_SYNC_FAIL_ONCE") and wants in operands and not (root / "failed-once").exists():
    (root / "failed-once").touch(); failed = True
with (root / "barriers").open("a") as log:
    log.write(json.dumps({"args": args, "ok": not failed}) + "\n")
if failed: sys.exit(42)
if "-f" not in args: sys.exit(0)
database = root / "durable.json"
durable = json.loads(database.read_text()) if database.exists() else {}
for path in operands:
    scope = path.relative_to(root).parts[0]
    if scope not in ("units", "runner", "state"): sys.exit(99)
    filesystem = root / scope
    snapshot = {}
    for entry in [filesystem, *filesystem.rglob("*")]:
        name, mode = str(entry.relative_to(filesystem)), stat.S_IMODE(entry.lstat().st_mode)
        if entry.is_symlink(): snapshot[name] = ["link", str(entry.readlink()), mode]
        elif entry.is_dir(): snapshot[name] = ["directory", "", mode]
        else: snapshot[name] = ["file", base64.b64encode(entry.read_bytes()).decode(), mode]
    durable[scope] = snapshot
database.write_text(json.dumps(durable))
''')
        # This retained model covers the accepted two-activator finalization
        # transaction. The new periodic preparation timer is tested separately.
        self.shell('s4_install_runner; s4_install_units; systemctl disable --now "$S4_UPDATE_TIMER"; sync -f -- "$S4_SYSTEMD_DIR"; s4_write_state bootstrap complete 0 0 0')

    def adverse_reboot(self, persist_visible_unit_deletions=False):
        durable = json.loads((self.root / "durable.json").read_text())
        # Unsynced deletion is also allowed to survive. Exercise that choice
        # separately once completion is committed, rather than always rolling back.
        deleted = []
        if persist_visible_unit_deletions:
            for timer in ("azurelinux3s4-repair.timer", "azurelinux3s4-finalization-recovery.timer"):
                link = self.root / "units/timers.target.wants" / timer
                if not link.is_symlink(): deleted.append(timer)
        for scope, snapshot in durable.items():
            directory = self.root / scope
            shutil.rmtree(directory)
            for name, (kind, payload, mode) in sorted(snapshot.items(), key=lambda item: len(Path(item[0]).parts)):
                path = directory / name
                if kind == "directory": path.mkdir(mode=mode)
                elif kind == "link": path.symlink_to(payload)
                else: path.write_bytes(base64.b64decode(payload)); path.chmod(mode)
        for timer in deleted:
            (self.root / "units/timers.target.wants" / timer).unlink(missing_ok=True)
        for flag in (self.root / "run").glob("*-active"): flag.unlink()
        for flag in (self.root / "run").glob("*-enabled"): flag.unlink()
        activators = []
        for link in sorted((self.root / "units/timers.target.wants").glob("*.timer")):
            if not link.is_symlink() or not link.is_file(): continue
            policy = link.read_text()
            self.assertIn("WantedBy=timers.target", policy)
            self.assertIn("OnBootSec=", policy)
            self.assertIn("Unit=azurelinux3s4-repair.service", policy)
            service = (self.root / "units/azurelinux3s4-repair.service").read_text()
            self.assertIn("ExecStart=/bin/bash " + str(self.root / "runner/azurelinux3s4.sh") + " --repair", service)
            self.assertEqual((self.root / "runner/azurelinux3s4.sh").read_bytes(), SCRIPT.read_bytes())
            kind = "recovery" if "finalization-recovery" in link.name else "timer"
            (self.root / ("run/" + kind + "-active")).touch()
            (self.root / ("run/" + kind + "-enabled")).touch()
            activators.append(link.name)
        return activators

    def resume_boot_worker(self):
        # Dispatch the persisted worker, using the same fixture commands and
        # trusted-variable overrides. Component health is already closed/scoped.
        header = self.header.replace(shlex.quote(str(SCRIPT)),
                                     shlex.quote(str(self.root / "runner/azurelinux3s4.sh")), 1)
        result = subprocess.run(["bash", "-c", header + "\ns4_lock; s4_verify_bootstrap() { return 0; }; s4_repair no"],
                                text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.root / "state/finalization").read_text(), "status=complete\n")
        self.assertEqual(list((self.root / "units/timers.target.wants").glob("*.timer")), [])
        self.assertFalse((self.root / "run/timer-active").exists())
        self.assertFalse((self.root / "run/recovery-active").exists())

    def test_nonroot_main_refuses_before_mutating(self):
        if os.geteuid() == 0:
            self.skipTest("Requires an unprivileged test process")
        result = subprocess.run([str(SCRIPT)], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 77)
        self.assertIn("administrator privileges", result.stderr)

    def test_help_is_available_without_privilege(self):
        result = subprocess.run([str(SCRIPT), "--help"], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertIn("hardening and update installation are incomplete", result.stdout)

    def test_unknown_action_is_rejected(self):
        result = subprocess.run([str(SCRIPT), "--unknown"], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 64)

    def test_wrong_distribution_and_version_are_rejected(self):
        for distro, version in (("debian", "13"), ("azurelinux", "4.0"), ("mariner", "2.0")):
            with self.subTest(distro=distro, version=version):
                (self.root / "os-release").write_text(f'ID="{distro}"\nVERSION_ID="{version}"\n')
                self.shell("s4_platform", expected=78)

    def test_supported_azure_linux_platform(self):
        (self.root / "os-release").write_text('ID="azurelinux"\nVERSION_ID="3.0"\n')
        self.shell("s4_platform; [[ $S4_ARCH == x86_64 || $S4_ARCH == aarch64 ]]")

    def test_os_release_is_not_executed(self):
        (self.root / "os-release").write_text(f'ID="$(touch {self.root}/executed)"\nVERSION_ID="3.0"\n')
        self.shell("s4_platform", expected=78)
        self.assertFalse((self.root / "executed").exists())

    def test_container_and_unsupported_architecture_refused(self):
        (self.root / "os-release").write_text("ID=azurelinux\nVERSION_ID=3.0\n")
        self.shell("S4_SYSTEMD_RUNTIME=$S4_RUN/not-systemd; s4_platform", expected=78)
        self.shell("uname() { printf 'armv7l\\n'; }; s4_platform", expected=78)

    def test_atomic_write_is_private_and_idempotent(self):
        self.shell("printf 'content\\n' | s4_atomic_write \"$S4_STATE/record\" 0600")
        path = self.root / "state/record"
        original = path.stat().st_mtime_ns
        self.shell("printf 'content\\n' | s4_atomic_write \"$S4_STATE/record\" 0600")
        self.assertEqual(path.stat().st_mtime_ns, original)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_symlink_file_and_directory_are_rejected(self):
        target = self.root / "target"
        target.write_text("must remain unchanged")
        (self.root / "state/link").symlink_to(target)
        self.shell("printf changed | s4_atomic_write \"$S4_STATE/link\" 0600", expected=78)
        self.assertEqual(target.read_text(), "must remain unchanged")
        (self.root / "state/linkdir").symlink_to(self.root / "run", target_is_directory=True)
        self.shell("printf changed | s4_atomic_write \"$S4_STATE/linkdir/new\" 0600", expected=78)
        self.assertFalse((self.root / "run/new").exists())

    def test_writable_ancestor_and_destination_are_rejected(self):
        writable = self.root / "state/writable"
        writable.mkdir(mode=0o777)
        writable.chmod(0o777)
        self.shell("printf bad | s4_atomic_write \"$S4_STATE/writable/new\" 0600", expected=78)
        file = self.root / "state/record"
        file.write_text("unchanged")
        file.chmod(0o666)
        self.shell("printf bad | s4_atomic_write \"$S4_STATE/record\" 0600", expected=78)
        self.assertEqual(file.read_text(), "unchanged")

    def test_rename_failure_preserves_old_record(self):
        path = self.root / "state/record"
        path.write_text("old")
        path.chmod(0o600)
        self.shell("mv() { return 1; }; printf new | s4_atomic_write \"$S4_STATE/record\" 0600", expected=1)
        self.assertEqual(path.read_text(), "old")
        self.assertEqual(list(path.parent.glob("record.*")), [])

    def test_state_is_not_sourced_and_corrupt_integers_reset(self):
        (self.root / "state/components/bootstrap").write_text(
            'attempts=$(touch "$S4_RUN/executed")\nnext_attempt=99999999999999999999999999\n'
        )
        result = self.shell("s4_state_value bootstrap attempts; s4_state_value bootstrap next_attempt")
        self.assertEqual(result.stdout, "0\n0\n")
        self.assertFalse((self.root / "run/executed").exists())

    def test_first_failure_persists_pending_and_backoff(self):
        self.shell("s4_verify_bootstrap() { return 1; }; s4_run_component() { return 28; }; s4_reconcile_component bootstrap yes", expected=75)
        state = self.state()
        self.assertEqual(state["status"], "pending")
        self.assertEqual(state["last_exit"], "28")
        self.assertEqual(state["attempts"], "1")
        self.assertIn(int(state["next_attempt"]), range(1000060, 1000091))

    def test_backoff_prevents_unnecessary_retry(self):
        (self.root / "state/components/bootstrap").write_text("attempts=2\nnext_attempt=1000300\n")
        self.shell("s4_verify_bootstrap() { return 1; }; s4_run_component() { touch \"$S4_RUN/executed\"; }; s4_reconcile_component bootstrap no", expected=75)
        self.assertFalse((self.root / "run/executed").exists())

    def test_corrupt_attempt_count_cannot_overflow_backoff(self):
        (self.root / "state/components/bootstrap").write_text("attempts=9999999999\nnext_attempt=0\n")
        self.shell("s4_verify_bootstrap() { return 1; }; s4_run_component() { return 1; }; s4_reconcile_component bootstrap yes", expected=75)
        state = self.state()
        self.assertEqual(state["attempts"], "11")
        self.assertIn(int(state["next_attempt"]), range(1003600, 1003631))

    def test_backwards_clock_does_not_strand_work(self):
        (self.root / "state/components/bootstrap").write_text("attempts=1\nnext_attempt=2000000000\n")
        self.shell("s4_verify_bootstrap() { return 1; }; s4_run_component() { touch \"$S4_RUN/executed\"; return 1; }; s4_reconcile_component bootstrap no", expected=75)
        self.assertTrue((self.root / "run/executed").exists())

    def test_success_requires_postcondition(self):
        self.shell("s4_verify_bootstrap() { return 1; }; s4_run_component() { return 0; }; s4_reconcile_component bootstrap yes", expected=75)
        self.assertEqual(self.state()["status"], "pending")

    def test_stale_success_marker_is_repaired(self):
        (self.root / "state/components/bootstrap").write_text("status=complete\nattempts=0\nnext_attempt=0\n")
        self.shell("s4_verify_bootstrap() { return 1; }; s4_run_component() { return 5; }; s4_reconcile_component bootstrap no", expected=75)
        self.assertEqual(self.state()["status"], "pending")

    def test_verified_success_disables_only_repair_timer(self):
        self.shell('s4_verify_bootstrap() { return 0; }; s4_repair no')
        self.assertEqual(self.state()["status"], "complete")
        events = (self.root / "events").read_text()
        self.assertIn("disable --now azurelinux3s4-repair.timer", events)
        self.assertFalse((self.root / "run/timer-enabled").exists())
        self.assertEqual((self.root / "state/finalization").read_text(), "status=complete\n")

    def test_failure_keeps_repair_timer_enabled(self):
        self.shell("s4_verify_bootstrap() { return 1; }; s4_run_component() { return 1; }; s4_repair yes", expected=75)
        self.assertTrue((self.root / "run/timer-enabled").exists())
        self.assertNotIn("disable", (self.root / "events").read_text())

    def test_timer_stop_is_verified(self):
        self.shell('s4_verify_bootstrap() { return 0; }; export S4_ACTIVE_STATE=active; s4_repair no', expected=75)

    def test_timer_query_error_preserves_pending_boot_retry(self):
        result = self.shell('s4_verify_bootstrap() { return 0; }; export S4_QUERY_FAILURE=42; s4_repair no', expected=75)
        self.assertNotIn("its repair timer has stopped", result.stderr)
        self.assertEqual((self.root / "state/finalization").read_text(), "status=pending\n")
        self.assertEqual((self.root / "units/timers.target.wants/azurelinux3s4-repair.timer").resolve(),
                         self.root / "units/azurelinux3s4-repair.timer")

    def test_timer_persistent_and_runtime_states_are_distinct(self):
        for state in ("enabled", "enabled-runtime", "masked", "not-found", "static"):
            with self.subTest(state=state):
                result = self.shell('s4_verify_bootstrap() { return 0; }; export S4_FILE_STATE='
                                    + shlex.quote(state) + '; s4_repair no', expected=75)
                self.assertNotIn("its repair timer has stopped", result.stderr)
        self.shell('export S4_FILE_STATE=disabled S4_ACTIVE_STATE=active; s4_timer_state disabled inactive', expected=1)
        self.shell('export S4_FILE_STATE=enabled-runtime S4_ACTIVE_STATE=active; s4_timer_state enabled active', expected=1)

    def test_partial_disable_failure_restores_verified_retry(self):
        self.shell('s4_verify_bootstrap() { return 0; }; export S4_DISABLE_FAILURE=42; s4_repair no', expected=75)
        self.shell('s4_timer_state enabled active')
        self.assertEqual((self.root / "state/finalization").read_text(), "status=pending\n")
        self.assertTrue((self.root / "units/timers.target.wants/azurelinux3s4-repair.timer").is_symlink())

    def test_manager_activation_failure_retains_checked_boot_link(self):
        self.shell('s4_verify_bootstrap() { return 0; }; export S4_QUERY_FAILURE=42 S4_ENABLE_FAILURE=43; s4_repair no', expected=75)
        self.assertTrue((self.root / "units/timers.target.wants/azurelinux3s4-repair.timer").is_symlink())
        self.assertEqual((self.root / "state/finalization").read_text(), "status=pending\n")

    def test_retry_link_does_not_replace_foreign_objects(self):
        directory = self.root / "units/timers.target.wants"
        directory.mkdir()
        link = directory / "azurelinux3s4-repair.timer"
        link.write_text("operator object")
        self.shell('s4_start_repair_timer', expected=78)
        self.assertEqual(link.read_text(), "operator object")
        link.unlink()
        link.symlink_to(self.root / "rpm-key")
        self.shell('s4_start_repair_timer', expected=78)
        self.assertEqual(link.readlink(), self.root / "rpm-key")

    def test_finalization_write_failure_restores_retry(self):
        self.shell('s4_atomic_write() { return 42; }; s4_finish_repair', expected=75)
        self.shell('s4_timer_state enabled active')

    def test_completion_write_failure_restores_retry_and_keeps_pending(self):
        self.shell('''s4_atomic_write() {
            if [[ -f $S4_STATE/finalization ]]; then return 42; fi
            command cat >"$1"
        }; s4_finish_repair''', expected=75)
        self.assertEqual((self.root / "state/finalization").read_text(), "status=pending\n")
        self.shell('s4_timer_state enabled active')

    def test_failed_retry_link_barriers_never_certify_visible_boot_recovery(self):
        self.durability_model()
        result = self.shell('''systemctl disable --now "$S4_REPAIR_TIMER"
            sync -f -- "$S4_SYSTEMD_DIR"
            export S4_SYNC_FAIL_WANTS=1 S4_ENABLE_FAILURE=43 S4_QUERY_FAILURE=42
            s4_restore_repair_timer''')
        self.assertTrue((self.root / "units/timers.target.wants/azurelinux3s4-repair.timer").is_symlink())
        self.assertFalse((self.root / "run/timer-active").exists())
        barriers = [json.loads(line) for line in (self.root / "barriers").read_text().splitlines()]
        failures = [item for item in barriers if not item["ok"]]
        self.assertEqual(len(failures), 2)  # creation and the existing-link fallback
        for item in failures:
            self.assertIn(str(self.root / "units/timers.target.wants"), item["args"])
            self.assertIn(str(self.root / "units"), item["args"])
        self.assertNotIn("Boot retry activation is verified", result.stderr)
        self.assertIn("could not be preserved", result.stderr)
        self.assertEqual(self.adverse_reboot(), [])  # unflushed visible link is lost

    def test_existing_link_recovery_requires_a_successful_new_barrier(self):
        self.durability_model()
        result = self.shell('''systemctl disable --now "$S4_REPAIR_TIMER"
            sync -f -- "$S4_SYSTEMD_DIR"
            export S4_SYNC_FAIL_ONCE=1 S4_ENABLE_FAILURE=43
            s4_restore_repair_timer''')
        self.assertIn("Boot retry activation is verified", result.stderr)
        barriers = [json.loads(line) for line in (self.root / "barriers").read_text().splitlines()]
        self.assertEqual([item["ok"] for item in barriers[-2:]], [False, True])
        self.assertIn("azurelinux3s4-repair.timer", self.adverse_reboot())
        self.resume_boot_worker()

    def test_enablement_parent_barrier_failure_is_not_recovery_proof(self):
        self.durability_model()
        result = self.shell('''systemctl disable --now "$S4_REPAIR_TIMER"
            sync -f -- "$S4_SYSTEMD_DIR"
            export S4_SYNC_FAIL_PARENT=1
            s4_restore_repair_timer''')
        self.assertNotIn("Boot retry activation is verified", result.stderr)
        self.assertEqual(self.adverse_reboot(), [])

    def test_matching_completion_content_still_requires_persistence(self):
        self.durability_model()
        self.shell("printf 'status=pending\\n' | s4_atomic_write \"$S4_STATE/finalization\" 0600")
        self.shell("export S4_SYNC_FAIL_COMPLETION=1; printf 'status=complete\\n' | s4_atomic_write \"$S4_STATE/finalization\" 0600",
                   expected=42)
        inode = (self.root / "state/finalization").stat().st_ino
        self.shell("export S4_SYNC_FAIL_COMPLETION=1; printf 'status=complete\\n' | s4_atomic_write \"$S4_STATE/finalization\" 0600",
                   expected=42)
        self.assertEqual((self.root / "state/finalization").stat().st_ino, inode)
        self.assertIn("azurelinux3s4-repair.timer", self.adverse_reboot())
        self.assertEqual((self.root / "state/finalization").read_text(), "status=pending\n")
        self.resume_boot_worker()

    def test_independent_recovery_must_be_observed_before_primary_disable(self):
        for setting in ("S4_RECOVERY_ENABLE_FAILURE=43", "S4_RECOVERY_QUERY_FAILURE=42",
                        "S4_RECOVERY_FILE_STATE=enabled-runtime", "S4_RECOVERY_ACTIVE_STATE=inactive"):
            with self.subTest(setting=setting):
                (self.root / "events").unlink(missing_ok=True)
                result = self.shell("export " + setting + "; s4_finish_repair", expected=75)
                self.assertIn("Independent finalization recovery could not be verified", result.stderr)
                self.assertNotIn("disable", (self.root / "events").read_text())
                self.assertEqual((self.root / "state/finalization").read_text(), "status=pending\n")
                self.shell("s4_timer_state enabled active")

    def test_recovery_payload_persistence_failure_keeps_original_boot_activator(self):
        self.durability_model()
        (self.root / "events").unlink()
        self.shell("export S4_SYNC_FAIL_RUNNER=1; s4_finish_repair", expected=75)
        self.assertNotIn("disable", (self.root / "events").read_text())
        self.assertIn("azurelinux3s4-repair.timer", self.adverse_reboot())
        self.resume_boot_worker()

    def test_foreign_recovery_link_is_preserved_before_primary_disable(self):
        self.shell("s4_start_repair_timer")
        link = self.root / "units/timers.target.wants/azurelinux3s4-finalization-recovery.timer"
        link.symlink_to(self.root / "rpm-key")
        self.shell("s4_finish_repair", expected=75)
        self.assertEqual(link.readlink(), self.root / "rpm-key")
        self.assertNotIn("disable", (self.root / "events").read_text())
        self.shell("s4_timer_state enabled active")

    def test_interruptions_around_disable_and_observation_recover_at_boot(self):
        wrappers = {
            "before-disable": '''saved=$(declare -f s4_stop_timer); eval "${saved/s4_stop_timer/original_stop_timer}"
                s4_stop_timer() { [[ $1 != "$S4_REPAIR_TIMER" ]] || exit 99; original_stop_timer "$@"; }''',
            "after-disable-before-observation": '''saved=$(declare -f s4_timer_state); eval "${saved/s4_timer_state/original_timer_state}"
                s4_timer_state() { if [[ $1 == disabled && $3 == "$S4_REPAIR_TIMER" ]]; then exit 99; fi; original_timer_state "$@"; }''',
            "after-observation-before-persistence": '''saved=$(declare -f s4_timer_state); eval "${saved/s4_timer_state/original_timer_state}"
                s4_timer_state() { original_timer_state "$@" || return $?; if [[ $1 == disabled && $3 == "$S4_REPAIR_TIMER" ]]; then exit 99; fi; }''',
            "after-durable-disable": '''saved=$(declare -f s4_stop_timer); eval "${saved/s4_stop_timer/original_stop_timer}"
                s4_stop_timer() { original_stop_timer "$@" || return $?; [[ $1 != "$S4_REPAIR_TIMER" ]] || exit 99; }''',
        }
        for checkpoint, wrapper in wrappers.items():
            with self.subTest(checkpoint=checkpoint):
                self.durability_model()
                self.shell(wrapper + "\ns4_finish_repair", expected=99)
                self.assertEqual((self.root / "state/finalization").read_text(), "status=pending\n")
                self.assertTrue((self.root / "run/recovery-active").exists())
                self.assertIn("azurelinux3s4-finalization-recovery.timer", self.adverse_reboot())
                self.assertEqual((self.root / "state/finalization").read_text(), "status=pending\n")
                self.resume_boot_worker()

    def test_process_kill_around_completion_rename_preserves_pending_recovery(self):
        self.command("mv", r'''
import os
from pathlib import Path
import signal
import subprocess
import sys
source, destination = Path(sys.argv[-2]), Path(sys.argv[-1])
completion = destination.name == "finalization" and source.read_text() == "status=complete\n"
if completion and os.environ.get("S4_KILL_CHECKPOINT") == "before-rename":
    os.kill(int(os.environ["S4_WORKER_PID"]), signal.SIGKILL); sys.exit(99)
result = subprocess.run(["/usr/bin/mv", *sys.argv[1:]])
if completion and os.environ.get("S4_KILL_CHECKPOINT") == "after-rename":
    os.kill(int(os.environ["S4_WORKER_PID"]), signal.SIGKILL); sys.exit(99)
sys.exit(result.returncode)
''')
        for checkpoint in ("before-rename", "after-rename"):
            with self.subTest(checkpoint=checkpoint):
                self.durability_model()
                self.shell("export S4_WORKER_PID=$BASHPID S4_KILL_CHECKPOINT=" + checkpoint + "; s4_finish_repair", expected=-9)
                self.assertIn("azurelinux3s4-finalization-recovery.timer", self.adverse_reboot())
                self.assertEqual((self.root / "state/finalization").read_text(), "status=pending\n")
                self.resume_boot_worker()

    def test_failed_completion_barrier_keeps_recovery_across_reboot(self):
        self.durability_model()
        self.shell("export S4_SYNC_FAIL_COMPLETION=1; s4_finish_repair", expected=75)
        self.assertEqual((self.root / "state/finalization").read_text(), "status=complete\n")  # visible only
        self.assertIn("azurelinux3s4-finalization-recovery.timer", self.adverse_reboot())
        self.assertEqual((self.root / "state/finalization").read_text(), "status=pending\n")
        self.resume_boot_worker()

    def test_interruptions_during_restoration_retain_independent_recovery(self):
        for stage in ("before", "after"):
            with self.subTest(stage=stage):
                self.durability_model()
                prefix = "saved=$(declare -f s4_restore_repair_timer); eval \"${saved/s4_restore_repair_timer/original_restore}\"\n"
                body = 'original_restore "$@"; exit 99' if stage == "after" else "exit 99"
                self.shell(prefix + "s4_restore_repair_timer() { " + body + "; }; export S4_PRIMARY_QUERY_FAILURE=42; s4_finish_repair",
                           expected=99)
                self.assertIn("azurelinux3s4-finalization-recovery.timer", self.adverse_reboot())
                self.assertEqual((self.root / "state/finalization").read_text(), "status=pending\n")
                self.resume_boot_worker()

    def test_durable_completion_precedes_recovery_retirement(self):
        for stage in ("before-retirement", "after-retirement-rollback", "after-retirement-persist"):
            with self.subTest(stage=stage):
                self.durability_model()
                if stage == "before-retirement":
                    wrapper = '''saved=$(declare -f s4_stop_timer); eval "${saved/s4_stop_timer/original_stop_timer}"
                        s4_stop_timer() { [[ $1 != "$S4_RECOVERY_TIMER" ]] || exit 99; original_stop_timer "$@"; }'''
                else:
                    wrapper = '''saved=$(declare -f s4_timer_state); eval "${saved/s4_timer_state/original_timer_state}"
                        s4_timer_state() { if [[ $1 == disabled && $3 == "$S4_RECOVERY_TIMER" ]]; then exit 99; fi; original_timer_state "$@"; }'''
                self.shell(wrapper + "\ns4_finish_repair", expected=99)
                activators = self.adverse_reboot(persist_visible_unit_deletions=stage == "after-retirement-persist")
                self.assertEqual((self.root / "state/finalization").read_text(), "status=complete\n")
                if stage == "after-retirement-persist":
                    self.assertEqual(activators, [])  # all work was durably committed first
                else:
                    self.assertIn("azurelinux3s4-finalization-recovery.timer", activators)
                    self.resume_boot_worker()

    def test_recovery_cleanup_query_error_preserves_completion_and_boot_cleanup(self):
        self.durability_model()
        result = self.shell('''saved=$(declare -f s4_timer_state); eval "${saved/s4_timer_state/original_timer_state}"
            s4_timer_state() { if [[ $1 == disabled && $3 == "$S4_RECOVERY_TIMER" ]]; then return 42; fi; original_timer_state "$@"; }
            s4_finish_repair''', expected=75)
        self.assertIn("Completion is durable", result.stderr)
        self.assertNotIn("its repair timer has stopped", result.stderr)
        self.assertIn("azurelinux3s4-finalization-recovery.timer", self.adverse_reboot())
        self.assertEqual((self.root / "state/finalization").read_text(), "status=complete\n")
        self.resume_boot_worker()

    def test_stopping_last_timer_accepts_removed_empty_wants_directory(self):
        self.shell('s4_install_units; systemctl disable --now "$S4_UPDATE_TIMER"; export S4_REMOVE_EMPTY_WANTS=1; s4_finish_repair')
        self.assertFalse((self.root / "units/timers.target.wants").exists())
        self.assertEqual((self.root / "state/finalization").read_text(), "status=complete\n")

    def test_stop_refuses_foreign_link_without_removing_operator_object(self):
        self.shell("s4_start_repair_timer")
        link = self.root / "units/timers.target.wants/azurelinux3s4-repair.timer"
        link.unlink()
        link.symlink_to(self.root / "rpm-key")
        self.shell('s4_stop_timer "$S4_REPAIR_TIMER"', expected=78)
        self.assertEqual(link.readlink(), self.root / "rpm-key")
        self.assertNotIn("disable", (self.root / "events").read_text())

    def test_empty_malformed_and_unloaded_timer_observations_fail(self):
        self.command("systemctl", "import sys\nsys.exit(0)\n")
        self.shell('s4_timer_state disabled inactive', expected=1)
        self.command("systemctl", 'print("LoadState=loaded=bad\\nUnitFileState=disabled\\nActiveState=inactive")\n')
        self.shell('s4_timer_state disabled inactive', expected=1)
        self.command("systemctl", 'print("LoadState=not-found\\nUnitFileState=disabled\\nActiveState=inactive")\n')
        self.shell('s4_timer_state disabled inactive', expected=1)

    def test_bootstrap_checks_each_package_and_executable(self):
        self.shell('rpm() { [[ $2 != python3 ]]; }; s4_verify_bootstrap', expected=1)
        self.shell('s4_verify_bootstrap')

    def test_installed_packages_with_broken_ca_are_not_complete(self):
        (self.root / 'ca-bundle').write_text('not a certificate bundle\n')
        self.shell('rpm() { return 0; }; s4_verify_bootstrap', expected=1)

    def test_installed_but_disabled_metadata_verifier_is_not_complete(self):
        self.plugin_config.write_text('[main]\nenabled=0\n')
        self.shell('rpm() { return 0; }; s4_verify_bootstrap', expected=1)
        self.shell('s4_activate_verifier; s4_verify_bootstrap')

    def test_misleading_plugin_section_is_not_accepted(self):
        self.plugin_config.write_text('[unrelated]\nenabled=1\n[main]\nenabled=0\n')
        self.shell('rpm() { return 0; }; s4_verify_bootstrap', expected=1)

    def test_corrupt_registered_verifier_is_pending(self):
        self.plugin.write_text("not an ELF shared library\n")
        result = self.shell("s4_verifier_damage")
        self.assertIn("tdnf-plugin-repogpgcheck", result.stdout)
        self.shell("s4_verify_bootstrap", expected=1)
        self.shell('s4_run_component() { return 42; }; s4_repair yes', expected=75)
        self.assertEqual(self.state()["status"], "pending")
        self.assertTrue((self.root / "run/timer-enabled").exists())

    def test_native_probe_rejects_unloadable_library_even_with_integrity_standin(self):
        self.plugin.write_text("not an ELF shared library\n")
        self.shell("s4_verifier_damage() { return 0; }; s4_verify_metadata", expected=1)

    def test_native_probe_rejects_missing_interface_symbol(self):
        subprocess.run(["cc", "-shared", "-fPIC", "-x", "c", "-", "-o", str(self.plugin)],
                       input="void unrelated_symbol(void) {}\n", text=True, check=True, capture_output=True)
        self.shell("s4_verifier_damage() { return 0; }; s4_verify_metadata", expected=1)

    def test_damaged_or_missing_runtime_dependency_is_not_healthy(self):
        self.plugin_dependency.write_text("corrupted dependency\n")
        result = self.shell("s4_verifier_damage")
        self.assertIn("plugin-dependency", result.stdout)
        self.shell("s4_verify_metadata", expected=1)
        self.plugin_dependency.unlink()
        self.shell("s4_verifier_damage() { return 0; }; s4_verify_metadata", expected=1)

    def test_native_participation_requires_control_and_signature_rejection(self):
        for mode in ("bypass", "load-only", "engine-error"):
            with self.subTest(mode=mode):
                self.shell("export S4_TDNF_MODE=" + shlex.quote(mode) + "; s4_probe_verifier", expected=1)
        self.shell("export S4_CONTROL_FAILURE=42; s4_probe_verifier", expected=1)

    def test_probe_uses_private_gpg_home_and_removes_its_fixture(self):
        home = self.root / "operator-keyring"
        home.mkdir(mode=0o700)
        config = home / "gpg.conf"
        config.write_text("operator configuration must remain unchanged\n")
        self.shell("export GNUPGHOME=" + shlex.quote(str(home)) + "; s4_probe_verifier")
        self.assertEqual(config.read_text(), "operator configuration must remain unchanged\n")
        self.assertEqual(list((self.root / "run").glob("verifier.*")), [])

    def test_verifier_probe_is_bounded_when_native_process_hangs(self):
        self.shell("export S4_TDNF_MODE=hang; timeout() { shift 2; command timeout --kill-after=1s 1s \"$@\"; }; s4_probe_verifier",
                   expected=124, timeout=5)

    def test_integrity_query_errors_do_not_certify_empty_damage(self):
        self.command("rpm", "import sys\nsys.exit(42)\n")
        self.shell("s4_verify_metadata", expected=1)

    def test_only_omitted_documentation_is_excluded_from_payload_integrity(self):
        self.database["verification"]["plugin-dependency"] = {"exit": 1, "stdout": "missing     d /usr/share/doc/fixture/info\n"}
        self.database["manifest"] = {"plugin-dependency": [("/usr/share/doc/fixture/info", stat.S_IFREG | 0o644, 2)]}
        self.write_database()
        self.assertEqual(self.shell("s4_verifier_damage").stdout, "")
        self.database["verification"]["plugin-dependency"]["stdout"] += "..5......   /usr/lib64/libfixturedependency.so\n"
        self.write_database()
        self.assertIn("plugin-dependency", self.shell("s4_verifier_damage").stdout)

    def test_mutable_state_is_excluded_using_the_rpm_manifest(self):
        self.database["manifest"] = {"tdnf": [("/var/cache/tdnf", stat.S_IFDIR | 0o755, 0),
                                               ("/var/log/fixture", stat.S_IFREG | 0o600, 0)]}
        self.database["verification"]["tdnf"] = {"exit": 1, "stdout": "missing     /var/cache/tdnf\nSM5......   /var/log/fixture\n"}
        self.write_database()
        self.assertEqual(self.shell("s4_verifier_damage").stdout, "")
        self.database["verification"]["tdnf"]["stdout"] += "verification could not be completed\n"
        self.write_database()
        self.assertIn("tdnf", self.shell("s4_verifier_damage").stdout)

    def test_normal_transactions_refuse_unverified_metadata(self):
        self.shell('s4_verify_metadata() { return 1; }; s4_tdnf makecache', expected=75)

    def test_recovery_transaction_does_not_load_damaged_plugins(self):
        result = self.shell('timeout() { printf "%s\\n" "$*"; if read -r line; then return 9; fi; }; s4_tdnf_recovery reinstall tdnf-plugin-repogpgcheck')
        self.assertIn("--noplugins reinstall tdnf-plugin-repogpgcheck", result.stdout)
        self.assertNotIn("--enableplugin", result.stdout)

    def test_registered_broken_payloads_are_reinstalled_then_reverified(self):
        for path in (self.plugin, self.plugin_dependency):
            shutil.copyfile(path, self.root / ("trusted-" + path.name))
            path.write_text("damaged registered payload\n")
        self.shell('''s4_tdnf_recovery() {
            printf '%s\\n' "$*" >> "$S4_FIXTURE_ROOT/transactions"
            [[ $1 == reinstall ]] || return 99
            cp "$S4_FIXTURE_ROOT/trusted-libtdnfrepogpgcheck.so" "$S4_PLUGIN_LIBRARY"
            cp "$S4_FIXTURE_ROOT/trusted-libfixturedependency.so" "$(dirname "$S4_PLUGIN_LIBRARY")/libfixturedependency.so"
        }; s4_apply_bootstrap''')
        self.assertEqual((self.root / "transactions").read_text(),
                         "reinstall plugin-dependency tdnf-plugin-repogpgcheck\n")
        self.shell("s4_verify_metadata")

    def test_failed_payload_reinstall_keeps_verified_retry_active(self):
        self.plugin.write_text("damaged registered library\n")
        self.shell('s4_tdnf_recovery() { return 42; }; s4_run_component() { s4_apply_bootstrap; }; s4_repair yes', expected=75)
        self.assertEqual(self.state()["status"], "pending")
        self.assertEqual(self.state()["last_exit"], "42")
        self.shell("s4_timer_state enabled active")

    def test_failed_trust_rebuild_blocks_network_transaction(self):
        self.shell('update-ca-trust() { return 42; }; s4_tdnf() { touch "$S4_RUN/executed"; }; s4_apply_bootstrap', expected=42)
        self.assertFalse((self.root / 'run/executed').exists())

    def test_transactions_have_timeout_refresh_and_no_stdin(self):
        result = self.shell('s4_repositories; s4_verify_metadata() { return 0; }; timeout() { printf "%s\\n" "$*"; command timeout "$@"; }; s4_tdnf makecache')
        self.assertIn("--kill-after=30s 5m python3 -I -", result.stdout)
        transaction = json.loads((self.root / "native-transactions").read_text())
        self.assertIn("--releasever=3.0 --refresh -y --disableplugin=* --enableplugin=tdnfrepogpgcheck makecache",
                      " ".join(transaction["args"]))
        self.assertEqual(transaction["stdin"], "")

    def test_metadata_transaction_imports_only_pinned_vendor_into_private_home(self):
        operator = self.root / "operator-keyring"
        operator.mkdir(mode=0o700)
        (operator / "gpg.conf").write_text("operator configuration must remain unchanged\n")
        self.shell("s4_repositories; export GNUPGHOME=" + shlex.quote(str(operator))
                   + " GPG_AGENT_INFO=foreign-agent; s4_verify_repository_trust")
        transaction = json.loads((self.root / "native-transactions").read_text())
        self.assertNotEqual(transaction["home"], str(operator))
        self.assertFalse(Path(transaction["home"]).exists())
        self.assertEqual(list((self.root / "run").glob("transaction.*")), [])
        self.assertEqual((operator / "gpg.conf").read_text(), "operator configuration must remain unchanged\n")
        self.assertEqual(list(operator.iterdir()), [operator / "gpg.conf"])

    def test_changed_vendor_key_refuses_before_native_transaction(self):
        for data in (b"unknown key\n", (self.root / "rpm-key").read_bytes() + b"extra packets\n", b"x" * 65537):
            with self.subTest(size=len(data)):
                (self.root / "rpm-key").write_bytes(data)
                result = self.shell("s4_repositories; s4_verify_repository_trust", expected=75)
                self.assertIn("does not match the vetted keyblock", result.stderr)
                self.assertFalse((self.root / "native-transactions").exists())
                self.assertEqual(list((self.root / "run").glob("transaction.*")), [])

    def test_missing_vendor_key_is_deferred_without_native_transaction(self):
        (self.root / "rpm-key").unlink()
        self.shell("s4_verify_metadata() { return 0; }; s4_tdnf makecache", expected=75)
        self.assertFalse((self.root / "native-transactions").exists())

    def test_failed_vendor_import_blocks_native_transaction(self):
        self.command("gpg2", "import sys\nsys.exit(42)\n")
        result = self.shell("s4_repositories; s4_verify_repository_trust", expected=75)
        self.assertIn("could not be imported", result.stderr)
        self.assertFalse((self.root / "native-transactions").exists())
        self.assertEqual(list((self.root / "run").glob("transaction.*")), [])

    def test_private_keyring_identity_observation_must_be_exact(self):
        self.command("gpg2", r'''
import os
import subprocess
import sys
if "--list-keys" in sys.argv:
    print(os.environ["S4_KEY_OBSERVATION"])
    sys.exit(int(os.environ.get("S4_KEY_QUERY_FAILURE", "0")))
sys.exit(subprocess.run(["/usr/bin/gpg", *sys.argv[1:]]).returncode)
''')
        valid = "pub:-:2048:1:0CD9FED33135CE90:1584388724:::-:::scSC:\nfpr:::::::::2BC94FFF7015A5F28F1537AD0CD9FED33135CE90:"
        for observation in ("", "pub", valid.replace("2BC94FFF", "00000000"), valid + "\n" + valid,
                            valid.replace("pub:-", "pub:r"), valid.replace("pub:-", "pub:e"),
                            valid.replace("pub:-", "pub:d"), valid + "\nsec:::::::::::"):
            with self.subTest(observation=observation):
                self.shell("s4_repositories; export S4_KEY_OBSERVATION=" + shlex.quote(observation)
                           + "; s4_verify_repository_trust", expected=75)
                self.assertFalse((self.root / "native-transactions").exists())
        self.shell("s4_repositories; export S4_KEY_OBSERVATION=" + shlex.quote(valid)
                   + " S4_KEY_QUERY_FAILURE=42; s4_verify_repository_trust", expected=75)

    def test_actual_operation_without_native_loader_evidence_is_pending(self):
        self.command("tdnf", "print('Metadata cache created')\n")
        self.shell("s4_repositories; s4_verify_metadata() { return 0; }; s4_verify_repository_trust", expected=75)
        self.assertEqual(list((self.root / "run").glob("transaction.*")), [])

    def test_actual_operation_loader_error_does_not_certify_metadata(self):
        self.command("tdnf", "print('Loaded plugin: tdnfrepogpgcheck\\nError loading plugin')\n")
        self.shell("s4_repositories; s4_verify_metadata() { return 0; }; s4_verify_repository_trust", expected=75)

    def test_actual_operation_failure_propagates_and_cleans_keyring(self):
        self.shell("s4_repositories; export S4_NETWORK_FAILURE=28; s4_verify_repository_trust", expected=28)
        self.assertEqual(list((self.root / "run").glob("transaction.*")), [])

    def test_repository_trust_failure_keeps_repair_enabled_and_records_backoff(self):
        self.shell("S4_COMPONENTS=(bootstrap repository-trust); s4_verify_bootstrap() { return 0; }; export S4_NETWORK_FAILURE=28; s4_repair yes",
                   expected=75)
        record = dict(line.split("=", 1) for line in (self.root / "state/components/repository-trust").read_text().splitlines())
        self.assertEqual(record["status"], "pending")
        self.assertEqual(record["last_exit"], "28")
        self.assertIn(int(record["next_attempt"]), range(int(record["last_attempt"]) + 60, int(record["last_attempt"]) + 91))
        self.assertNotIn("disable", (self.root / "events").read_text())
        self.shell("s4_timer_state enabled active")

    def test_repository_trust_backoff_precedes_network_work(self):
        (self.root / "state/components/repository-trust").write_text("attempts=2\nnext_attempt=1000300\n")
        self.shell("s4_repositories; s4_reconcile_component repository-trust no", expected=75)
        self.assertFalse((self.root / "native-transactions").exists())

    def test_stale_repository_success_does_not_replace_signed_refresh(self):
        (self.root / "state/components/repository-trust").write_text("status=complete\nattempts=0\nnext_attempt=0\n")
        self.shell("s4_repositories; export S4_NETWORK_FAILURE=28; s4_reconcile_component repository-trust no", expected=75)
        self.assertIn("status=pending", (self.root / "state/components/repository-trust").read_text())
        self.assertEqual(len((self.root / "native-transactions").read_text().splitlines()), 1)

    def test_both_components_require_success_before_timer_finalization(self):
        self.shell("S4_COMPONENTS=(bootstrap repository-trust); s4_verify_bootstrap() { return 0; }; s4_repair yes")
        for component in ("bootstrap", "repository-trust"):
            self.assertIn("status=complete", (self.root / ("state/components/" + component)).read_text())
        self.assertEqual((self.root / "state/finalization").read_text(), "status=complete\n")
        self.shell("s4_timer_state disabled inactive; s4_timer_state disabled inactive \"$S4_RECOVERY_TIMER\"")

    def test_repository_refresh_deadline_is_shorter_than_package_transaction(self):
        result = self.shell('s4_repositories; s4_verify_metadata() { return 0; }; timeout() { printf "%s\\n" "$*"; command timeout "$@"; }; s4_verify_repository_trust')
        self.assertIn("--kill-after=30s 5m python3 -I -", result.stdout)

    def test_repo_component_status_preserves_incomplete_server_claim(self):
        result = self.shell("S4_COMPONENTS=(bootstrap repository-trust); s4_status")
        self.assertIn("implemented_components=bootstrap repository-trust", result.stdout)
        self.assertIn("[repository-trust]", result.stdout)
        self.assertIn("server_ready=no", result.stdout)

    def test_embedded_anchor_is_exact_reviewed_public_material(self):
        result = self.shell('s4_vendor_key_material')
        self.assertEqual(result.stdout.encode(), (SCRIPT.parent / 'tests/fixtures/azurelinux-rpm-key.asc').read_bytes())
        self.assertEqual(hashlib.sha256(result.stdout.encode()).hexdigest(),
                         '1092f37ec429e58bf9c7f898df17c3c32eb2ce3c4c037afb8ffe2d2b42e16e89')

    def test_missing_private_anchor_recovers_without_network_or_gnupg(self):
        (self.root / 'rpm-key').unlink()
        self.database['vendor_packets'] = []
        self.write_database()
        self.command('gpg2', 'raise SystemExit(99)\n')
        self.command('tdnf', 'raise SystemExit(99)\n')
        self.shell('s4_apply_trust_anchor; s4_verify_trust_anchor')
        self.assertEqual((self.root / 'rpm-key').read_bytes(), (SCRIPT.parent / 'tests/fixtures/azurelinux-rpm-key.asc').read_bytes())
        self.assertEqual((self.root / 'rpm-key').stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.root / 'rpm-imports').read_text().splitlines(), [str(self.root / 'rpm-key')])

    def test_damaged_private_anchor_recovers_and_preserves_distribution_key(self):
        original = self.root / 'distribution-key'
        original.write_text('operator distribution material remains untouched\n')
        (self.root / 'rpm-key').write_text('damaged private bytes\n')
        self.shell('s4_apply_trust_anchor; s4_verify_trust_anchor')
        self.assertEqual(original.read_text(), 'operator distribution material remains untouched\n')
        self.assertFalse((self.root / 'rpm-imports').exists())

    def test_corrupt_embedded_material_never_replaces_existing_anchor(self):
        prior = (self.root / 'rpm-key').read_bytes()
        self.shell("s4_vendor_key_material() { printf 'changed embedded bytes\\n'; }; s4_apply_trust_anchor", expected=75)
        self.assertEqual((self.root / 'rpm-key').read_bytes(), prior)
        self.assertFalse((self.root / 'rpm-imports').exists())

    def test_registered_anchor_is_idempotent_and_preserves_other_rpm_keys(self):
        self.database['foreign_keys'] = ['operator key']
        self.write_database()
        prior = (self.root / 'rpm-key').stat().st_mtime_ns
        self.shell('s4_apply_trust_anchor; s4_apply_trust_anchor')
        self.assertEqual((self.root / 'rpm-key').stat().st_mtime_ns, prior)
        self.assertFalse((self.root / 'rpm-imports').exists())
        self.assertEqual(json.loads((self.root / 'rpm-database.json').read_text())['foreign_keys'], ['operator key'])

    def test_rpm_admission_failure_and_zero_exit_noop_remain_pending(self):
        self.database['vendor_packets'] = []
        self.write_database()
        for setting in ('S4_RPM_IMPORT_ERROR=1', 'S4_RPM_IMPORT_NOOP=1'):
            with self.subTest(setting=setting):
                self.shell('export ' + setting + '; s4_apply_trust_anchor', expected=75)
                self.shell('s4_verify_trust_anchor', expected=1)

    def test_rpm_identity_requires_actual_complete_packets(self):
        encoded = self.database['vendor_packets'][0]
        for packets in ([], ['not base64'], [encoded, encoded], [base64.b64encode(b'wrong public packet').decode()],
                        [encoded[:-4]], ['x' * 2049]):
            with self.subTest(packets=packets):
                self.database['vendor_packets'] = packets
                self.write_database()
                self.shell('s4_rpm_vendor_key_matches', expected=1)
        self.database['vendor_packets'] = [encoded]
        self.write_database()
        self.shell('export S4_RPM_KEY_QUERY_ERROR=1; s4_rpm_vendor_key_matches', expected=1)

    def test_unsupported_or_unknown_rpm_observation_cannot_admit_trust(self):
        for setting in ('S4_RPM_KEYRING=fs', 'S4_RPM_KEYRING=unknown', 'S4_RPM_EVAL_ERROR=1',
                        'S4_RPM_DATABASE=relative', 'S4_RPM_DATABASE=' + str(self.root / 'absent-db')):
            with self.subTest(setting=setting):
                self.shell('export ' + setting + '; s4_apply_trust_anchor', expected=75)
                self.assertFalse((self.root / 'rpm-imports').exists())
        self.shell("export S4_RPM_KEYRING=''; s4_verify_trust_anchor")

    def test_database_alias_in_untrusted_parent_is_refused(self):
        directory = self.root / 'untrusted'
        directory.mkdir()
        directory.chmod(0o777)
        alias = directory / 'rpmdb'
        alias.symlink_to(self.root / 'rpmdb', target_is_directory=True)
        self.shell('export S4_RPM_DATABASE=' + shlex.quote(str(alias)) + '; s4_apply_trust_anchor', expected=75)
        self.assertTrue(alias.is_symlink())
        self.assertFalse((self.root / 'rpm-imports').exists())

    def test_anchor_wrong_kind_paths_refuse_without_open_or_removal(self):
        path = self.root / 'rpm-key'
        path.unlink()
        os.mkfifo(path, 0o600)
        inode = path.stat().st_ino
        self.shell('s4_apply_trust_anchor', expected=78, timeout=3)
        self.assertEqual(path.stat().st_ino, inode)
        path.unlink()
        path.mkdir(mode=0o700)
        inode = path.stat().st_ino
        self.shell('s4_apply_trust_anchor', expected=78)
        self.assertEqual(path.stat().st_ino, inode)
        path.rmdir()
        target = self.root / 'operator-key'
        target.write_text('unchanged')
        path.symlink_to(target)
        self.shell('s4_apply_trust_anchor', expected=78)
        self.assertEqual(target.read_text(), 'unchanged')
        path.unlink()
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(path))
            inode = path.stat().st_ino
            self.shell('s4_apply_trust_anchor', expected=78)
            self.assertEqual(path.stat().st_ino, inode)

    def test_anchor_barrier_failure_never_certifies_visible_admission(self):
        (self.root / 'rpm-key').unlink()
        self.database['vendor_packets'] = []
        self.write_database()
        failure = 'export S4_SYNC_ERROR_PATH=$S4_FIXTURE_ROOT/rpmdb; '
        self.shell(failure + 's4_apply_trust_anchor', expected=75)
        self.assertTrue((self.root / 'rpm-key').exists())
        self.shell(failure + 's4_apply_trust_anchor', expected=75)
        self.assertEqual(len((self.root / 'rpm-imports').read_text().splitlines()), 1)
        self.shell(failure + 's4_verify_trust_anchor', expected=1)
        self.shell('s4_verify_trust_anchor')

    def test_anchor_write_barrier_failure_prevents_rpm_import(self):
        (self.root / 'rpm-key').unlink()
        self.database['vendor_packets'] = []
        self.write_database()
        self.shell('sync() { return 42; }; s4_apply_trust_anchor', expected=1)
        self.assertFalse((self.root / 'rpm-imports').exists())

    def test_anchor_failure_blocks_bootstrap_and_online_refresh(self):
        self.database['vendor_packets'] = []
        self.write_database()
        self.shell('''S4_COMPONENTS=(trust-anchor bootstrap repository-trust)
            export S4_RPM_IMPORT_NOOP=1
            s4_run_component() { [[ $1 == trust-anchor ]] || return 99; s4_apply_trust_anchor; }
            s4_repair yes''', expected=75)
        record = dict(line.split('=', 1) for line in (self.root / 'state/components/trust-anchor').read_text().splitlines())
        self.assertEqual(record['status'], 'pending')
        self.assertEqual(record['last_exit'], '75')
        self.assertFalse((self.root / 'state/tdnf.conf').exists())
        self.assertFalse((self.root / 'native-transactions').exists())
        self.shell('s4_timer_state enabled active')

    def test_all_three_components_recover_key_before_online_completion(self):
        (self.root / 'rpm-key').unlink()
        self.database['vendor_packets'] = []
        self.write_database()
        self.shell('''S4_COMPONENTS=(trust-anchor bootstrap repository-trust)
            s4_verify_bootstrap() { return 0; }
            s4_run_component() { [[ $1 == trust-anchor ]] || return 99; s4_apply_trust_anchor; }
            s4_repair yes''')
        for component in ('trust-anchor', 'bootstrap', 'repository-trust'):
            self.assertIn('status=complete', (self.root / ('state/components/' + component)).read_text())
        self.shell('s4_timer_state disabled inactive; s4_timer_state disabled inactive "$S4_RECOVERY_TIMER"')

    def test_anchor_identity_query_is_bounded(self):
        self.command('rpm', 'import time\ntime.sleep(100)\n')
        self.shell('timeout() { shift 2; command timeout --kill-after=1s 1s "$@"; }; s4_rpm_vendor_key_matches', expected=1, timeout=3)

    def test_repository_policy_is_production_only(self):
        self.shell("s4_repositories")
        for name in ("base", "extended"):
            policy = (self.root / f"state/repos/{name}.repo").read_text()
            self.assertIn(f"https://packages.microsoft.com/azurelinux/3.0/prod/{name}/x86_64/", policy)
            for setting in ("gpgcheck=1", "repo_gpgcheck=1", "sslverify=1", "skip_if_unavailable=0"):
                self.assertIn(setting, policy)
            self.assertNotIn("preview", policy)
        self.assertIn("installonly_limit=3", (self.root / "state/tdnf.conf").read_text())

    def test_missing_trust_anchor_never_disables_signatures(self):
        (self.root / "rpm-key").unlink()
        self.shell("s4_repositories", expected=75)
        self.assertEqual(list((self.root / "state/repos").iterdir()), [])

    def test_missing_trust_anchor_records_pending_repair(self):
        (self.root / "rpm-key").unlink()
        self.shell("s4_repair yes", expected=75)
        self.assertEqual(self.state()["status"], "pending")
        self.assertEqual(self.state()["last_exit"], "75")
        self.assertTrue((self.root / "run/timer-enabled").exists())

    def test_failed_first_policy_write_does_not_continue(self):
        self.shell('s4_atomic_write() { printf "%s\\n" "$1"; return 29; }; s4_repositories', expected=29)
        self.assertFalse((self.root / "state/tdnf.conf").exists())

    def test_concurrent_operations_fail_without_blocking(self):
        self.shell("s4_lock; bash -c 'source \"$1\"; S4_RUN=$2; s4_lock' bash "
                   + shlex.quote(str(SCRIPT)) + " " + shlex.quote(str(self.root / "run")), expected=0)
        # The child inherited descriptor 9. An unrelated process must fail.
        lock = (self.root / "run/operation.lock").open("w")
        self.addCleanup(lock.close)
        import fcntl
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.shell("s4_lock", expected=75)

    def test_fifo_lock_refuses_promptly_without_changing_operator_object(self):
        path = self.root / "run/operation.lock"
        os.mkfifo(path, 0o600)
        inode = path.stat().st_ino
        self.shell("s4_lock", expected=78, timeout=2)
        self.assertEqual(path.stat().st_ino, inode)

    def test_socket_directory_and_symlink_locks_are_rejected(self):
        path = self.root / "run/operation.lock"
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(path))
            inode = path.stat().st_ino
            self.shell("s4_lock", expected=78, timeout=2)
            self.assertEqual(path.stat().st_ino, inode)
        path.unlink()
        path.mkdir(mode=0o700)
        self.shell("s4_lock", expected=78, timeout=2)
        path.rmdir()
        path.symlink_to(self.root / "rpm-key")
        self.shell("s4_lock", expected=78, timeout=2)
        self.assertEqual(path.readlink(), self.root / "rpm-key")

    def test_device_lock_objects_are_refused(self):
        self.shell("s4_lock_object /dev/null", expected=78, timeout=2)
        self.shell("s4_lock_object /dev/zero", expected=78, timeout=2)

    def test_inherited_lock_must_match_the_regular_file_inode(self):
        self.shell('s4_lock; stat() { if [[ $1 == -Lc ]]; then printf "wrong:inode\\n"; else command stat "$@"; fi; }; s4_lock',
                   expected=78)

    def test_unit_installation_failure_is_not_masked(self):
        self.shell('export S4_DAEMON_FAILURE=42; s4_install_units', expected=42)
        self.assertFalse((self.root / "run/timer-enabled").exists())

    def test_units_resume_at_boot_without_network_online_dependency(self):
        self.shell("s4_install_units")
        service = (self.root / "units/azurelinux3s4-repair.service").read_text()
        timer = (self.root / "units/azurelinux3s4-repair.timer").read_text()
        recovery = (self.root / "units/azurelinux3s4-finalization-recovery.timer").read_text()
        self.assertIn("KillMode=control-group", service)
        self.assertIn("TimeoutStartSec=45min", service)
        self.assertNotIn("network-online.target", service)
        self.assertIn("OnBootSec=2min", timer)
        self.assertIn("OnUnitInactiveSec=1min", timer)
        self.assertIn("RandomizedDelaySec=30s", timer)
        for setting in ("OnBootSec=1min", "OnActiveSec=1min", "OnUnitInactiveSec=1min",
                        "Unit=azurelinux3s4-repair.service", "WantedBy=timers.target"):
            self.assertIn(setting, recovery)
        self.assertNotIn("network-online.target", recovery)

    def test_periodic_update_preparation_survives_primary_finalization(self):
        self.shell("s4_install_units; s4_finish_repair")
        unit = self.root / "units/azurelinux3s4-update-preparation.timer"
        policy = unit.read_text()
        for setting in ("OnBootSec=3min", "OnCalendar=hourly", "Persistent=yes",
                        "RandomizedDelaySec=15min", "WantedBy=timers.target",
                        "Unit=azurelinux3s4-repair.service"):
            self.assertIn(setting, policy)
        self.shell('s4_timer_state enabled active "$S4_UPDATE_TIMER"')
        self.shell('s4_timer_state disabled inactive "$S4_REPAIR_TIMER"')
        self.shell('s4_timer_state disabled inactive "$S4_RECOVERY_TIMER"')
        link = self.root / "units/timers.target.wants" / unit.name
        self.assertEqual(link.resolve(), unit)

    def test_periodic_preparation_enablement_rejects_failed_observation(self):
        self.shell('s4_install_units; export S4_QUERY_FAILURE=42; s4_start_timer "$S4_UPDATE_TIMER"', expected=1)
        self.assertTrue((self.root / "units/timers.target.wants/azurelinux3s4-update-preparation.timer").is_symlink())

    def test_status_never_claims_full_hardening(self):
        self.shell("s4_verify_bootstrap() { return 0; }; s4_reconcile_component bootstrap yes")
        result = self.shell("s4_status")
        self.assertIn("server_ready=no", result.stdout)
        self.assertIn("network containment", result.stdout)


if __name__ == "__main__":
    unittest.main()

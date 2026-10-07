import hashlib
import errno
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "azurelinux3s4.sh"
SPEC = importlib.util.spec_from_file_location("web_policy", ROOT / "Web/policy.py")
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)
PROBE = ROOT / "Web.Tests/socket_probe.py"


def sections(content):
    result = {}
    current = None
    for line in content.splitlines():
        if line.startswith("["):
            current = line[1:-1]
            result[current] = {}
        elif line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result[current].setdefault(key, []).append(value)
    return result


class WebPolicyTests(unittest.TestCase):
    def invoke(self, *args, expected=0, **kwargs):
        result = subprocess.run([str(SCRIPT), "--web-isolation-policy", *args],
                                capture_output=True, timeout=10, **kwargs)
        self.assertEqual(result.returncode, expected, result.stderr)
        return result

    def test_standalone_cli_matches_source_bundle_with_checked_file_identities(self):
        result = json.loads(self.invoke().stdout)
        self.assertEqual(result, POLICY.bundle())
        for entry in result["files"]:
            data = entry["content"].encode()
            self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
            self.assertEqual(entry["bytes"], len(data))
            self.assertEqual(entry["mode"], "0644")
            self.assertFalse(entry["file"].startswith("/"))
            self.assertNotIn("..", entry["file"].split("/"))

    def test_emission_is_deterministic_and_cannot_borrow_environment_policy(self):
        baseline = self.invoke().stdout
        altered = self.invoke(cwd="/", env=dict(os.environ, S4_STATE="/operator/state",
            S4_WEB_ALLOW="AF_INET AF_INET6", PYTHONPATH="/operator/python", PYTHONSTARTUP="/operator/start",
            PYTHONHASHSEED="91", LC_ALL="C", TZ="Pacific/Fiji"))
        self.assertEqual(altered.stdout, baseline)

    def test_no_host_readiness_or_installation_authority_is_claimed(self):
        result = json.loads(self.invoke().stdout)
        self.assertTrue(result["authority"])
        self.assertTrue(all(value is False for value in result["authority"].values()))
        self.assertIn("inherited IP", " ".join(result["limits"]))
        self.assertIn("Independent proxy egress", " ".join(result["prerequisites"]))

    def test_backend_has_no_ip_listener_dns_upstream_or_dynamic_configuration(self):
        nginx = POLICY.files()["nginx/nginx.conf"]
        self.assertIn("listen unix:/run/azurelinux3s4-web/http.sock;", nginx)
        self.assertEqual(nginx.count("listen "), 1)
        for directive in ("include ", "load_module ", "resolver ", "proxy_pass ", "fastcgi_pass ", "user "):
            self.assertNotIn(directive, nginx)
        self.assertIn("disable_symlinks on;", nginx)
        self.assertIn("autoindex off;", nginx)

    def test_units_remove_capabilities_and_alternative_socket_abis(self):
        for name, content in POLICY.files().items():
            if not name.endswith(".service"):
                continue
            values = sections(content)["Service"]
            for key, expected in (("CapabilityBoundingSet", [""]), ("AmbientCapabilities", [""]),
                ("NoNewPrivileges", ["yes"]), ("PrivateNetwork", ["yes"]),
                ("RestrictAddressFamilies", ["AF_UNIX"]), ("SystemCallArchitectures", ["native"]),
                ("RestrictNamespaces", ["yes"]), ("ProtectSystem", ["strict"]), ("ProtectHome", ["yes"])):
                self.assertEqual(values[key], expected, name)
            self.assertEqual(values["DynamicUser"], ["yes"])
            self.assertNotIn("+", " ".join(values["ExecStart"]))
            self.assertNotIn("PermissionsStartOnly", values)

    def test_backend_denies_connect_and_io_uring_socket_bypasses(self):
        for name in ("systemd/azurelinux3s4-web-backend.service", "systemd/azurelinux3s4-web.service"):
            filters = " ".join(sections(POLICY.files()[name])["Service"]["SystemCallFilter"])
            for call in ("io_uring_setup", "io_uring_enter", "io_uring_register", "bpf"):
                self.assertIn(call, filters.split())
        backend = sections(POLICY.files()["systemd/azurelinux3s4-web-backend.service"])["Service"]
        self.assertIn("~connect", backend["SystemCallFilter"])

    def test_ingress_inherits_public_listeners_and_requires_backend(self):
        listener = sections(POLICY.files()["systemd/azurelinux3s4-web.socket"])["Socket"]
        self.assertEqual(listener["ListenStream"], ["0.0.0.0:80", "[::]:80"])
        self.assertEqual(listener["BindIPv6Only"], ["ipv6-only"])
        self.assertEqual(listener["Accept"], ["no"])
        self.assertNotIn("PrivateNetwork", listener)
        proxy = sections(POLICY.files()["systemd/azurelinux3s4-web.service"])
        self.assertIn("azurelinux3s4-web-backend.service", proxy["Unit"]["BindsTo"])
        self.assertIn("azurelinux3s4-web-backend.service", " ".join(proxy["Unit"]["After"]))
        self.assertEqual(proxy["Service"]["Type"], ["exec"])
        self.assertIn("/run/azurelinux3s4-web/http.sock", proxy["Service"]["ExecStart"][0])

    def test_shared_socket_parent_is_not_world_traversable_or_proxy_owned(self):
        backend = sections(POLICY.files()["systemd/azurelinux3s4-web-backend.service"])["Service"]
        proxy = sections(POLICY.files()["systemd/azurelinux3s4-web.service"])["Service"]
        self.assertEqual(backend["RuntimeDirectoryMode"], ["0750"])
        self.assertNotIn("RuntimeDirectory", proxy)
        self.assertNotEqual(backend["User"], proxy["User"])
        self.assertEqual(backend["Group"], proxy["Group"])
        self.assertEqual(POLICY.files()["sysusers/azurelinux3s4-web.conf"], "g azurelinux3s4-web -\n")
        self.assertEqual(proxy["TemporaryFileSystem"], ["/run:ro /var:ro"])
        self.assertEqual(proxy["BindReadOnlyPaths"], ["/run/azurelinux3s4-web"])

    def test_resource_limits_are_finite_and_independent_of_repair_budget(self):
        for name, content in POLICY.files().items():
            if name.endswith(".service"):
                values = sections(content)["Service"]
                self.assertEqual(values["TasksMax"], ["64"])
                self.assertEqual(values["MemoryMax"], ["256M"])
                self.assertEqual(values["TimeoutStartSec"], ["30s"])
                self.assertEqual(values["TimeoutStopSec"], ["30s"])
        result = subprocess.run(["bash", "-c", 'source "$1"; s4_repair_timeout_seconds', "fixture", str(SCRIPT)],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"22245\n")

    def test_policy_is_not_a_default_completion_component(self):
        result = subprocess.run(["bash", "-c", 'source "$1"; printf "%s\\n" "${S4_COMPONENTS[@]}"',
                                 "fixture", str(SCRIPT)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout.splitlines()), 9)
        self.assertNotIn(b"web", result.stdout)

    def test_cli_rejects_overrides_without_partial_output(self):
        for argument in ("--apply", "/operator/path", "AF_INET"):
            self.assertEqual(self.invoke(argument, expected=64).stdout, b"")
        result = subprocess.run([sys.executable, "-I", str(ROOT / "Web/policy.py"), "--apply"],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 75)
        self.assertEqual(result.stdout, b"")

    def test_cli_is_read_only_and_does_not_enter_host_preflight_or_repair(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "host-action"
            command = '''source "$1"
marker=$2
host_action() { touch -- "$marker"; return 99; }
s4_preflight() { host_action; }
s4_prepare_state() { host_action; }
s4_lock() { host_action; }
s4_repair() { host_action; }
s4_install_runner() { host_action; }
s4_install_units() { host_action; }
s4_main --web-isolation-policy'''
            result = subprocess.run(["bash", "-c", command, "fixture", str(SCRIPT), str(marker)],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())
            self.assertEqual(list(Path(temporary).iterdir()), [])

    def test_single_file_delivery_emits_policy_without_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            delivered = Path(temporary) / "azurelinux3s4.sh"
            shutil.copyfile(SCRIPT, delivered)
            delivered.chmod(0o755)
            result = subprocess.run([str(delivered), "--web-isolation-policy"], cwd="/",
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, self.invoke().stdout)
            self.assertEqual(list(Path(temporary).iterdir()), [delivered])


class NativeSocketProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="s4-web-", dir="/dev/shm")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = str(self.root / "backend.sock")
        self.backend = socket.socket(socket.AF_UNIX)
        self.addCleanup(self.backend.close)
        self.backend.bind(self.target)
        self.backend.listen(4)
        self.backend.settimeout(5)
        self.errors = []

    def backend_server(self, forwarding):
        try:
            with self.backend.accept()[0] as baseline:
                self.assertEqual(baseline.recv(4096), b"")
            if forwarding:
                with self.backend.accept()[0] as connection:
                    connection.settimeout(5)
                    self.assertEqual(connection.recv(4096), b"fixture request")
                    connection.sendall(b"fixture response")
        except BaseException as error:
            self.errors.append(error)

    def run_probe(self, mode, descriptor=-1, reconnect_port=0, forwarding=False):
        unit = "systemd/azurelinux3s4-web" + ("-backend" if mode == "backend" else "") + ".service"
        filters = sections(POLICY.files()[unit])["Service"]["SystemCallFilter"]
        # Explicit leaf rules come from the emitted policy. Systemd groups,
        # namespaces, mounts, users and capability handling are NOT exercised.
        calls = sorted({item.lstrip("~") for line in filters for item in line.split()
                        if not item.lstrip("~").startswith("@")})
        thread = threading.Thread(target=self.backend_server, args=(forwarding,))
        thread.start()
        self.addCleanup(thread.join, 6)
        command = [sys.executable, "-I", str(PROBE), mode, self.target, str(self.root / "listener.sock"),
                   str(descriptor), str(reconnect_port), json.dumps(calls)]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   pass_fds=() if descriptor < 0 else (descriptor,))
        self.addCleanup(self.stop, process)
        return process, thread

    @staticmethod
    def stop(process):
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)

    def finish(self, process, thread):
        stdout, stderr = process.communicate(timeout=10)
        thread.join(6)
        self.assertFalse(thread.is_alive())
        self.assertEqual(self.errors, [])
        self.assertEqual(process.returncode, 0, stderr.decode())
        result = json.loads(stdout)
        for family in ("new_inet", "new_inet6", "new_netlink", "new_packet"):
            self.assertEqual(result[family], errno.EAFNOSUPPORT)
        self.assertFalse(result["systemd_units_executed"])
        self.assertFalse(result["private_network_verified"])
        return result

    def test_native_backend_leaf_filter_allows_unix_response_and_refuses_new_connections(self):
        process, thread = self.run_probe("backend")
        deadline = time.monotonic() + 5
        while not (self.root / "listener.sock").exists() and process.poll() is None:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(5)
            client.connect(str(self.root / "listener.sock"))
            client.sendall(b"fixture request")
            self.assertEqual(client.recv(4096), b"fixture response")
        result = self.finish(process, thread)
        self.assertEqual(result["unix_connect"], errno.EPERM)
        self.assertTrue(result["unix_listener_response"])

    def test_native_proxy_forwards_inherited_tcp_but_cannot_claim_reconnect_isolation(self):
        with socket.socket(socket.AF_INET) as listener, socket.socket(socket.AF_INET) as reconnect:
            for stream in (listener, reconnect):
                stream.bind(("127.0.0.1", 0))
                stream.listen(1)
                stream.settimeout(5)
            process, thread = self.run_probe("proxy", listener.fileno(), reconnect.getsockname()[1], True)
            with socket.socket(socket.AF_INET) as client:
                client.settimeout(5)
                client.connect(listener.getsockname())
                client.sendall(b"fixture request")
                self.assertEqual(client.recv(4096), b"fixture response")
            with reconnect.accept()[0] as observed:
                observed.settimeout(5)
                self.assertEqual(observed.recv(4096), b"fixture reconnect")
                observed.sendall(b"fixture reconnect observed")
            result = self.finish(process, thread)
        self.assertEqual(result["recvmsg"], errno.EPERM)
        self.assertTrue(result["inherited_tcp_unix_forwarding"])
        self.assertTrue(result["inherited_tcp_reconnect_allowed"])
        self.assertFalse(POLICY.bundle()["authority"]["inherited_inet_sockets_restricted"])

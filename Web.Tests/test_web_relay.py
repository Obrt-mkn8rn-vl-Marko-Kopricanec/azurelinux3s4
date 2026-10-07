import hashlib
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

from test_web_isolation import POLICY, ROOT, sections


WORKER = ROOT / "Web/relay.py"
PROBE = ROOT / "Web.Tests/relay_probe.py"


class RelayPolicyTests(unittest.TestCase):
    def test_missing_assembly_payload_refuses_without_partial_candidate_output(self):
        result = subprocess.run([sys.executable, "-I", str(ROOT / "Web/policy.py")],
                                capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 75, result.stderr)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"assembled relay payload is required", result.stderr)

    def test_bundle_emits_exact_worker_bytes_and_connection_instance_protocol(self):
        result = subprocess.run([str(ROOT / "azurelinux3s4.sh"), "--web-isolation-policy"],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        entries = {entry["file"]: entry for entry in json.loads(result.stdout)["files"]}
        entry = entries["lib/web-relay.py"]
        self.assertEqual(entry["content"].encode(), WORKER.read_bytes())
        self.assertEqual(entry["sha256"], hashlib.sha256(WORKER.read_bytes()).hexdigest())
        unit = sections(entries["systemd/azurelinux3s4-web@.service"]["content"])
        proxy = unit["Service"]
        self.assertEqual(unit["Unit"]["CollectMode"], ["inactive-or-failed"])
        self.assertEqual(proxy["StandardInput"], ["socket"])
        self.assertEqual(proxy["Restart"][-1], "no")
        self.assertEqual(proxy["RuntimeMaxSec"], ["390s"])
        self.assertEqual(proxy["ExecStart"], ["/usr/bin/python3 -I /usr/local/lib/azurelinux3s4/web-relay.py"])
        listener = sections(entries["systemd/azurelinux3s4-web.socket"]["content"])["Socket"]
        self.assertEqual(listener["Accept"], ["yes"])
        self.assertEqual(listener["MaxConnections"], ["32"])
        self.assertNotIn("Service", listener)  # Accept=yes selects the matching template automatically.
        for name in ("systemd/azurelinux3s4-web-backend.service", "systemd/azurelinux3s4-web@.service"):
            self.assertEqual(sections(entries[name]["content"])["Service"]["Slice"], ["azurelinux3s4-web.slice"])
        self.assertNotIn("nftables/azurelinux3s4-web-egress.nft", entries)

    def test_raw_relay_literal_cannot_escape_assembly_boundary(self):
        spec = importlib.util.spec_from_file_location("s4_pack_test", ROOT / "Bootstrap/pack.py")
        pack = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pack)
        with tempfile.TemporaryDirectory() as temporary:
            checkout = Path(temporary)
            for name in pack.INPUTS:
                target = checkout / name
                target.parent.mkdir(exist_ok=True)
                shutil.copyfile(ROOT / name, target)
            path = checkout / pack.WORKER_TEMPLATE
            # This is valid Python but would close its enclosing raw literal.
            path.write_bytes(path.read_bytes() + b'# unsafe literal separator: ' + bytes([39]) * 3 + b'\n')
            with self.assertRaisesRegex(ValueError, "assembly boundary"):
                pack.assemble(checkout)

    def test_generated_policy_keeps_every_activation_authority_false(self):
        bundle = POLICY.bundle()
        self.assertTrue(all(value is False for value in bundle["authority"].values()))
        self.assertIn("sealing BEFORE forwarding", " ".join(bundle["prerequisites"]))
        self.assertIn("trusted", " ".join(bundle["limits"]).lower())
        self.assertIn("x86 source config disables", " ".join(bundle["limits"]))

    def test_worker_rejects_overrides_and_pipe_input_without_network_setup(self):
        for args in ([], ["--allow-connect"], ["/operator/backend"]):
            result = subprocess.run([sys.executable, "-I", str(WORKER), *args], input=b"request",
                                    capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 75, result.stderr)
            self.assertEqual(result.stdout, b"")

    def test_worker_rejects_listener_and_udp_descriptors(self):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(socket.AF_INET, kind) as stream:
                stream.bind(("127.0.0.1", 0))
                if kind == socket.SOCK_STREAM:
                    stream.listen(1)
                result = subprocess.run([sys.executable, "-I", str(WORKER)], stdin=stream,
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 75, result.stderr)
                self.assertEqual(result.stdout, b"")

    def test_inherited_extra_socket_descriptor_is_closed(self):
        with socket.socket(socket.AF_INET) as extra:
            result = subprocess.run([sys.executable, "-I", str(PROBE), "close-fds", str(extra.fileno())],
                                    pass_fds=(extra.fileno(),), capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(json.loads(result.stdout)["extra_fd_closed"])


class NativeRelayTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="s4-relay-", dir="/dev/shm")
        self.addCleanup(self.temporary.cleanup)
        self.target = str(Path(self.temporary.name) / "backend.sock")

    def accepted(self, family):
        listener = socket.socket(family)
        client = socket.socket(family)
        self.addCleanup(listener.close)
        self.addCleanup(client.close)
        listener.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
        listener.listen(1)
        client.settimeout(5)
        client.connect(listener.getsockname())
        inherited = listener.accept()[0]
        self.addCleanup(inherited.close)
        return client, inherited

    def finish(self, child, expected):
        stdout, stderr = child.communicate(timeout=8)
        self.assertEqual(child.returncode, expected, stderr.decode())
        return stdout, stderr

    def native(self, family):
        client, inherited = self.accepted(family)
        child = subprocess.Popen([sys.executable, "-I", str(PROBE), "native", str(inherited.fileno())],
                                 pass_fds=(inherited.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        client.sendall(b"fixture request")
        self.assertEqual(client.recv(64), b"fixture response")
        stdout, stderr = self.finish(child, 0)
        result = json.loads(stdout)
        for key in ("new_unix", "new_pair", "connect", "sendmsg", "recvmsg", "sendto_fastopen",
                    "setsockopt", "io_uring_setup", "pidfd_getfd", "clone3", "execveat", "bpf"):
            self.assertEqual(result[key], 1, key)
        for flag in ("server_ready", "nginx_executed", "systemd_units_executed"):
            self.assertFalse(result[flag])
        self.assertEqual(stderr, b"")
        return result

    def test_native_ipv4_seal_refuses_reconnect_fastopen_fd_acquisition_and_new_sockets(self):
        self.native(socket.AF_INET)

    def test_native_ipv6_seal_refuses_reconnect_fastopen_fd_acquisition_and_new_sockets(self):
        self.native(socket.AF_INET6)

    def forwarding(self, family):
        client, inherited = self.accepted(family)
        backend = socket.socket(socket.AF_UNIX)
        self.addCleanup(backend.close)
        backend.bind(self.target)
        backend.listen(1)
        backend.settimeout(5)
        request = b"bounded request\x00" * 70000
        response = b"bounded response\xff" * 70000
        observations, errors = [], []

        def serve():
            try:
                with backend.accept()[0] as connection:
                    connection.settimeout(5)
                    data = bytearray()
                    while True:
                        part = connection.recv(8191)
                        if not part:
                            break
                        data.extend(part)
                    observations.append(hashlib.sha256(data).hexdigest())
                    connection.sendall(response)
                    connection.shutdown(socket.SHUT_WR)
            except BaseException as error:
                errors.append(error)

        server = threading.Thread(target=serve)
        server.start()
        self.addCleanup(server.join, 6)
        child = subprocess.Popen([sys.executable, "-I", str(PROBE), "forward", self.target],
                                 stdin=inherited, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        inherited.close()
        client.sendall(request)
        client.shutdown(socket.SHUT_WR)
        actual = bytearray()
        while True:
            data = client.recv(8189)
            if not data:
                break
            actual.extend(data)
        stdout, stderr = self.finish(child, 0)
        server.join(6)
        self.assertFalse(server.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(observations, [hashlib.sha256(request).hexdigest()])
        self.assertEqual(hashlib.sha256(actual).hexdigest(), hashlib.sha256(response).hexdigest())
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"")

    def test_real_ipv4_worker_forwards_large_bytes_and_half_closes_with_sealed_syscalls(self):
        self.forwarding(socket.AF_INET)

    def test_real_ipv6_worker_forwards_large_bytes_and_half_closes_with_sealed_syscalls(self):
        self.forwarding(socket.AF_INET6)

    def test_missing_backend_refuses_without_forwarding(self):
        client, inherited = self.accepted(socket.AF_INET)
        child = subprocess.Popen([sys.executable, "-I", str(PROBE), "forward", self.target],
                                 stdin=inherited, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        inherited.close()
        stdout, stderr = self.finish(child, 75)
        self.assertEqual(stdout, b"")
        self.assertIn(b"Web relay refused", stderr)
        self.assertEqual(client.recv(64), b"")

    def refused_worker(self, mode):
        client, inherited = self.accepted(socket.AF_INET)
        with socket.socket(socket.AF_UNIX) as backend:
            backend.bind(self.target)
            backend.listen(1)
            backend.settimeout(5)
            child = subprocess.Popen([sys.executable, "-I", str(PROBE), mode, self.target],
                                     stdin=inherited, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.addCleanup(lambda: child.kill() if child.poll() is None else None)
            inherited.close()
            with backend.accept()[0] as connection:
                connection.settimeout(3)
                if mode == "total":
                    # Continuous progress must not extend the absolute deadline.
                    start = time.monotonic()
                    while child.poll() is None and time.monotonic() - start < 2:
                        try:
                            client.sendall(b"progress")
                            connection.recv(64)
                        except OSError:
                            break
                        time.sleep(0.03)
                else:
                    self.assertEqual(connection.recv(64), b"")
            stdout, stderr = self.finish(child, 75)
        self.assertEqual(stdout, b"")
        self.assertIn(b"Web relay refused", stderr)
        return stderr

    def test_idle_timeout_is_bounded_and_closes_without_success(self):
        self.assertIn(b"deadline", self.refused_worker("idle"))

    def test_total_timeout_cannot_be_extended_by_continuous_progress(self):
        self.assertIn(b"deadline", self.refused_worker("total"))

    def test_final_filter_failure_does_not_forward_or_publish_success(self):
        self.assertIn(b"final filter failure", self.refused_worker("filter-failure"))

    def test_failed_positive_seal_challenge_does_not_forward_or_publish_success(self):
        self.assertIn(b"seal challenge failure", self.refused_worker("challenge-failure"))


if __name__ == "__main__":
    unittest.main()

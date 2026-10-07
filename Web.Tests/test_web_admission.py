import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "Web.Tests/admission_probe.py"


def relay():
    spec = importlib.util.spec_from_file_location("s4_admission", ROOT / "Web/relay.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fingerprint(directory):
    records = []
    for path in sorted(directory.rglob("*")):
        value = path.lstat()
        records.append((str(path.relative_to(directory)), value.st_dev, value.st_ino,
                        value.st_mode, value.st_uid, value.st_gid, value.st_size,
                        path.read_bytes().hex() if stat.S_ISREG(value.st_mode) else
                        os.readlink(path) if stat.S_ISLNK(value.st_mode) else None))
    return records


class CredentialAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.worker = relay()
        self.proxy = types.SimpleNamespace(pw_name=self.worker.PROXY_USER, pw_uid=12345)
        self.backend = types.SimpleNamespace(pw_name=self.worker.BACKEND_USER, pw_uid=12346)
        self.group = types.SimpleNamespace(gr_name=self.worker.SHARED_GROUP, gr_gid=23456)
        self.status = (b"Uid:\t12345\t12345\t12345\t12345\n"
                       b"Gid:\t23456\t23456\t23456\t23456\nNoNewPrivs:\t1\n" +
                       b"".join(name + b":\t0000000000000000\n" for name in
                                (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb")))

    def observe(self, status=None, uids=(12345,) * 3, gids=(23456,) * 3, groups=(23456,)):
        names = {self.proxy.pw_name: self.proxy, self.backend.pw_name: self.backend}
        ids = {self.proxy.pw_uid: self.proxy, self.backend.pw_uid: self.backend}
        with (patch.object(self.worker.pwd, "getpwnam", side_effect=names.__getitem__),
              patch.object(self.worker.pwd, "getpwuid", side_effect=ids.__getitem__),
              patch.object(self.worker.grp, "getgrnam", return_value=self.group),
              patch.object(self.worker.grp, "getgrgid", return_value=self.group),
              patch.object(self.worker.os, "getresuid", return_value=uids),
              patch.object(self.worker.os, "getresgid", return_value=gids),
              patch.object(self.worker.os, "getgroups", return_value=list(groups)),
              patch("builtins.open", return_value=io.BytesIO(self.status if status is None else status))):
            return self.worker.process_identity()

    def test_bounded_consistent_identity_observation_has_no_authority_side_effect(self):
        self.assertEqual(self.observe(), (12345, 12346, 23456))

    def test_root_or_colliding_backend_proxy_identity_refuses(self):
        for uid in (0, self.proxy.pw_uid, 0xffffffff):
            self.backend.pw_uid = uid
            with self.assertRaises(ValueError):
                self.observe()

    def test_account_alias_and_reverse_lookup_ambiguity_refuse(self):
        self.proxy.pw_name = "borrowed-account"
        with self.assertRaises(KeyError):
            self.observe()
        self.proxy.pw_name = self.worker.PROXY_USER
        with patch.object(self.worker.pwd, "getpwuid", return_value=self.backend):
            # observe() supplies its own mappings; exercise the real branch
            # directly with the other NSS deliveries, no native account write.
            with (patch.object(self.worker.pwd, "getpwnam", side_effect=[self.proxy, self.backend]),
                  patch.object(self.worker.grp, "getgrnam", return_value=self.group)):
                with self.assertRaises(ValueError):
                    self.worker.process_identity()

    def test_root_shared_group_and_group_alias_refuse(self):
        self.group.gr_gid = 0
        with self.assertRaises(ValueError):
            self.observe()
        self.group.gr_gid = 23456
        self.group.gr_name = "borrowed-group"
        with self.assertRaises(ValueError):
            self.observe()

    def test_saved_or_real_credential_mismatch_refuses(self):
        for values in ((12345, 0, 12345), (0, 12345, 12345), (12345, 12345, 0)):
            with self.assertRaises(ValueError):
                self.observe(uids=values)
        with self.assertRaises(ValueError):
            self.observe(gids=(23456, 23456, 0))

    def test_borrowed_supplementary_groups_refuse(self):
        for values in ((0,), (23456, 999), (23456, 0)):
            with self.assertRaises(ValueError):
                self.observe(groups=values)

    def test_retained_each_capability_set_refuses(self):
        for name in (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.observe(status=self.status.replace(name + b":\t0000000000000000",
                                                        name + b":\t0000000000000001"))

    def test_nnp_missing_duplicate_and_filesystem_id_mismatch_refuse(self):
        for value in (self.status.replace(b"NoNewPrivs:\t1", b"NoNewPrivs:\t0"),
                      self.status.replace(b"NoNewPrivs:\t1\n", b""),
                      self.status + b"NoNewPrivs:\t1\n",
                      self.status.replace(b"12345\t12345\t12345\t12345", b"12345\t12345\t12345\t0")):
            with self.assertRaises(ValueError):
                self.observe(status=value)

    def test_oversized_and_malformed_process_status_refuse(self):
        for value in (b"x" * 16385, self.status.replace(b"CapBnd:\t0000000000000000", b"CapBnd:\t0"),
                      self.status.replace(b"CapAmb:\t0000000000000000\n", b"")):
            with self.assertRaises(ValueError):
                self.observe(status=value)

    def test_real_unconfigured_caller_is_refused_without_account_creation(self):
        result = subprocess.run([sys.executable, "-I", str(ROOT / "Web/relay.py")],
                                input=b"no authority", capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 75)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"Web relay refused", result.stderr)


class BackendAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.worker = relay()
        self.temporary = tempfile.TemporaryDirectory(prefix="s4wa-", dir="/dev/shm")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        (self.directory / "run").mkdir(mode=0o755)
        self.runtime = self.directory / "run/azurelinux3s4-web"
        self.runtime.mkdir(mode=0o750)
        self.leaf = self.runtime / "http.sock"
        # Disclosed root-fd/UID delivery; real object kinds/permissions/inodes,
        # O_PATH flags, mount records, native connection and peer credentials.
        self.worker.ROOT_UID = os.getuid()
        self.worker.ROOT_GID = os.getgid()
        self.worker.backend_root = lambda: os.open(self.directory, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)

    def listener(self, path=None, kind=socket.SOCK_STREAM):
        value = socket.socket(socket.AF_UNIX, kind)
        self.addCleanup(value.close)
        value.bind(str(path or self.leaf))
        (path or self.leaf).chmod(0o666)
        if kind == socket.SOCK_STREAM:
            value.listen(2)
        value.settimeout(2)
        return value

    def connect(self):
        return self.worker.connect_backend(os.getuid(), os.getgid())

    def reject_preserved(self):
        before = fingerprint(self.directory)
        with self.assertRaises((ValueError, OSError)):
            self.connect()
        self.assertEqual(fingerprint(self.directory), before)

    def test_actual_held_socket_and_kernel_peer_positive_preserve_tree(self):
        listener = self.listener()
        before = fingerprint(self.directory)
        with self.connect() as connection, listener.accept()[0] as peer:
            self.assertEqual(self.worker.peer_credentials(connection), (os.getpid(), os.getuid(), os.getgid()))
            connection.sendall(b"same held socket")
            self.assertEqual(peer.recv(64), b"same held socket")
        self.assertEqual(fingerprint(self.directory), before)

    def test_leaf_fifo_device_directory_regular_and_symlink_refuse_without_io(self):
        for kind in ("fifo", "directory", "file", "symlink-device", "symlink-dangling"):
            with self.subTest(kind=kind):
                if kind == "fifo": os.mkfifo(self.leaf, 0o666)
                elif kind == "directory": self.leaf.mkdir()
                elif kind == "file": self.leaf.write_bytes(b"operator object")
                else: self.leaf.symlink_to("/dev/null" if kind == "symlink-device" else "missing")
                self.reject_preserved()
                if kind == "directory": self.leaf.rmdir()
                else: self.leaf.unlink()

    def test_matching_symlink_to_actual_socket_is_not_followed(self):
        other = self.runtime / "other.sock"
        self.listener(other)
        self.leaf.symlink_to(other.name)
        self.reject_preserved()

    def test_runtime_alias_is_not_followed(self):
        self.runtime.rename(self.runtime.with_name("original-runtime"))
        self.runtime.symlink_to("original-runtime", target_is_directory=True)
        self.reject_preserved()

    def test_world_writable_protected_parent_refuses(self):
        self.listener()
        (self.directory / "run").chmod(0o777)
        self.reject_preserved()

    def test_wrong_runtime_modes_refuse(self):
        self.listener()
        for mode in (0o700, 0o751, 0o770, 0o777):
            self.runtime.chmod(mode)
            self.reject_preserved()

    def test_wrong_socket_modes_refuse(self):
        self.listener()
        for mode in (0o600, 0o660, 0o777):
            self.leaf.chmod(mode)
            self.reject_preserved()

    def test_wrong_owner_or_shared_group_refuses(self):
        self.listener()
        for uid, gid in ((os.getuid() + 1, os.getgid()), (os.getuid(), os.getgid() + 1)):
            before = fingerprint(self.directory)
            with self.assertRaises(ValueError):
                self.worker.connect_backend(uid, gid)
            self.assertEqual(fingerprint(self.directory), before)

    def test_missing_socket_and_dead_listener_refuse(self):
        self.reject_preserved()
        value = self.listener()
        value.close()
        self.reject_preserved()

    def test_datagram_leaf_cannot_be_used_as_stream_backend(self):
        self.listener(kind=socket.SOCK_DGRAM)
        self.reject_preserved()

    def test_listener_peer_credential_mismatch_refuses_without_sending_bytes(self):
        listener = self.listener()
        with patch.object(self.worker, "peer_credentials", return_value=(os.getpid(), os.getuid() + 1, os.getgid())):
            self.reject_preserved()
        with listener.accept()[0] as peer:
            self.assertEqual(peer.recv(1), b"")

    def test_leaf_replacement_after_connection_refuses_before_payload(self):
        listener = self.listener()
        original, calls = self.worker.backend_path, []

        def replaced(uid, gid):
            calls.append(None)
            if len(calls) == 2:
                self.leaf.rename(self.runtime / "preserved-original.sock")
                self.listener()
            return original(uid, gid)

        with patch.object(self.worker, "backend_path", side_effect=replaced):
            with self.assertRaisesRegex(ValueError, "changed"):
                self.connect()
        with listener.accept()[0] as peer:
            self.assertEqual(peer.recv(1), b"")
        self.assertTrue((self.runtime / "preserved-original.sock").is_socket())

    def test_socket_mount_transition_refuses(self):
        self.listener()
        actual = self.worker.mount_identity
        with patch.object(self.worker, "mount_identity", side_effect=lambda fd: actual(fd) +
                          int(stat.S_ISSOCK(os.fstat(fd).st_mode))):
            self.reject_preserved()

    def test_no_follow_open_flags_and_kernel_fd_connect_are_required(self):
        listener = self.listener()
        actual_open, actual_socket = os.open, socket.socket
        opens, targets = [], []

        def opened(path, flags, *args, **kwargs):
            opens.append((str(path), flags))
            return actual_open(path, flags, *args, **kwargs)

        class AuditedSocket(actual_socket):
            def connect(self, address):
                targets.append(address)
                return super().connect(address)

        with patch.object(self.worker.os, "open", side_effect=opened), patch.object(self.worker.socket, "socket", AuditedSocket):
            with self.connect(), listener.accept()[0]:
                pass
        self.assertTrue(opens)
        self.assertTrue(all(flags & os.O_PATH and flags & os.O_NOFOLLOW for _, flags in opens))
        self.assertEqual(len(targets), 1)
        self.assertRegex(targets[0], r"^/proc/self/fd/[0-9]+$")

    def test_failure_and_success_close_all_held_path_descriptors(self):
        listener = self.listener()
        before = set(os.listdir("/proc/self/fd"))
        with self.connect(), listener.accept()[0]:
            pass
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)
        self.leaf.chmod(0o777)
        self.reject_preserved()
        self.assertEqual(set(os.listdir("/proc/self/fd")), before)

    def test_real_unconnected_peer_credentials_are_unavailable(self):
        with socket.socket(socket.AF_UNIX) as stream:
            with self.assertRaises(ValueError):
                self.worker.peer_credentials(stream)

    def test_unavailable_mount_observation_preserves_objects(self):
        self.listener()
        with patch("builtins.open", return_value=io.BytesIO(b"pos:\t0\n")):
            with self.assertRaisesRegex(ValueError, "mount identity"):
                self.connect()


class LoggingAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.worker = relay()
        self.worker.ROOT_UID, self.worker.ROOT_GID = os.getuid(), os.getgid()
        self.temporary = tempfile.TemporaryDirectory(prefix="s4wj-", dir="/dev/shm")
        self.addCleanup(self.temporary.cleanup)
        self.path = str(Path(self.temporary.name) / "journal.sock")
        self.worker.JOURNAL = self.path

    def stream(self, path=None):
        listener = socket.socket(socket.AF_UNIX)
        client = socket.socket(socket.AF_UNIX)
        self.addCleanup(listener.close)
        self.addCleanup(client.close)
        listener.bind(path or self.path)
        listener.listen(1)
        client.connect(path or self.path)
        peer = listener.accept()[0]
        self.addCleanup(peer.close)
        return client

    def observe(self, first, second=None):
        second = first if second is None else second
        mapping = {1: first.fileno(), 2: second.fileno()}
        actual_stat, actual_socket = os.fstat, socket.socket
        # FD-number delivery only. Actual socket kinds/getpeername/SO_PEERCRED
        # remain native, and stdout/stderr of the test runner are untouched.
        with (patch.object(self.worker.os, "fstat", side_effect=lambda fd: actual_stat(mapping[fd])),
              patch.object(self.worker.socket, "socket", side_effect=lambda *, fileno: actual_socket(fileno=mapping[fileno]))):
            return self.worker.admit_logging()

    def test_real_connected_unix_journal_delivery_is_accepted_without_closing_stdio(self):
        client = self.stream()
        self.assertIsNone(self.observe(client))
        client.sendall(b"still open")

    def test_ip_logging_socket_refuses_without_affecting_original_descriptor(self):
        with socket.socket(socket.AF_INET) as stream:
            with self.assertRaises(ValueError):
                self.observe(stream)
            self.assertGreaterEqual(stream.fileno(), 0)

    def test_unix_listener_and_datagram_logging_refuse(self):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with socket.socket(socket.AF_UNIX, kind) as stream:
                path = self.path + str(kind)
                stream.bind(path)
                if kind == socket.SOCK_STREAM: stream.listen(1)
                with self.assertRaises((ValueError, OSError)):
                    self.observe(stream)

    def test_connected_wrong_journal_path_refuses(self):
        with self.assertRaises(ValueError):
            self.observe(self.stream(self.path + ".foreign"))

    def test_wrong_journal_peer_uid_or_gid_refuses(self):
        client = self.stream()
        for uid, gid in ((os.getuid() + 1, os.getgid()), (os.getuid(), os.getgid() + 1)):
            with patch.object(self.worker, "peer_credentials", return_value=(os.getpid(), uid, gid)):
                with self.assertRaises(ValueError):
                    self.observe(client)

    def test_distinct_journal_peer_pid_observations_refuse(self):
        client = self.stream()
        with patch.object(self.worker, "peer_credentials", side_effect=[
                (os.getpid(), os.getuid(), os.getgid()), (os.getpid() + 1, os.getuid(), os.getgid())]):
            with self.assertRaises(ValueError):
                self.observe(client)

    def test_actual_pipe_logging_refuses_without_opening_socket(self):
        read_fd, write_fd = os.pipe()
        try:
            with patch.object(self.worker.os, "fstat", return_value=os.fstat(write_fd)):
                with self.assertRaises(ValueError):
                    self.worker.admit_logging()
            os.write(write_fd, b"operator pipe remains usable")
            self.assertEqual(os.read(read_fd, 64), b"operator pipe remains usable")
        finally:
            os.close(read_fd)
            os.close(write_fd)


class NativeWorkerAdmissionTests(unittest.TestCase):
    setUp = BackendAdmissionTests.setUp
    listener = BackendAdmissionTests.listener

    def integrated(self, family=socket.AF_INET, mode="normal", expected=0, bad_logging=False):
        backend = self.listener()
        journal = self.listener(self.directory / "journal.sock")
        journal_client = socket.socket(socket.AF_UNIX)
        self.addCleanup(journal_client.close)
        journal_client.connect(str(self.directory / "journal.sock"))
        journal_peer = journal.accept()[0]
        self.addCleanup(journal_peer.close)
        journal_peer.settimeout(3)
        ingress = socket.socket(family)
        client = socket.socket(family)
        self.addCleanup(ingress.close)
        self.addCleanup(client.close)
        ingress.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
        ingress.listen(1)
        client.settimeout(5)
        client.connect(ingress.getsockname())
        accepted = ingress.accept()[0]
        request, response = b"same-byte-request\x00" * 5000, b"same-byte-response\xff" * 6000
        observations, failures = [], []

        def serve():
            try:
                with backend.accept()[0] as stream:
                    stream.settimeout(3)
                    payload = bytearray()
                    while part := stream.recv(8191): payload.extend(part)
                    observations.append(bytes(payload))
                    if expected == 0:
                        stream.sendall(response)
                        stream.shutdown(socket.SHUT_WR)
            except socket.timeout:
                if not bad_logging: failures.append("unexpected backend timeout")
            except BaseException as error:
                failures.append(str(error))

        server = threading.Thread(target=serve)
        server.start()
        self.addCleanup(server.join, 4)
        before = fingerprint(self.directory)
        child = subprocess.Popen([sys.executable, "-I", str(PROBE), str(self.directory), mode],
                                 stdin=accepted, stdout=subprocess.PIPE if bad_logging else journal_client,
                                 stderr=journal_client)
        self.addCleanup(lambda: child.kill() if child.poll() is None else None)
        accepted.close()
        journal_client.close()
        if expected == 0:
            client.sendall(request)
            client.shutdown(socket.SHUT_WR)
        actual = bytearray()
        while part := client.recv(8189): actual.extend(part)
        actual_exit = child.wait(timeout=6)
        if bad_logging: child.stdout.close()
        logs = bytearray()
        while part := journal_peer.recv(4096): logs.extend(part)
        server.join(4)
        self.assertEqual(actual_exit, expected, logs.decode())
        self.assertFalse(server.is_alive())
        self.assertEqual(failures, [])
        if expected == 0:
            self.assertEqual(observations, [request])
            self.assertEqual(bytes(actual), response)
            self.assertEqual(logs, b"")
        else:
            self.assertEqual(bytes(actual), b"")
            self.assertTrue(all(not value for value in observations))
            self.assertIn(b"Web relay refused", logs)
        replacement = None
        if mode in ("replace-leaf", "replace-leaf-without-recheck"):
            replacement = json.loads((self.directory / "replacement-proof.json").read_text())
            self.assertTrue(replacement["inherited_cleanup_completed"])
            self.assertEqual(replacement["backend_path_call"], 2)
            self.assertTrue(replacement["replacement_listener"])
            self.assertNotEqual(replacement["original_identity"], replacement["replacement_identity"])
            self.assertEqual(replacement["original_identity"], replacement["preserved_identity"])
            self.assertTrue(stat.S_ISSOCK(replacement["replacement_mode"]))
            self.assertEqual(stat.S_IMODE(replacement["replacement_mode"]), 0o666)
            self.assertEqual((replacement["replacement_uid"], replacement["replacement_gid"]),
                             (os.getuid(), os.getgid()))
            for path, identity in ((self.leaf, replacement["replacement_identity"]),
                                   (self.runtime / "retained-original.sock", replacement["original_identity"])):
                value = path.lstat()
                self.assertTrue(stat.S_ISSOCK(value.st_mode))
                self.assertEqual([value.st_dev, value.st_ino], identity)
            self.assertEqual(replacement["production_recheck_omitted"], mode.endswith("without-recheck"))
            if mode == "replace-leaf":
                self.assertEqual(expected, 75)
                self.assertEqual(logs, b"Web relay refused: backend ancestry/socket changed during admission\n")
                self.assertEqual(observations, [b""])
            else:
                self.assertEqual(expected, 0)
                self.assertIn("backend ancestry/socket changed during admission", replacement["removed_recheck_ast"])
        else:
            self.assertEqual(fingerprint(self.directory), before)
        # Optional evidence hook is AFTER every ordinary assertion.
        self.record = {"actual_child_wait_exit": actual_exit, "expected_exit": expected,
                       "mode": mode, "family": int(family), "backend_received_bytes": sum(map(len, observations)),
                       "response_bytes": len(actual), "request_sha256": hashlib.sha256(request).hexdigest(),
                       "response_sha256": hashlib.sha256(actual).hexdigest(), "stderr": logs.decode(),
                       "root_fd_uid_gid_journal_path_and_caller_delivery_substituted": True,
                       "native_accounts_or_manager_authorized": False, "systemd_nginx_executed": False,
                       "installation_authorized": False, "server_ready": False,
                       "replacement_proof": replacement}

    def test_native_checked_admission_ipv4_seals_and_forwards_same_bytes(self):
        self.integrated()

    def test_native_checked_admission_ipv6_seals_and_forwards_same_bytes(self):
        self.integrated(socket.AF_INET6)

    def test_native_startup_lookup_descriptor_is_closed_before_sealing(self):
        self.integrated(mode="extra-fd")

    def test_native_account_observation_change_refuses_before_forwarding(self):
        self.integrated(mode="changed-accounts", expected=75)

    def test_native_leaf_replacement_refuses_before_forwarding(self):
        self.integrated(mode="replace-leaf", expected=75)

    def test_omitted_recheck_model_demonstrates_replacement_detection_sensitivity(self):
        self.integrated(mode="replace-leaf-without-recheck")

    def test_native_pipe_logging_refuses_before_connecting_backend(self):
        self.integrated(expected=75, bad_logging=True)


if __name__ == "__main__":
    unittest.main()

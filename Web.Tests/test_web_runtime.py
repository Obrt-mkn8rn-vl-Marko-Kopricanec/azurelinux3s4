import ctypes
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

import test_web_admission as admission
from test_web_isolation import POLICY, sections


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "Web.Tests/runtime_probe.py"


def loaded():
    spec = importlib.util.spec_from_file_location("s4_runtime_tests", ROOT / "Web/runtime.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RuntimeMapTests(unittest.TestCase):
    def setUp(self):
        self.runtime = loaded()
        self.line = b"1000-2000 r-xp 00000000 01:02 17 /lib/image.so\n"

    def test_bounded_executable_image_and_kernel_ranges_are_observed(self):
        records, images = self.runtime.runtime_maps(self.line + b"3000-4000 r-xp 00000000 00:00 0 [vdso]\n")
        self.assertEqual(images, {(1, 2, 17): "/lib/image.so"})
        self.assertEqual(len(records), 2)

    def test_data_only_map_split_does_not_change_executable_observation(self):
        original = self.runtime.runtime_maps(self.line)
        self.assertEqual(original, self.runtime.runtime_maps(
            self.line + b"3000-4000 r--p 00000000 01:02 17 /lib/image.so\n"))

    def test_anonymous_and_writable_executable_ranges_refuse(self):
        for data in (self.line + b"3000-4000 r-xp 00000000 00:00 0\n",
                     self.line.replace(b"r-xp", b"rwxp")):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.runtime.runtime_maps(data)

    def test_unknown_kernel_executable_label_refuses(self):
        with self.assertRaises(ValueError):
            self.runtime.runtime_maps(self.line + b"3000-4000 r-xp 00000000 00:00 0 [future-label]\n")

    def test_malformed_fields_truncation_and_integer_bounds_refuse(self):
        for data in (b"", self.line[:-1], b"bad line\n", self.line.replace(b"01:02", b"bad"),
                     self.line.replace(b"1000-2000", b"2000-1000"),
                     self.line.replace(b"17 /", b"18446744073709551616 /")):
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.runtime.runtime_maps(data)

    def test_deleted_relative_alias_or_ambiguous_image_paths_refuse(self):
        for path in (b"relative.so", b"/lib/../image.so", b"/lib//image.so", b"/lib/image.so (deleted)"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.runtime.runtime_maps(self.line.replace(b"/lib/image.so", path))
        for extra in (b"3000-4000 r-xp 00000000 01:02 18 /lib/image.so\n",
                      b"3000-4000 r-xp 00000000 01:02 17 /lib/other.so\n"):
            with self.assertRaises(ValueError):
                self.runtime.runtime_maps(self.line + extra)

    def test_proc_short_reads_are_collected_until_actual_eof(self):
        with (patch.object(self.runtime.os, "open", return_value=99),
              patch.object(self.runtime.os, "fstat", return_value=types.SimpleNamespace(st_mode=stat.S_IFREG)),
              patch.object(self.runtime.os, "read", side_effect=[self.line[:9], self.line[9:], b""]) as reader,
              patch.object(self.runtime.os, "close") as close):
            self.assertEqual(self.runtime.runtime_maps(), self.runtime.runtime_maps(self.line))
        self.assertEqual(reader.call_count, 3)
        close.assert_called_once_with(99)

    def test_proc_wrong_kind_or_oversize_refuses_and_closes(self):
        with (patch.object(self.runtime.os, "open", return_value=99),
              patch.object(self.runtime.os, "fstat", return_value=types.SimpleNamespace(st_mode=stat.S_IFIFO)),
              patch.object(self.runtime.os, "read") as reader,
              patch.object(self.runtime.os, "close") as close):
            with self.assertRaises(ValueError): self.runtime.runtime_maps()
            reader.assert_not_called()
            close.assert_called_once_with(99)
        with patch.object(self.runtime, "RUNTIME_MAP_BYTES", 4):
            with self.assertRaises(ValueError): self.runtime.runtime_maps(self.line)

    def test_no_executable_image_or_too_many_images_refuses(self):
        with self.assertRaises(ValueError):
            self.runtime.runtime_maps(self.line.replace(b"r-xp", b"r--p"))
        with patch.object(self.runtime, "RUNTIME_IMAGES", 0):
            with self.assertRaises(ValueError): self.runtime.runtime_maps(self.line)


class RuntimeFileTests(unittest.TestCase):
    def setUp(self):
        self.runtime = loaded()
        self.temporary = tempfile.TemporaryDirectory(prefix="s4-runtime-files-", dir="/dev/shm")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.library = self.root / "lib"
        self.library.mkdir(mode=0o750)
        self.file = self.library / "image.so"
        header = bytearray(64)
        header[:7] = b"\x7fELF\x02\x01\x01"
        struct.pack_into("<HHI", header, 16, 3, 62 if self.runtime.platform.machine() == "x86_64" else 183, 1)
        struct.pack_into("<H", header, 52, 64)
        self.bytes = bytes(header) + b"synthetic ELF prefix; not an executable fixture\n" * 100
        self.file.write_bytes(self.bytes)
        self.file.chmod(0o644)
        # Delivery substitution ONLY in these private file controls. Native
        # whole-worker observations retain actual root-owned host paths/UID0.
        self.runtime.RUNTIME_OWNER = os.getuid()
        self.runtime.runtime_root = lambda: os.open(self.root, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)

    def invoke(self, expected=None):
        value = self.file.lstat()
        identity = os.major(value.st_dev), os.minor(value.st_dev), value.st_ino
        return self.runtime.runtime_image("/lib/image.so", expected or identity, time.monotonic() + 5)

    def test_actual_private_held_inode_hash_and_elf_prefix_correspond(self):
        proof = self.invoke()
        self.assertEqual(proof["sha256"], hashlib.sha256(self.bytes).hexdigest())
        self.assertEqual(proof["bytes"], len(self.bytes))
        self.assertEqual(proof["path"], "/lib/image.so")

    def test_wrong_mapped_inode_refuses_before_hash_reopen(self):
        with patch.object(self.runtime.os, "open", wraps=os.open) as opened:
            with self.assertRaisesRegex(ValueError, "mapped inode"):
                self.invoke((0, 0, 0))
        self.assertFalse(any(str(call.args[0]).startswith("/proc/self/fd/") for call in opened.call_args_list))

    def test_writable_regular_leaf_and_directory_remain_refusals(self):
        for path in (self.file, self.library):
            old = stat.S_IMODE(path.stat().st_mode)
            path.chmod(old | 0o020)
            with self.assertRaisesRegex(ValueError, "unprotected"):
                self.invoke()
            path.chmod(old)

    def test_wrong_kind_fifo_socket_directory_and_symlink_are_not_opened_for_io(self):
        self.file.unlink()
        operator = self.root / "operator"
        operator.write_bytes(b"untouched operator bytes")
        for kind in ("fifo", "socket", "directory", "symlink"):
            endpoint = None
            with self.subTest(kind=kind):
                if kind == "fifo": os.mkfifo(self.file, 0o600)
                elif kind == "socket":
                    endpoint = socket.socket(socket.AF_UNIX)
                    endpoint.bind(str(self.file))
                    self.file.chmod(0o600)
                elif kind == "directory": self.file.mkdir(mode=0o700)
                else: self.file.symlink_to(operator)
                identity = self.file.lstat()
                with patch.object(self.runtime.os, "open", wraps=os.open) as opened:
                    with self.assertRaises(ValueError): self.invoke()
                self.assertEqual(self.file.lstat(), identity)
                self.assertEqual(operator.read_bytes(), b"untouched operator bytes")
                self.assertFalse(any(str(call.args[0]).startswith("/proc/self/fd/") for call in opened.call_args_list))
                if endpoint is not None: endpoint.close()
                if kind == "directory": self.file.rmdir()
                else: self.file.unlink()

    def test_parent_symlink_refuses_without_following_referent(self):
        self.library.rename(self.root / "retained")
        self.library.symlink_to("retained", target_is_directory=True)
        with self.assertRaises(ValueError): self.invoke()
        self.assertEqual((self.root / "retained/image.so").read_bytes(), self.bytes)

    def test_untrusted_owner_delivery_refuses_without_reading_content(self):
        original = os.fstat

        def observed(fd):
            value = original(fd)
            if stat.S_ISREG(value.st_mode):
                return types.SimpleNamespace(st_uid=os.getuid() + 1, st_mode=value.st_mode)
            return value

        with patch.object(self.runtime.os, "fstat", side_effect=observed):
            with self.assertRaisesRegex(ValueError, "unprotected"):
                self.invoke((0, 0, 0))

    def test_bad_elf_class_endian_machine_type_version_and_size_refuse(self):
        for offset, replacement in ((4, b"\x01"), (5, b"\x02"), (16, b"\x01\x00"),
                                    (18, b"\x00\x00"), (20, b"\x00\x00\x00\x00"), (52, b"\x01\x00")):
            data = bytearray(self.bytes)
            data[offset:offset + len(replacement)] = replacement
            self.file.write_bytes(data)
            with self.subTest(offset=offset), self.assertRaisesRegex(ValueError, "ELF header"):
                self.invoke()
        self.file.write_bytes(b"too short")
        with self.assertRaisesRegex(ValueError, "size bound"): self.invoke()

    def test_per_file_size_and_expired_read_bound_refuse(self):
        with patch.object(self.runtime, "RUNTIME_IMAGE_BYTES", 64):
            with self.assertRaises(ValueError): self.invoke()
        value = self.file.stat()
        identity = os.major(value.st_dev), os.minor(value.st_dev), value.st_ino
        with self.assertRaisesRegex(ValueError, "byte/time bound"):
            self.runtime.runtime_image("/lib/image.so", identity, 0)

    def test_actual_file_mutation_during_hash_refuses(self):
        original = os.read
        modified = []

        def observed(fd, count):
            data = original(fd, count)
            if count == 1024 * 1024 and not modified:
                modified.append(True)
                self.file.write_bytes(self.bytes + b"changed")
            return data

        with patch.object(self.runtime.os, "read", side_effect=observed):
            with self.assertRaisesRegex(ValueError, "changed while hashing"):
                self.invoke()
        self.assertTrue(modified)

    def test_actual_path_inode_replacement_after_hash_refuses(self):
        original = self.runtime.runtime_walk
        calls = []

        def replaced(path):
            calls.append(path)
            if len(calls) == 2:
                self.file.rename(self.library / "retained.so")
                self.file.write_bytes(self.bytes)
                self.file.chmod(0o644)
            return original(path)

        with patch.object(self.runtime, "runtime_walk", side_effect=replaced):
            with self.assertRaisesRegex(ValueError, "path or mount changed"):
                self.invoke()
        self.assertEqual((self.library / "retained.so").read_bytes(), self.bytes)

    def test_hash_uses_kernel_fd_link_and_all_namespace_opens_use_no_follow(self):
        with patch.object(self.runtime.os, "open", wraps=os.open) as opened:
            self.invoke()
        magic = [call for call in opened.call_args_list if str(call.args[0]).startswith("/proc/self/fd/")]
        self.assertEqual(len(magic), 1)
        for call in opened.call_args_list:
            if call not in magic:
                self.assertTrue(call.args[1] & os.O_PATH)
                self.assertTrue(call.args[1] & os.O_NOFOLLOW)


class RuntimeStartupTests(unittest.TestCase):
    def setUp(self):
        self.runtime = loaded()

    def fake(self, blocked=False, existing=False, ignored=False, arm_zero=False, retirement_bad=False):
        state = {"handler": signal.SIG_IGN if ignored else signal.SIG_DFL,
                 "timer": (10.0, 0.0) if existing else (0.0, 0.0)}
        calls = []

        def handler(number, value):
            old, state["handler"] = state["handler"], value
            calls.append(("handler", value))
            return old

        def timer(which, value):
            state["timer"] = (0.0 if arm_zero else float(value), 0.0)
            if retirement_bad and not value: state["timer"] = (1.0, 0.0)
            calls.append(("timer", value))
            return (0.0, 0.0)

        return state, calls, [patch.object(self.runtime.signal, "getsignal", side_effect=lambda number: state["handler"]),
                              patch.object(self.runtime.signal, "getitimer", side_effect=lambda which: state["timer"]),
                              patch.object(self.runtime.signal, "pthread_sigmask", return_value={signal.SIGALRM} if blocked else set()),
                              patch.object(self.runtime.signal, "signal", side_effect=handler),
                              patch.object(self.runtime.signal, "setitimer", side_effect=timer)]

    def invoke(self, **options):
        import contextlib
        state, self.calls, patches = self.fake(**options)
        with contextlib.ExitStack() as stack:
            for item in patches: stack.enter_context(item)
            with self.runtime.RuntimeStartup() as startup:
                startup.disarm()
                startup.disarm()
        return state

    def test_timer_is_armed_observed_and_retired_before_reuse(self):
        state = self.invoke()
        self.assertEqual(state, {"handler": signal.SIG_DFL, "timer": (0.0, 0.0)})
        self.assertEqual([call for call in self.calls if call[0] == "timer"], [("timer", 60), ("timer", 0)])

    def test_blocked_alarm_existing_timer_and_ignored_handler_are_preserved_refusals(self):
        for options in ({"blocked": True}, {"existing": True}, {"ignored": True}):
            with self.subTest(options=options), self.assertRaisesRegex(ValueError, "signal context refused"):
                self.invoke(**options)
            self.assertEqual(self.calls, [])

    def test_successful_arm_delivery_without_live_timer_is_not_certified(self):
        with self.assertRaises(RuntimeError): self.invoke(arm_zero=True)

    def test_failed_timer_retirement_observation_cannot_reach_forwarding(self):
        with self.assertRaisesRegex(RuntimeError, "retirement"):
            self.invoke(retirement_bad=True)

    def test_handler_expiry_is_a_caught_timeout_failure(self):
        with self.assertRaisesRegex(TimeoutError, "startup deadline"):
            self.runtime.RuntimeStartup().expired(signal.SIGALRM, None)

    def test_service_allowance_accounts_for_startup_forwarding_and_local_reserve(self):
        entry = next(item for item in POLICY.bundle()["files"] if item["file"].endswith("web@.service"))
        service = sections(entry["content"])["Service"]
        total = int(service["RuntimeMaxSec"][0].removesuffix("s"))
        self.assertEqual(total, self.runtime.STARTUP_SECONDS + 300 + 30)
        self.assertEqual(service["TimeoutStopSec"], ["30s"])
        self.assertTrue(all(value is False for value in POLICY.bundle()["authority"].values()))


class NativeRuntimeTests(unittest.TestCase):
    def test_actual_root_owned_interpreter_and_native_files_have_bound_hash_observations(self):
        result = subprocess.run([sys.executable, "-I", str(PROBE), "native"], capture_output=True, timeout=12)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        proof = json.loads(result.stdout)
        self.assertGreater(len(proof["images"]), 3)
        self.assertTrue(proof["startup_timer_retired"])
        self.assertFalse(proof["root_file_owner_or_path_substituted"])
        self.assertFalse(proof["native_runtime_authenticated"])
        self.assertFalse(proof["memory_contents_attested"])
        self.assertFalse(proof["dependency_closure_complete"])
        self.assertFalse(proof["installation_authorized"])
        self.assertFalse(proof["server_ready"])
        self.assertIn(proof["interpreter_path"], {entry["path"] for entry in proof["images"]})
        for entry in proof["images"]:
            self.assertEqual(entry["file_identity"][0][3], 0)
            self.assertEqual(len(entry["sha256"]), 64)
            self.assertGreaterEqual(entry["bytes"], 64)
        self.record = {"actual_child_wait_exit": result.returncode, **proof}


class WorkerRuntimeTests(unittest.TestCase):
    setUp = admission.NativeWorkerAdmissionTests.setUp
    listener = admission.NativeWorkerAdmissionTests.listener
    integrated = admission.NativeWorkerAdmissionTests.integrated

    def refuses(self, mode, reason, prefix="", no_backend=False):
        with patch.object(admission, "PROBE", PROBE):
            self.integrated(mode=mode, expected=75, bad_logging=no_backend)
        self.assertEqual(self.record["stderr"], prefix + "Web relay refused: " + reason + "\n")
        self.assertEqual(self.record["backend_received_bytes"], 0)
        self.assertEqual(self.record["response_bytes"], 0)
        self.record["runtime_or_clock_delivery_model"] = mode in ("unstable-maps", "wrong-mapped-inode", "startup-expiry")

    def test_changed_executable_map_delivery_refuses_before_forwarding(self):
        self.refuses("unstable-maps", "loaded runtime changed during file observation")

    def test_wrong_interpreter_mapped_inode_delivery_refuses_before_forwarding(self):
        self.refuses("wrong-mapped-inode", "interpreter executable is not bound to mapped runtime")

    def test_actual_anonymous_executable_mapping_refuses_before_forwarding(self):
        self.refuses("anonymous-exec", "anonymous executable runtime mapping refused")

    def test_actual_unprotected_executable_file_mapping_refuses_before_forwarding(self):
        self.refuses("unprotected-file-exec", "unprotected runtime image ancestry or ownership")

    def test_actual_blocked_startup_alarm_context_refuses_before_admission(self):
        self.refuses("blocked-alarm", "relay startup signal context refused", no_backend=True)

    def test_actual_scaled_startup_alarm_is_delivered_after_final_filter_and_landlock(self):
        self.refuses("startup-expiry", "relay startup deadline reached", "FIXTURE_FINAL_FILTER_LANDLOCK_READY\n")


if __name__ == "__main__":
    unittest.main()

import contextlib
import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import test_web_admission as admission
from test_web_isolation import POLICY

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "Web.Tests/filesystem_probe.py"


class FilesystemContractTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("s4_filesystem", ROOT / "Web/relay.py")
        self.worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.worker)

    def invoke(self, abi=6, context=(1, 2), create=101, restrict=0,
               tasks=None, baseline_mode=stat.S_IFREG | 0o444, baseline=b"N",
               challenge_errno=errno.EACCES, challenge_success=False, close_failure=None):
        self.calls, self.closed, self.opened = [], [], []

        def prctl(number, *args):
            return context[0] if number == 39 else context[1]

        def syscall(number, *args):
            self.calls.append((number.value, args))
            if number.value == 446:
                return restrict
            if args[-1].value == 1:
                return abi
            self.mask, self.size = args[0]._obj.value, args[1].value
            return create

        def opened(path, flags):
            self.opened.append((path, flags))
            if len(self.opened) == 1:
                return 100
            if challenge_success:
                return 102
            raise OSError(challenge_errno, "delivered challenge failure")

        def closed(fd):
            self.closed.append(fd)
            if fd == close_failure:
                raise OSError(errno.EIO, "delivered close failure")

        entries = [types.SimpleNamespace(name=name) for name in
                   (tasks if tasks is not None else [str(os.getpid())])]
        library = types.SimpleNamespace(syscall=syscall, prctl=prctl)
        with (patch.object(self.worker.ctypes, "CDLL", return_value=library),
              patch.object(self.worker.ctypes, "get_errno", return_value=errno.EIO),
              patch.object(self.worker.os, "scandir", return_value=contextlib.nullcontext(iter(entries))),
              patch.object(self.worker.os, "open", side_effect=opened),
              patch.object(self.worker.os, "fstat", return_value=types.SimpleNamespace(st_mode=baseline_mode)),
              patch.object(self.worker.os, "read", return_value=baseline),
              patch.object(self.worker.os, "close", side_effect=closed)):
            return self.worker.confine_filesystem()

    def test_native_uapi_prefix_and_abi3_4_5_plus_masks_have_no_allow_rules(self):
        for abi in (3, 4, 5, 6, 7):
            with self.subTest(abi=abi):
                result = self.invoke(abi=abi)
                self.assertEqual(result, (abi, 32767 if abi < 5 else 65535))
                self.assertEqual(self.size, 8)
                self.assertEqual(self.mask, result[1])
                self.assertEqual([number for number, _ in self.calls], [444, 444, 446])
                self.assertEqual(self.closed, [101, 100])

    def test_absent_landlock_query_refuses_before_open_or_create(self):
        with self.assertRaisesRegex(OSError, "ABI query refused"):
            self.invoke(abi=-1)
        self.assertEqual(self.opened, [])
        self.assertEqual(self.closed, [])

    def test_old_abi_cannot_drop_truncation_and_certify_confinement(self):
        for abi in (0, 1, 2):
            with self.subTest(abi=abi), self.assertRaisesRegex(ValueError, "ABI3"):
                self.invoke(abi=abi)
            self.assertEqual(len(self.calls), 1)
            self.assertEqual(self.opened, [])

    def test_missing_nnp_or_filter_refuses_before_query(self):
        for context in ((0, 2), (1, 0), (-1, 2)):
            with self.subTest(context=context), self.assertRaisesRegex(RuntimeError, "NNP and seccomp"):
                self.invoke(context=context)
            self.assertEqual(self.calls, [])

    def test_creation_failure_closes_the_baseline_descriptor(self):
        with self.assertRaisesRegex(OSError, "ruleset creation refused"):
            self.invoke(create=-1)
        self.assertEqual(self.closed, [100])

    def test_restriction_failure_closes_both_descriptors_before_refusal(self):
        with self.assertRaisesRegex(OSError, "restriction refused"):
            self.invoke(restrict=-1)
        self.assertEqual(self.closed, [101, 100])
        self.assertEqual(len(self.opened), 1)

    def test_existing_sibling_or_wrong_task_refuses_before_baseline(self):
        for tasks in ([str(os.getpid()), "999"], ["999"], []):
            with self.subTest(tasks=tasks), self.assertRaisesRegex(RuntimeError, "one live task"):
                self.invoke(tasks=tasks)
            self.assertEqual(self.opened, [])

    def test_nonregular_or_unreadable_baseline_cannot_certify_denial(self):
        for kwargs in ({"baseline_mode": stat.S_IFIFO | 0o600}, {"baseline": b""}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, "baseline"):
                self.invoke(**kwargs)
            self.assertEqual(self.closed, [100])
            self.assertEqual(len(self.calls), 1)

    def test_baseline_nofollow_and_both_namespace_and_fd_reopen_are_checked(self):
        self.invoke()
        self.assertEqual([path for path, _ in self.opened],
                         ["/proc/self/status", "/proc/self/status", "/proc/self/fd/100"])
        self.assertTrue(self.opened[0][1] & os.O_NOFOLLOW)
        self.assertTrue(all(flags & os.O_CLOEXEC for _, flags in self.opened))

    def test_api_success_without_read_denial_is_refused_and_closes_new_fd(self):
        with self.assertRaisesRegex(RuntimeError, "read-denial challenge failed"):
            self.invoke(challenge_success=True)
        self.assertEqual(self.closed, [101, 102, 100])

    def test_enoent_or_other_challenge_error_is_not_enforcement(self):
        for error in (errno.ENOENT, errno.EPERM, errno.EIO):
            with self.subTest(error=error), self.assertRaises(OSError) as caught:
                self.invoke(challenge_errno=error)
            self.assertEqual(caught.exception.errno, error)
            self.assertEqual(self.closed, [101, 100])

    def test_failed_ruleset_close_prevents_challenges_and_success(self):
        with self.assertRaisesRegex(OSError, "close failure"):
            self.invoke(close_failure=101)
        self.assertEqual(self.closed, [101, 100])
        self.assertEqual(len(self.opened), 1)

    def test_failed_probe_close_prevents_success_even_after_challenges(self):
        with self.assertRaisesRegex(OSError, "close failure"):
            self.invoke(close_failure=100)
        self.assertEqual(self.closed, [101, 100])

    def test_unknown_native_architecture_refuses_without_library_loading(self):
        with patch.object(self.worker.platform, "machine", return_value="riscv64"):
            with self.assertRaisesRegex(ValueError, "architecture"):
                self.worker.confine_filesystem()

    def test_compatibility_pointer_or_long_abi_refuses_before_syscall(self):
        actual_size = ctypes.sizeof
        for narrow in (ctypes.c_void_p, ctypes.c_long):
            with self.subTest(narrow=narrow), patch.object(self.worker.ctypes, "sizeof",
                    side_effect=lambda kind: 4 if kind is narrow else actual_size(kind)):
                with self.assertRaisesRegex(ValueError, "ABI"):
                    self.worker.confine_filesystem()

    def test_candidate_declares_landlock_prerequisite_and_keeps_authority_false(self):
        bundle = POLICY.bundle()
        self.assertIn("Landlock ABI3+", " ".join(bundle["prerequisites"]))
        self.assertIn("metadata/O_PATH", " ".join(bundle["limits"]))
        self.assertTrue(all(value is False for value in bundle["authority"].values()))


class NativeFilesystemTests(unittest.TestCase):
    def native(self, mode):
        with tempfile.TemporaryDirectory(prefix="s4ll-", dir="/dev/shm") as temporary:
            directory = Path(temporary)
            seed = directory / "seed"
            seed.write_bytes(b"private existing descriptor fixture")
            (directory / "folder").mkdir()
            before = seed.lstat()
            result = subprocess.run([sys.executable, "-I", str(PROBE), temporary, mode],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stderr, b"")
            proof = json.loads(result.stdout)
            after = seed.lstat()
            # Baseline/held-FD reads may update atime. Require stable content
            # metadata and inode identity, without treating atime as a write.
            self.assertEqual((after.st_dev, after.st_ino, after.st_mode, after.st_uid,
                              after.st_gid, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                             (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                              before.st_gid, before.st_size, before.st_mtime_ns, before.st_ctime_ns))
            self.assertEqual(seed.read_bytes(), b"private existing descriptor fixture")
            self.assertEqual(sorted(p.name for p in directory.iterdir()), ["folder", "seed"])
        self.assertEqual(len(proof["native_errno"]), 16)
        self.assertTrue(all(value == errno.EACCES for value in proof["native_errno"].values()))
        self.assertTrue(proof["preexisting_read_descriptor_remains_usable"])
        self.assertTrue(proof["metadata_and_o_path_remain_available"])
        self.assertTrue(proof["positive_true_baseline_executed"])
        self.assertFalse(proof["final_exec_denial_filter_installed"])
        self.assertFalse(proof["kernel_enforcement_substituted"])
        self.assertFalse(proof["installation_authorized"])
        self.assertFalse(proof["server_ready"])
        self.record = {"actual_child_wait_exit": result.returncode, "mode": mode, **proof}
        return proof

    def test_native_empty_ruleset_refuses_file_and_namespace_operations(self):
        proof = self.native("native")
        self.assertGreaterEqual(proof["abi"], 3)
        self.assertEqual(proof["handled_access_fs"], 32767 if proof["abi"] < 5 else 65535)
        self.assertFalse(proof["version_query_substituted"])

    def test_native_kernel_accepts_abi3_prefix_with_disclosed_query_delivery(self):
        proof = self.native("abi3")
        self.assertEqual(proof["abi"], 3)
        self.assertEqual(proof["handled_access_fs"], 32767)
        self.assertTrue(proof["version_query_substituted"])


class WorkerFilesystemTests(unittest.TestCase):
    setUp = admission.NativeWorkerAdmissionTests.setUp
    listener = admission.NativeWorkerAdmissionTests.listener
    integrated = admission.NativeWorkerAdmissionTests.integrated

    def refuses(self, mode, reason):
        with patch.object(admission, "PROBE", PROBE):
            self.integrated(mode=mode, expected=75)
        self.assertEqual(self.record["stderr"], "Web relay refused: " + reason + "\n")
        self.assertEqual(self.record["actual_child_wait_exit"], 75)
        self.assertEqual(self.record["backend_received_bytes"], 0)
        self.assertEqual(self.record["response_bytes"], 0)

    def test_missing_native_landlock_refuses_before_forwarding(self):
        self.refuses("query-failure", "[Errno 38] Landlock ABI query refused")

    def test_old_abi_refuses_before_forwarding(self):
        self.refuses("abi2", "Landlock ABI3 or newer is required")

    def test_failed_native_ruleset_creation_refuses_before_forwarding(self):
        self.refuses("create-failure", "[Errno 5] Landlock ruleset creation refused")

    def test_failed_native_restriction_refuses_before_forwarding(self):
        self.refuses("restrict-failure", "[Errno 13] Landlock restriction refused")

    def test_unapplied_zero_exit_is_detected_by_actual_read_challenge(self):
        self.refuses("unapplied", "filesystem read-denial challenge failed")

    def test_existing_sibling_thread_refuses_after_final_tsync_filter(self):
        self.refuses("threaded", "filesystem confinement requires one live task")


if __name__ == "__main__":
    unittest.main()

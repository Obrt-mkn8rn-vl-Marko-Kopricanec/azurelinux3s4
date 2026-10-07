import ctypes
import errno
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

import test_web_admission as admission
from test_web_isolation import POLICY


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "Web.Tests/memory_probe.py"


class MemoryContractTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("s4_memory_contract", ROOT / "Web/memory.py")
        self.worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.worker)

    def invoke(self, initial=0, install=0, readback=1, final=1, allocate=True,
               change=-1, change_errno=errno.EACCES, create=False, create_errno=errno.EACCES,
               cleanup=0, baseline=0, compatible=0, page=4096):
        self.calls, self.unmapped = [], []
        queried, mappings, protections = [], [], []
        failed = ctypes.c_void_p(-1).value

        def prctl(option, *args):
            self.calls.append(("prctl", option, args))
            if option == 65:
                ctypes.set_errno(errno.EPERM)
                return install
            queried.append(None)
            ctypes.set_errno(errno.EINVAL)
            return initial if len(queried) == 1 else readback if len(queried) == 2 else final

        def mmap(*args):
            mappings.append(None)
            self.calls.append(("mmap", args))
            ctypes.set_errno(errno.ENOMEM if len(mappings) == 1 else create_errno)
            return (100 if allocate else failed) if len(mappings) == 1 else (200 if create else failed)

        def mprotect(address, size, permissions):
            protections.append(permissions)
            self.calls.append(("mprotect", address, size, permissions))
            ctypes.set_errno(change_errno)
            return baseline if len(protections) == 1 else change if len(protections) == 2 else compatible

        def munmap(address, size):
            self.unmapped.append(address)
            ctypes.set_errno(errno.EIO)
            return cleanup

        libc = types.SimpleNamespace(prctl=prctl, mmap=mmap, mprotect=mprotect, munmap=munmap)
        with patch.object(self.worker.ctypes, "CDLL", return_value=libc), \
                patch.object(self.worker.os, "sysconf", return_value=page):
            return self.worker.protect_memory()

    def test_fresh_and_already_protected_state_require_exact_mask_and_live_denials(self):
        for initial in (0, 1):
            with self.subTest(initial=initial):
                self.assertEqual(self.invoke(initial=initial), 1)
                self.assertEqual(self.unmapped, [100])
                self.assertIn(("prctl", 65, (1, 0, 0, 0)), self.calls)

    def test_query_failure_and_noninheriting_or_unknown_masks_refuse_before_mapping(self):
        for initial in (-1, 2, 3, 4):
            with self.subTest(initial=initial), self.assertRaises((OSError, ValueError)):
                self.invoke(initial=initial)
            self.assertFalse(any(call[0] == "mmap" for call in self.calls))

    def test_unavailable_read_write_baseline_is_not_misread_as_protection(self):
        with self.assertRaisesRegex(OSError, "baseline refused"):
            self.invoke(allocate=False)
        self.assertEqual(self.unmapped, [])

    def test_failed_baseline_protection_refuses_with_owned_page_cleanup(self):
        with self.assertRaisesRegex(OSError, "baseline protection"):
            self.invoke(baseline=-1)
        self.assertEqual(self.unmapped, [100])

    def test_failed_installation_refuses_and_cleans_its_page(self):
        with self.assertRaisesRegex(OSError, "installation refused"):
            self.invoke(install=-1)
        self.assertEqual(self.unmapped, [100])

    def test_zero_install_exit_without_exact_readback_cannot_pass(self):
        for state in (0, -1, 3):
            with self.subTest(state=state), self.assertRaisesRegex(RuntimeError, "mask was not observed"):
                self.invoke(readback=state)
            self.assertEqual(self.unmapped, [100])

    def test_execute_gain_success_or_unrelated_error_is_not_denial_evidence(self):
        for result, error in ((0, 0), (-1, errno.ENOMEM), (-1, errno.EINVAL), (-1, errno.EPERM)):
            with self.subTest(result=result, error=error), self.assertRaisesRegex(RuntimeError, "execute-gain"):
                self.invoke(change=result, change_errno=error)

    def test_unexpected_writable_executable_page_is_cleaned_before_refusal(self):
        with self.assertRaisesRegex(RuntimeError, "writable-executable"):
            self.invoke(create=True)
        self.assertEqual(self.unmapped, [200, 100])

    def test_writable_executable_failure_requires_the_exact_kernel_error(self):
        for error in (0, errno.ENOMEM, errno.EPERM, errno.ENOSYS):
            with self.subTest(error=error), self.assertRaisesRegex(RuntimeError, "writable-executable"):
                self.invoke(create_errno=error)

    def test_data_page_operation_and_final_mask_must_remain_healthy(self):
        with self.assertRaisesRegex(OSError, "compatibility"):
            self.invoke(compatible=-1)
        with self.assertRaisesRegex(RuntimeError, "final protection"):
            self.invoke(final=0)

    def test_cleanup_failure_cannot_publish_success(self):
        with self.assertRaisesRegex(OSError, "cleanup refused"):
            self.invoke(cleanup=-1)

    def test_wrong_native_architecture_pointer_width_or_page_size_refuses(self):
        with patch.object(self.worker.platform, "machine", return_value="other"):
            with self.assertRaisesRegex(ValueError, "native architecture"): self.invoke()
        original = ctypes.sizeof
        with patch.object(self.worker.ctypes, "sizeof", side_effect=lambda kind: 4 if kind is ctypes.c_void_p else original(kind)):
            with self.assertRaisesRegex(ValueError, "native architecture"): self.invoke()
        for page in (0, 3, 65537):
            with self.subTest(page=page), self.assertRaisesRegex(ValueError, "page size"):
                self.invoke(page=page)

    def test_candidate_preserves_false_authority_and_clear_memory_limits(self):
        bundle = POLICY.bundle()
        self.assertTrue(all(value is False for value in bundle["authority"].values()))
        self.assertIn("PR_SET_MDWE", " ".join(bundle["prerequisites"]))
        self.assertIn("fresh read-execute", " ".join(bundle["limits"]))


class NativeMemoryTests(unittest.TestCase):
    def native(self, mode):
        result = subprocess.run([sys.executable, "-I", str(PROBE), mode], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        proof = json.loads(result.stdout)
        self.assertTrue(proof["positive_wx_and_execute_gain_baselines"])
        self.assertEqual(len(proof["native_errno"]), 6)
        self.assertEqual(set(proof["native_errno"].values()), {errno.EACCES})
        self.assertEqual(proof["mask"], 1)
        self.assertTrue(proof["clearing_refused"])
        self.assertTrue(proof["data_read_write_remains_usable"])
        self.assertTrue(proof["new_rx_remains_allowed"])
        self.assertEqual(proof["actual_fork_wait_exit"], 0)
        self.assertEqual(proof["fork_observation"], {"mask": 1, "result": -1, "errno": 13})
        for name in ("code_bytes_executed", "kernel_enforcement_substituted", "units_activated",
                     "native_runtime_authenticated", "installation_authorized", "server_ready"):
            self.assertFalse(proof[name])
        self.record = {"actual_child_wait_exit": result.returncode, **proof}

    def test_actual_new_protection_denies_memory_routes_and_is_sticky_and_inherited(self):
        self.native("fresh")

    def test_actual_preexisting_inherited_mask_is_retained_and_challenged(self):
        self.native("inherited")


class WorkerMemoryTests(unittest.TestCase):
    setUp = admission.NativeWorkerAdmissionTests.setUp
    listener = admission.NativeWorkerAdmissionTests.listener
    integrated = admission.NativeWorkerAdmissionTests.integrated

    def refuses(self, mode, reason):
        with patch.object(admission, "PROBE", PROBE):
            self.integrated(mode=mode, expected=75)
        self.assertEqual(self.record["stderr"], "Web relay refused: " + reason + "\n")
        self.assertEqual(self.record["backend_received_bytes"], 0)
        self.assertEqual(self.record["response_bytes"], 0)
        self.record["native_delivery_model"] = True

    def test_missing_native_query_refuses_before_forwarding(self):
        self.refuses("missing", "[Errno 22] MDWE query refused")

    def test_noninheriting_mask_delivery_refuses_before_forwarding(self):
        self.refuses("no-inherit", "unsupported inherited MDWE mask")

    def test_failed_installation_delivery_refuses_before_forwarding(self):
        self.refuses("install-failure", "[Errno 1] MDWE installation refused")

    def test_zero_installation_without_mask_delivery_refuses_before_forwarding(self):
        self.refuses("readback", "MDWE protection mask was not observed")

    def test_falsely_reported_mask_is_detected_by_actual_execute_gain(self):
        self.refuses("unapplied", "MDWE execute-gain challenge failed")

    def test_unexpected_page_delivery_fails_writable_executable_challenge(self):
        self.refuses("wx-delivery", "MDWE writable-executable challenge failed")


if __name__ == "__main__":
    unittest.main()

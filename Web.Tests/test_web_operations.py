import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

import test_web_admission as admission
from test_web_isolation import POLICY


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "Web.Tests/operations_probe.py"


class OperationsContractTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("s4_operations_contract", ROOT / "Web/relay.py")
        self.worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.worker)

    def challenges(self, failure=None, result=-1, error=errno.EPERM, unavailable=None):
        self.calls, self.resolved = [], []
        names = ("fchmod", "kill", "shmget", "mq_getsetattr", "keyctl")

        def resolve(name):
            self.resolved.append(name.decode())
            return -1 if name.decode() == unavailable else names.index(name.decode()) + 100

        def syscall(number, *args):
            name = names[number.value - 100]
            self.calls.append((name, tuple(arg.value for arg in args)))
            ctypes.set_errno(error if name == failure or failure is None else errno.EPERM)
            return result if name == failure or failure is None else -1

        library = types.SimpleNamespace(seccomp_syscall_resolve_name=resolve)
        libc = types.SimpleNamespace(syscall=syscall)
        with patch.object(self.worker.ctypes, "CDLL", side_effect=[libc, library]):
            self.worker.verify_operations()

    def test_only_safe_nonmutating_challenge_arguments_are_used(self):
        self.challenges()
        self.assertEqual(self.calls, [("fchmod", (-1, 0)), ("kill", (os.getpid(), 0)),
                                      ("shmget", (0, 0, 0)), ("mq_getsetattr", (-1, 0, 0)),
                                      ("keyctl", (-1, 0, 0, 0, 0))])

    def test_each_missing_family_is_detected_before_any_later_challenge(self):
        for name in ("fchmod", "kill", "shmget", "mq_getsetattr", "keyctl"):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "failed: " + name):
                self.challenges(failure=name, result=0, error=0)
            self.assertEqual(self.calls[-1][0], name)

    def test_invalid_fd_or_argument_error_does_not_certify_filter_enforcement(self):
        for error in (errno.EBADF, errno.EINVAL, errno.ENOSYS, errno.EOPNOTSUPP, errno.EACCES, 0):
            with self.subTest(error=error), self.assertRaisesRegex(RuntimeError, "failed: fchmod"):
                self.challenges(error=error)

    def test_nonnegative_return_cannot_pass_even_with_stale_eperm(self):
        for result in (0, 1):
            with self.subTest(result=result), self.assertRaisesRegex(RuntimeError, "failed: fchmod"):
                self.challenges(result=result)

    def test_unknown_challenge_syscall_refuses_without_invoking_it(self):
        with self.assertRaisesRegex(ValueError, "unavailable: shmget"):
            self.challenges(unavailable="shmget")
        self.assertEqual([name for name, _ in self.calls], ["fchmod", "kill"])

    def test_native_library_failure_is_not_replaced_with_success(self):
        with patch.object(self.worker.ctypes, "CDLL", side_effect=OSError(errno.ENOENT, "missing library")):
            with self.assertRaises(OSError):
                self.worker.verify_operations()

    def filter(self, unknown=None, rule_failure=None):
        self.closed, self.loaded = [], []
        numbers = {name: index + 100 for index, name in enumerate(self.worker.DENIED)}

        def prctl(number, *args):
            return 1 if number == 39 else 2 if number == 21 else 0

        def resolve(name):
            return -1 if name.decode() == unknown else numbers[name.decode()]

        def add(context, action, number, count, args):
            return -errno.EINVAL if number == numbers.get(rule_failure) else 0

        def loaded(context):
            self.loaded.append(context)
            return 0

        def init(action):
            return 100

        def attr(*args):
            return 0

        def close(context):
            self.closed.append(context)

        libc = types.SimpleNamespace(prctl=prctl)
        library = types.SimpleNamespace(seccomp_init=init, seccomp_syscall_resolve_name=resolve,
                                        seccomp_rule_add_array=add, seccomp_attr_set=attr,
                                        seccomp_load=loaded, seccomp_release=close)
        with patch.object(self.worker.platform, "machine", return_value="x86_64"), \
                patch.object(self.worker.ctypes, "CDLL", side_effect=[libc, library]):
            self.worker.restrict(True)

    def test_old_library_missing_fchmodat2_refuses_and_releases_unloaded_context(self):
        with self.assertRaisesRegex(ValueError, "unknown syscall: fchmodat2"):
            self.filter(unknown="fchmodat2")
        self.assertEqual(self.closed, [100])
        self.assertEqual(self.loaded, [])

    def test_metadata_rule_failure_refuses_and_releases_unloaded_context(self):
        with self.assertRaises(OSError):
            self.filter(rule_failure="fchmodat2")
        self.assertEqual(self.closed, [100])
        self.assertEqual(self.loaded, [])

    def test_ipc_rule_failure_refuses_and_releases_unloaded_context(self):
        with self.assertRaises(OSError):
            self.filter(rule_failure="mq_getsetattr")
        self.assertEqual(self.closed, [100])
        self.assertEqual(self.loaded, [])

    def test_candidate_preserves_false_authority_and_explicit_scope(self):
        bundle = POLICY.bundle()
        self.assertTrue(all(flag is False for flag in bundle["authority"].values()))
        self.assertIn("fchmodat2", " ".join(bundle["prerequisites"]))
        self.assertIn("not complete IPC", " ".join(bundle["limits"]))


class NativeOperationsTests(unittest.TestCase):
    def native(self, mode):
        with tempfile.TemporaryDirectory(prefix="s4-operations-", dir="/dev/shm") as temporary:
            result = subprocess.run([sys.executable, "-I", str(PROBE), temporary, mode],
                                    capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stderr, b"")
            proof = json.loads(result.stdout)
            self.assertFalse(proof["ipc_objects_allocated"])
            self.assertFalse(proof["signal_delivery_performed"])
            self.assertFalse(proof["units_activated"])
            self.assertFalse(proof["installation_authorized"])
            self.assertFalse(proof["server_ready"])
            self.record = proof
            return proof

    def test_actual_metadata_signal_and_nonallocating_ipc_probes_are_denied(self):
        proof = self.native("sealed")
        self.assertEqual(len(proof["outcomes"]), 45)
        self.assertTrue(all(value == {"result": -1, "errno": errno.EPERM}
                            for value in proof["outcomes"].values()))
        self.assertEqual(len(proof["metadata_positive_baseline_names"]), 18)
        self.assertEqual(len(proof["zero_signal_baseline_names"]), 6)
        self.assertTrue(all(proof["baseline"][name] == {"result": 0, "errno": 0}
                            for name in proof["metadata_positive_baseline_names"] + proof["zero_signal_baseline_names"]))
        self.assertEqual(proof["before"], proof["after"])
        self.assertFalse(proof["landlock_only_model"])

    def test_actual_landlock_only_model_leaves_metadata_and_zero_signal_available(self):
        proof = self.native("landlock-only")
        self.assertTrue(proof["landlock_only_model"])
        self.assertEqual(len(proof["outcomes"]), 19)
        self.assertTrue(all(value == {"result": 0, "errno": 0}
                            for value in proof["outcomes"].values()))


class WorkerOperationsTests(unittest.TestCase):
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
        self.record["omission_or_resolver_delivery_model"] = True

    def test_missing_metadata_rules_are_detected_before_forwarding(self):
        self.refuses("metadata-open", "operation denial challenge failed: fchmod")

    def test_missing_signal_rules_are_detected_before_forwarding(self):
        self.refuses("signals-open", "operation denial challenge failed: kill")

    def test_missing_sysv_rules_are_detected_before_forwarding(self):
        self.refuses("sysv-open", "operation denial challenge failed: shmget")

    def test_missing_mqueue_rules_are_detected_before_forwarding(self):
        self.refuses("mqueue-open", "operation denial challenge failed: mq_getsetattr")

    def test_missing_key_rules_are_detected_before_forwarding(self):
        self.refuses("keys-open", "operation denial challenge failed: keyctl")

    def test_old_resolver_missing_fchmodat2_refuses_before_forwarding(self):
        self.refuses("old-resolver", "unknown syscall: fchmodat2")


if __name__ == "__main__":
    unittest.main()

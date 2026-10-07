import ctypes
import errno
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

import test_web_admission as admission
from test_web_isolation import POLICY


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "Web.Tests/descriptors_probe.py"


class DescriptorContractTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("s4_descriptor_contract", ROOT / "Web/relay.py")
        self.worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.worker)

    def rules(self, missing=False, failure=None):
        self.rules_observed = []

        def resolve(name):
            self.assertEqual(name, b"fcntl")
            return -1 if missing else 99

        def add(context, action, number, count, pointer):
            value = pointer._obj
            self.rules_observed.append((context, action, number, count, value.arg, value.op, value.a, value.b))
            return -errno.ENOMEM if len(self.rules_observed) == failure else 0

        lib = types.SimpleNamespace(seccomp_syscall_resolve_name=resolve, seccomp_rule_add_array=add)
        return self.worker.add_descriptor_rules(lib, 123)

    def test_exact_single_argument_rules_cover_all_but_the_two_queries(self):
        self.rules()
        self.assertEqual(self.rules_observed, [(123, 0x50001, 99, 1, 1, 2, 1, 0),
                                              (123, 0x50001, 99, 1, 1, 4, 2, 0),
                                              (123, 0x50001, 99, 1, 1, 6, 3, 0)])
        for command in [*range(1100), (1 << 32), (1 << 32) | 1, (1 << 32) | 3, (1 << 64) - 1]:
            compare = {2: lambda left, right: left < right,
                       4: lambda left, right: left == right,
                       6: lambda left, right: left > right}
            denied = any(compare[rule[5]](command, rule[6]) for rule in self.rules_observed)
            self.assertEqual(not denied, command in (1, 3))

    def test_unknown_fcntl_refuses_before_rule_publication(self):
        with self.assertRaisesRegex(ValueError, "unknown syscall: fcntl"):
            self.rules(missing=True)
        self.assertEqual(self.rules_observed, [])

    def test_each_failed_conditional_rule_refuses(self):
        for failed in (1, 2, 3):
            with self.subTest(failed=failed), self.assertRaises(OSError):
                self.rules(failure=failed)
            self.assertEqual(len(self.rules_observed), failed)

    def test_unsupported_native_width_refuses_before_rule_publication(self):
        with patch.object(self.worker.ctypes, "sizeof", return_value=4):
            with self.assertRaisesRegex(ValueError, "native ABI"):
                self.rules()
        self.assertEqual(self.rules_observed, [])

    def challenges(self, failure=None, result=-1, error=errno.EPERM, fd_flags=1, status=None):
        self.calls = []
        status = os.O_NONBLOCK if status is None else status

        def invoke(name, args):
            self.calls.append((name, args))
            if name == "fcntl" and args[0] >= 0:
                return fd_flags if args[1] == 1 else status
            ctypes.set_errno(error if failure is None or (name, args) == failure else errno.EPERM)
            return result if failure is None or (name, args) == failure else -1

        def dup(*args): return invoke("dup", args)
        def dup2(*args): return invoke("dup2", args)
        def dup3(*args): return invoke("dup3", args)
        def fcntl(*args): return invoke("fcntl", args)
        lib = types.SimpleNamespace(dup=dup, dup2=dup2, dup3=dup3, fcntl=fcntl)
        with patch.object(self.worker.ctypes, "CDLL", return_value=lib):
            self.worker.verify_descriptors((0, 8))

    def test_challenges_use_only_invalid_source_fds_and_queries(self):
        self.challenges()
        self.assertEqual(self.calls, [("dup", (-1,)), ("dup2", (-1, -1)), ("dup3", (-1, -1, 0)),
                                      ("fcntl", (-1, 0, 0)), ("fcntl", (-1, 2, 0)),
                                      ("fcntl", (-1, 4, 0)), ("fcntl", (-1, 1030, 0)),
                                      ("fcntl", (0, 1, 0)), ("fcntl", (0, 3, 0)),
                                      ("fcntl", (8, 1, 0)), ("fcntl", (8, 3, 0))])

    def test_each_ordinary_argument_error_cannot_certify_enforcement(self):
        cases = [("dup", (-1,)), ("dup2", (-1, -1)), ("dup3", (-1, -1, 0)),
                 ("fcntl", (-1, 0, 0)), ("fcntl", (-1, 2, 0)),
                 ("fcntl", (-1, 4, 0)), ("fcntl", (-1, 1030, 0))]
        for failure in cases:
            with self.subTest(failure=failure), self.assertRaisesRegex(RuntimeError, "denial challenge failed"):
                self.challenges(failure=failure, error=errno.EBADF)
            self.assertEqual(self.calls[-1], failure)

    def test_nonnegative_result_with_stale_eperm_does_not_pass(self):
        for result in (0, 1):
            with self.subTest(result=result), self.assertRaisesRegex(RuntimeError, "failed: dup$"):
                self.challenges(result=result)

    def test_wrong_errno_does_not_pass(self):
        for error in (0, errno.EBADF, errno.EINVAL, errno.EACCES, errno.ENOSYS):
            with self.subTest(error=error), self.assertRaisesRegex(RuntimeError, "failed: dup$"):
                self.challenges(error=error)

    def test_missing_or_unsupported_flag_queries_do_not_pass(self):
        for flags, status in [(-1, os.O_NONBLOCK), (2, os.O_NONBLOCK), (1, -1), (1, 0)]:
            with self.subTest(flags=flags, status=status), self.assertRaisesRegex(RuntimeError, "query/nonblocking"):
                self.challenges(fd_flags=flags, status=status)

    def test_cloexec_and_non_cloexec_channels_with_nonblocking_state_pass(self):
        for flags in (0, 1):
            with self.subTest(flags=flags):
                self.challenges(fd_flags=flags)

    def test_invalid_channel_observations_refuse_before_native_calls(self):
        for descriptors in [(), (0,), (0, 0), (0, -1), (0, True), (0, {}), (0, 1 << 32)]:
            with self.subTest(descriptors=descriptors), patch.object(self.worker.ctypes, "CDLL") as library:
                with self.assertRaises(ValueError):
                    self.worker.verify_descriptors(descriptors)
                library.assert_not_called()

    def test_missing_native_library_does_not_certify_enforcement(self):
        with patch.object(self.worker.ctypes, "CDLL", side_effect=OSError(errno.ENOENT, "missing library")):
            with self.assertRaises(OSError):
                self.worker.verify_descriptors((0, 8))

    def test_candidate_preserves_false_authority_and_descriptor_scope(self):
        bundle = POLICY.bundle()
        self.assertTrue(all(flag is False for flag in bundle["authority"].values()))
        self.assertIn("F_GETFD/F_GETFL", " ".join(bundle["prerequisites"]))
        self.assertIn("does not prohibit all descriptor creation", " ".join(bundle["limits"]))


class NativeDescriptorTests(unittest.TestCase):
    def native(self, mode):
        result = subprocess.run([sys.executable, "-I", str(PROBE), mode], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        proof = json.loads(result.stdout)
        self.assertEqual(len(proof["actual_positive_baselines"]), 11)
        self.assertEqual(len(proof["actual_outcomes"]), 11)
        self.assertEqual(proof["before"], proof["after"])
        self.assertTrue(proof["epoll_read_write_usable"])
        for flag in ("units_activated", "native_runtime_authenticated", "installation_authorized", "server_ready"):
            self.assertFalse(proof[flag])
        self.record = {"actual_child_wait_exit": result.returncode, **proof}
        return proof

    def test_actual_native_duplication_mutation_and_high_bit_aliases_are_denied(self):
        proof = self.native("sealed")
        self.assertFalse(proof["descriptor_control_omission_model"])
        self.assertTrue(all(value == {"result": -1, "errno": errno.EPERM} for value in proof["actual_outcomes"].values()))

    def test_descriptor_omission_model_with_actual_landlock_retains_descriptor_operations(self):
        proof = self.native("landlock-only-model")
        self.assertTrue(proof["descriptor_control_omission_model"])
        self.assertTrue(all(value["result"] >= 0 and value["errno"] == 0 for value in proof["actual_outcomes"].values()))


class WorkerDescriptorTests(unittest.TestCase):
    setUp = admission.NativeWorkerAdmissionTests.setUp
    listener = admission.NativeWorkerAdmissionTests.listener
    integrated = admission.NativeWorkerAdmissionTests.integrated

    def refuses(self, mode, reason):
        with patch.object(admission, "PROBE", PROBE):
            self.integrated(mode=mode, expected=75)
        self.assertEqual(self.record["stderr"], "Web relay refused: " + reason + "\n")
        self.assertEqual(self.record["backend_received_bytes"], 0)
        self.assertEqual(self.record["response_bytes"], 0)
        self.record["descriptor_omission_or_delivery_model"] = True

    def test_missing_dup_rule_refuses_before_forwarding(self):
        self.refuses("dup-open", "descriptor denial challenge failed: dup")

    def test_missing_dup2_rule_refuses_before_forwarding(self):
        self.refuses("dup2-open", "descriptor denial challenge failed: dup2")

    def test_missing_dup3_rule_refuses_before_forwarding(self):
        self.refuses("dup3-open", "descriptor denial challenge failed: dup3")

    def test_missing_low_fcntl_rule_refuses_before_forwarding(self):
        self.refuses("fcntl-low-open", "descriptor denial challenge failed: fcntl-dupfd")

    def test_missing_middle_fcntl_rule_refuses_before_forwarding(self):
        self.refuses("fcntl-mid-open", "descriptor denial challenge failed: fcntl-setfd")

    def test_missing_high_fcntl_rule_refuses_before_forwarding(self):
        self.refuses("fcntl-high-open", "descriptor denial challenge failed: fcntl-setfl")

    def test_missing_fcntl_resolver_refuses_before_forwarding(self):
        self.refuses("missing-fcntl", "unknown syscall: fcntl")

    def test_actual_blocking_channel_observation_refuses_before_forwarding(self):
        self.refuses("blocking-channel", "descriptor query/nonblocking state refused")


if __name__ == "__main__":
    unittest.main()

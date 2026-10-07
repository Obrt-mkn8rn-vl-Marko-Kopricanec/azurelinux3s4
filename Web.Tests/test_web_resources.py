import ctypes
import errno
import importlib.util
import json
from pathlib import Path
import resource
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

import test_web_admission as admission
from test_web_isolation import POLICY


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "Web.Tests/resource_probe.py"


class ResourceContractTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("s4_resource_contract", ROOT / "Web/relay.py")
        self.worker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.worker)

    def budget(self, before, after, ceiling=16, retained=()):
        with patch.object(self.worker.resource, "getrlimit", side_effect=[before, after]), \
                patch.object(self.worker.resource, "setrlimit") as apply:
            result = self.worker.bound_descriptors(ceiling, retained)
            self.applied = apply.call_args
            return result

    def test_default_and_unlimited_startup_limits_are_clamped(self):
        for observed in ((1048576, 1048576), (resource.RLIM_INFINITY,) * 2):
            with self.subTest(observed=observed):
                self.assertEqual(self.budget(observed, (256, 256), 256), (256, 256))
                self.assertEqual(self.applied.args, (resource.RLIMIT_NOFILE, (256, 256)))

    def test_stronger_soft_and_hard_limits_are_never_raised(self):
        for observed, expected in [((8, 12), (8, 12)), ((8, 100), (8, 16)), ((100, 100), (16, 16))]:
            with self.subTest(observed=observed):
                self.assertEqual(self.budget(observed, expected), expected)

    def test_matching_readback_is_required_even_for_already_bounded_values(self):
        for observed in ((16, 16), (1024, 1024)):
            with self.subTest(observed=observed), self.assertRaisesRegex(RuntimeError, "was not observed"):
                self.budget(observed, (15, 16))

    def test_retained_high_descriptor_refuses_before_limit_mutation(self):
        with patch.object(self.worker.resource, "getrlimit", return_value=(256, 256)), \
                patch.object(self.worker.resource, "setrlimit") as apply:
            with self.assertRaisesRegex(ValueError, "retained descriptor exceeds"):
                self.worker.bound_descriptors(16, (0, 1, 2, 32))
            apply.assert_not_called()

    def test_invalid_observations_refuse_before_mutation(self):
        for observed in [(20, 16), (True, 16), (-2, 16), (16,), [16, 16], (0, 1 << 64)]:
            with self.subTest(observed=observed), patch.object(self.worker.resource, "getrlimit", return_value=observed), \
                    patch.object(self.worker.resource, "setrlimit") as apply:
                with self.assertRaises(ValueError): self.worker.bound_descriptors(16)
                apply.assert_not_called()

    def test_unknown_budget_or_invalid_retained_delivery_refuses(self):
        for ceiling, retained in [(32, ()), (16, (-1,)), (16, (True,)), (16, ({},))]:
            with self.subTest(ceiling=ceiling, retained=retained):
                with self.assertRaises(ValueError): self.worker.bound_descriptors(ceiling, retained)

    def test_setter_failure_is_not_replaced_by_readback_success(self):
        with patch.object(self.worker.resource, "getrlimit", return_value=(1024, 1024)), \
                patch.object(self.worker.resource, "setrlimit", side_effect=OSError(errno.EPERM, "refused")):
            with self.assertRaises(OSError): self.worker.bound_descriptors(16)

    def test_unsupported_abi_refuses_without_setting_limits(self):
        with patch.object(self.worker.ctypes, "sizeof", return_value=4), \
                patch.object(self.worker.resource, "setrlimit") as apply:
            with self.assertRaisesRegex(ValueError, "native ABI"): self.worker.bound_descriptors(16)
            apply.assert_not_called()

    def rule(self, number=100, failure=0):
        self.rule_data = []
        def add(context, action, syscall, count, pointer):
            item = pointer._obj
            self.rule_data.append((context, action, syscall, count, item.arg, item.op, item.a, item.b))
            return failure
        def resolve(name):
            self.assertEqual(name, b"prlimit64")
            return number
        library = types.SimpleNamespace(seccomp_syscall_resolve_name=resolve, seccomp_rule_add_array=add)
        self.worker.add_resource_rules(library, 123)

    def test_update_rule_compares_new_pointer_presence_only(self):
        self.rule()
        self.assertEqual(self.rule_data, [(123, 0x50001, 100, 1, 2, 1, 0, 0)])

    def test_unknown_update_syscall_and_failed_rule_refuse(self):
        with self.assertRaisesRegex(ValueError, "prlimit64"): self.rule(number=-1)
        self.assertEqual(self.rule_data, [])
        with self.assertRaises(OSError): self.rule(failure=-errno.ENOMEM)

    def verify(self, python=(16, 16), native=(16, 16), query_result=0, final_python=(16, 16),
               final_native=(16, 16), missing=None, failed=None, result=-1, error=errno.EPERM):
        self.probes = []
        query_calls = []
        def query(pid, number, new, old):
            query_calls.append(None)
            self.assertEqual((pid, number, new), (0, 7, None))
            old._obj.current, old._obj.maximum = native if len(query_calls) == 1 else final_native
            return query_result
        def syscall(number, *arguments):
            name = {100: "setrlimit", 101: "prlimit64"}[number.value]
            self.probes.append((name, arguments))
            ctypes.set_errno(error if name == failed or failed is None else errno.EPERM)
            return result if name == failed or failed is None else -1
        def resolve(name): return -1 if name.decode() == missing else {b"setrlimit": 100, b"prlimit64": 101}[name]
        libc = types.SimpleNamespace(prlimit64=query, syscall=syscall)
        lib = types.SimpleNamespace(seccomp_syscall_resolve_name=resolve)
        with patch.object(self.worker.resource, "getrlimit", side_effect=[python, final_python]), \
                patch.object(self.worker, "native_resource_api", return_value=libc), \
                patch.object(self.worker.ctypes, "CDLL", return_value=lib):
            self.worker.verify_resource_limits((16, 16))

    def test_raw_invalid_resource_witnesses_cannot_change_limits(self):
        self.verify()
        self.assertEqual([item[0] for item in self.probes], ["setrlimit", "prlimit64"])
        first, second = [item[1] for item in self.probes]
        self.assertEqual(first[0].value, -1)
        self.assertEqual((second[0].value, second[1].value, second[3].value), (0, -1, None))
        self.assertEqual((first[1]._obj.current, first[1]._obj.maximum), (0, 0))

    def test_python_query_disagreement_refuses_before_native_work(self):
        with self.assertRaisesRegex(RuntimeError, "read-back refused"): self.verify(python=(256, 256))
        self.assertEqual(self.probes, [])

    def test_native_query_failure_or_disagreement_refuses_before_challenges(self):
        for native, result in [((16, 16), -1), ((15, 16), 0), ((16, 32), 0)]:
            with self.subTest(native=native, result=result), self.assertRaisesRegex(RuntimeError, "native descriptor"):
                self.verify(native=native, query_result=result)
            self.assertEqual(self.probes, [])

    def test_each_missing_setter_rule_is_detected_without_mutating_any_resource(self):
        for name in ("setrlimit", "prlimit64"):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "failed: " + name):
                self.verify(failed=name, error=errno.EINVAL)
            self.assertEqual(self.probes[-1][0], name)

    def test_nonnegative_or_wrong_errno_cannot_certify_setter_denial(self):
        for result, error in [(0, errno.EPERM), (-1, 0), (-1, errno.EINVAL), (-1, errno.EFAULT), (-1, errno.ENOSYS)]:
            with self.subTest(result=result, error=error), self.assertRaisesRegex(RuntimeError, "setter challenge"):
                self.verify(result=result, error=error)

    def test_unknown_raw_setter_syscall_refuses_without_executing_it(self):
        with self.assertRaisesRegex(ValueError, "unknown resource syscall: setrlimit"):
            self.verify(missing="setrlimit")
        self.assertEqual(self.probes, [])

    def test_post_challenge_budget_change_cannot_publish_success(self):
        for changes in ({"final_python": (15, 16)}, {"final_native": (15, 16)}):
            with self.subTest(changes=changes), self.assertRaisesRegex(RuntimeError, "changed during"):
                self.verify(**changes)

    def test_invalid_expected_budget_refuses_before_native_work(self):
        for expected in ((16, 32), (0, 16), (17, 16), (True, 16), [16, 16]):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                self.worker.verify_resource_limits(expected)

    def test_missing_native_interfaces_are_normalized_to_refusal(self):
        with patch.object(self.worker.ctypes, "CDLL", return_value=object()):
            with self.assertRaisesRegex(ValueError, "interfaces unavailable"):
                self.worker.native_resource_api()

    def test_candidate_preserves_false_authority_and_resource_scope(self):
        bundle = POLICY.bundle()
        self.assertTrue(all(flag is False for flag in bundle["authority"].values()))
        self.assertIn("RLIMIT_NOFILE", " ".join(bundle["prerequisites"]))
        self.assertIn("does not reserve slots", " ".join(bundle["limits"]))


class NativeResourceTests(unittest.TestCase):
    def native(self, mode):
        result = subprocess.run([sys.executable, "-I", str(PROBE), mode], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        proof = json.loads(result.stdout)
        expected = [12, 12] if mode == "stronger" else [16, 16]
        self.assertEqual(proof["forward_budget"], expected)
        self.assertEqual(proof["startup_budget"], [12, 12] if mode == "stronger" else [256, 256])
        self.assertEqual(proof["hard_raise_errno_before_filter"], errno.EPERM)
        self.assertEqual(proof["exhaustion_errno"], errno.EMFILE)
        self.assertLess(proof["replacement_fd_after_release"], expected[0])
        self.assertEqual(proof["held_identity_before"], proof["held_identity_after"])
        self.assertTrue(proof["held_epoll_read_write_usable_at_exhaustion"])
        self.assertTrue(proof["queries_and_invalid_resource_witnesses_at_exhaustion_passed"])
        for flag in ("kernel_or_limit_enforcement_substituted", "units_activated", "native_runtime_authenticated",
                     "installation_authorized", "server_ready"):
            self.assertFalse(proof[flag])
        self.record = {"actual_child_wait_exit": result.returncode, **proof}

    def test_actual_hard_limit_and_exhaustion_preserve_admitted_channel_resources(self):
        self.native("native")

    def test_actual_stronger_inherited_limit_is_preserved_and_enforced(self):
        self.native("stronger")


class WorkerResourceTests(unittest.TestCase):
    setUp = admission.NativeWorkerAdmissionTests.setUp
    listener = admission.NativeWorkerAdmissionTests.listener
    integrated = admission.NativeWorkerAdmissionTests.integrated

    def refuses(self, mode, reason):
        with patch.object(admission, "PROBE", PROBE):
            self.integrated(mode=mode, expected=75)
        self.assertEqual(self.record["stderr"], "Web relay refused: " + reason + "\n")
        self.assertEqual(self.record["backend_received_bytes"], 0)
        self.assertEqual(self.record["response_bytes"], 0)
        self.record["resource_omission_or_delivery_model"] = True

    def test_missing_raw_setter_rule_refuses_before_forwarding(self):
        self.refuses("setter-open", "resource setter challenge failed: setrlimit")

    def test_missing_update_rule_refuses_before_forwarding(self):
        self.refuses("update-open", "resource setter challenge failed: prlimit64")

    def test_false_final_limit_receipt_does_not_replace_native_readback(self):
        self.refuses("unapplied-final", "descriptor resource read-back refused")

    def test_false_native_query_delivery_refuses_before_forwarding(self):
        self.refuses("native-query-delivery", "native descriptor resource query refused")

    def test_missing_resource_syscall_resolution_refuses_before_forwarding(self):
        self.refuses("missing-prlimit", "unknown syscall: prlimit64")

    def test_actual_high_held_channel_refuses_instead_of_surviving_above_budget(self):
        self.refuses("retained-high", "retained descriptor exceeds resource budget")


if __name__ == "__main__":
    unittest.main()

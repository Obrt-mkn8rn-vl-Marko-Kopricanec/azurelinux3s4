import copy
import ctypes as C
import hashlib
import json
import os
import struct
import unittest
from unittest.mock import patch

import test_update_header_inputs as headers
import test_update_trigger_sources as sources
import test_update_triggers as triggers


class HeaderMatchNativeTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    def setUp(self):
        self.lib.headerModelReset()
        self.lib.headerMatchModelReset.restype = None; self.lib.headerMatchModelReset.argtypes = ()
        self.lib.headerMatchModelReset()
        for name in ('headerMatchModelCalls', 'dependencyModelAllocated', 'dependencyModelFreed'):
            getattr(self.lib, name).restype = C.c_uint; getattr(self.lib, name).argtypes = ()
        self.lib.dependencyModelReset.restype = None; self.lib.dependencyModelReset.argtypes = ()
        self.lib.dependencyModelReset()

    def query(self, left=('probe', '1-1', 8), right=('probe', '1-1', 65536 | 8)):
        return self.namespace['header_match_native']()(*self.namespace['header_match_probe'](left), right)

    def retired(self):
        self.assertEqual(self.lib.headerModelImported(), self.lib.headerModelRetired())
        self.assertEqual(self.lib.headerModelDsCreated(), self.lib.headerModelDsRetired())
        self.assertEqual(self.lib.dependencyModelAllocated(), self.lib.dependencyModelFreed())

    def test_actual_query_repeats_and_retires_header_provides_and_single_request(self):
        self.assertEqual(self.query(), 1); self.retired()
        self.assertEqual((self.lib.headerModelImported(), self.lib.headerModelDsCreated(), self.lib.dependencyModelAllocated(), self.lib.headerMatchModelCalls()), (1, 1, 1, 2))

    def test_participation_probe_has_complete_immutable_region_and_trailer(self):
        material, arrays = self.namespace['header_match_probe'](('probe', '1-1', 8))
        count, size = struct.unpack_from('>II', material)
        self.assertEqual(count, 4); self.assertEqual(len(material), 8 + 16 * count + size)
        tag, kind, offset, length = struct.unpack_from('>IIII', material, 8)
        self.assertEqual((tag, kind, length), (63, 7, 16)); self.assertEqual(offset + length, size)
        self.assertEqual(struct.unpack_from('>IIiI', material, 8 + 16 * count + offset), (63, 7, -16 * count, 16))
        self.assertEqual([struct.unpack_from('>IIII', material, 8 + 16 * index)[0] for index in range(count)], [63, 1047, 1112, 1113])
        self.assertEqual(self.namespace['audit_header'](material)['header_sha256'], hashlib.sha256(material).hexdigest())
        self.assertEqual(arrays[0][1][0]['flags'], 8)

    def test_each_direction_and_self_participation_vector_matches_its_expected_value(self):
        for left, right, expected in self.namespace['PROVIDER_PROBES']:
            for a, b, value in ((left, right, expected), (right, left, expected), (left, left, 1), (right, right, 1)):
                with self.subTest(left=a, right=b): self.assertEqual(self.query(a, b), value)
        self.retired(); self.assertEqual(self.lib.headerMatchModelCalls(), 200)

    def test_different_name_does_not_match_even_without_version_restrictions(self):
        self.assertEqual(self.query(('probe', '', 0), ('other', '', 0)), 0); self.retired()

    def test_later_duplicate_unversioned_provide_matches_after_first_versioned_negative(self):
        material, arrays = headers.HeaderInputNativeTests.fixture(self)
        result = self.namespace['header_match_native']()(material, arrays, ('probe', '2-1', 65536 | 8))
        self.assertEqual(result, 1); self.retired()

    def test_known_header_caller_and_dependency_request_aliases_refuse_before_ownership(self):
        for fault in ('request-header', 'request-caller', 'request-dependency', 'request-name', 'request-evr'):
            self.setUp()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_HEADER_MATCH_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'aliases a borrowed allocation'):
                self.query()
            self.retired(); self.assertEqual(self.lib.dependencyModelAllocated(), 0)
            self.assertEqual(self.lib.headerMatchModelCalls(), 0)

    def test_request_allocation_failure_retires_already_acquired_header_and_provides(self):
        with patch.dict(os.environ, {'S4_HEADER_MATCH_MODEL_FAULT': 'request-allocate'}), self.assertRaisesRegex(ValueError, 'request allocation failed'): self.query()
        self.retired(); self.assertEqual(self.lib.headerModelImported(), 1)

    def test_owned_name_and_evr_arguments_cannot_be_changed_by_single_allocation(self):
        for fault in ('argument-name-changed', 'argument-evr-changed'):
            self.setUp()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_HEADER_MATCH_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'caller argument changed'):
                self.query()
            self.retired()

    def test_invalid_and_changing_query_results_refuse_after_checked_retirement(self):
        for fault in ('invalid', 'alternating'):
            self.setUp()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_HEADER_MATCH_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'unsupported or changes'): self.query()
            self.retired()

    def test_query_cannot_mutate_the_complete_owned_request_receipt(self):
        with patch.dict(os.environ, {'S4_HEADER_MATCH_MODEL_FAULT': 'request-changed'}), self.assertRaisesRegex(ValueError, 'request receipt differs'): self.query()
        self.retired()

    def test_borrowed_header_change_is_caught_by_accepted_post_callback_readback(self):
        with patch.dict(os.environ, {'S4_HEADER_MATCH_MODEL_FAULT': 'header-changed'}), self.assertRaisesRegex(ValueError, 'receipt|export'): self.query()
        self.retired()

    def test_request_cleanup_refusal_does_not_prevent_other_owned_retirements(self):
        with patch.dict(os.environ, {'S4_DEPENDENCY_MODEL_FAULT': 'free'}), self.assertRaisesRegex(ValueError, 'request cleanup failed'): self.query()
        self.retired()

    def test_missing_public_match_symbol_refuses_before_header_import(self):
        original = self.namespace['C'].CDLL
        class Hidden:
            def __init__(self, lib): self.lib = lib
            def __getattr__(self, name):
                if name == 'rpmdsAnyMatchesDep': raise AttributeError(name)
                return getattr(self.lib, name)
        with patch.object(self.namespace['C'], 'CDLL', staticmethod(lambda name, **opts: Hidden(original(name, **opts)) if name else original(name, **opts))), self.assertRaisesRegex(ValueError, 'symbol is missing'):
            self.query()
        self.assertEqual(self.lib.headerModelImported(), 0)


class HeaderMatchProofTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    make_proof = headers.HeaderInputProofTests.make_proof
    make_proof_base = sources.TriggerSourceProofTests.make_proof
    proof = triggers.TriggerProofTests.proof
    rebind = headers.HeaderInputProofTests.rebind
    def observe(self, proof, factory=None):
        return self.namespace['header_match_observe'](self.namespace['trigger_observe'](proof),
            factory or self.namespace['header_match_native'], lambda: self.native_compare)['header_match_observation']

    def test_same_captured_source_header_query_agrees_and_does_not_select_a_phase(self):
        proof = self.make_proof(); record = self.observe(proof)
        self.assertEqual(record['pairs_queried'], 1); self.assertTrue(record['pairs'][0]['captured_header_dependency_match'])
        self.assertEqual(record['pairs'][0]['source_owner']['header_sha256'], proof['effects']['installed_header_exports'][0]['header_sha256'])
        self.assertEqual(record['native_query_calls'], 202); self.assertTrue(record['native_participation_checked'])
        self.assertFalse(record['trigger_phase_selected']); self.assertFalse(record['trigger_eligibility_complete'])

    def test_missing_raw_header_refuses_even_with_stale_match_receipt(self):
        proof = self.make_proof(); del proof['effects']['installed_header_exports']
        proof['header_match_observation'] = {'native_header_queries_observed': True}
        with self.assertRaises(KeyError): self.observe(proof, lambda: self.fail('factory before complete current inputs'))

    def test_no_ordinary_conditions_perform_no_match_factory_or_participation(self):
        record = self.observe(self.proof(), lambda: self.fail('no conditions must not load factory'))
        self.assertEqual(record['pairs_queried'], 0); self.assertEqual(record['native_query_calls'], 0)
        self.assertFalse(record['native_header_queries_observed']); self.assertFalse(record['native_participation_checked'])

    def test_nonmatching_package_name_loads_no_new_match_factory(self):
        proof = self.make_proof(); proof['effects']['installed_script_owners'][0].update(name='other', nevra='other-0-1.x86_64')
        self.rebind(proof)
        proof['effects']['installed_header_exports'][0].update(name='other', nevra='other-0-1.x86_64')
        record = self.observe(proof, lambda: self.fail('capability equality does not bypass package NAME'))
        self.assertEqual(record['pairs_queried'], 0); self.assertFalse(record['native_header_queries_observed'])

    def test_pair_and_reimport_byte_admission_precede_new_native_factory(self):
        for name in ('HEADER_MATCH_PAIR_LIMIT', 'HEADER_MATCH_BYTES', 'HEADER_MATCH_ROWS'):
            old = self.namespace[name]; self.namespace[name] = 0
            try:
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'pairs/bytes exceed|repeated rows exceed'):
                    self.observe(self.make_proof(), lambda: self.fail('factory before pair/byte bound'))
            finally: self.namespace[name] = old

    def test_constant_positive_zero_and_nonboolean_control_deliveries_refuse(self):
        for value in (0, 1, True, 42):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, 'participation|unsupported'):
                self.observe(self.make_proof(), lambda: lambda *args: value)

    def test_later_actual_query_disagreement_withholds_complete_match_receipt(self):
        actual = self.namespace['header_match_native'](); calls = 0
        def changed(*args):
            nonlocal calls
            calls += 1
            result = actual(*args)
            return result if calls <= 100 else 1 - result
        proof = self.make_proof()
        with self.assertRaisesRegex(ValueError, 'differs from complete declared Provides'): self.observe(proof, lambda: changed)
        self.assertEqual(calls, 101); self.assertNotIn('header_match_observation', proof)

    def test_output_commitment_and_all_fifteen_authority_flags_remain_false(self):
        record = self.observe(self.make_proof())
        encoded = json.dumps(record['pairs'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((record['pairs_bytes'], record['pairs_sha256']), (len(encoded), hashlib.sha256(encoded).hexdigest()))
        self.assertEqual(sum(value is False for value in record.values()), 15)

    def test_same_named_source_without_provides_has_an_actual_negative_query(self):
        proof = self.make_proof_base()
        material = headers.effects.exported(headers.providers.conditions.entries(names=(b'fixture', b'absent'), versions=(b'', b''), masks=(0, 0)))
        owner = proof['effects']['installed_script_owners'][0]
        self.assertEqual(hashlib.sha256(material).hexdigest(), owner['header_sha256'])
        proof['effects']['installed_header_exports'] = [{**proof['effects']['installed_versions']['entries'][0], 'header_export_hex': material.hex()}]
        proof['effects']['incoming'][0]['header_export_hex'] = headers.effects.exported([(1023, 6, [b'body'])]).hex()
        record = self.observe(proof); self.assertEqual(record['pairs_queried'], 1)
        self.assertFalse(record['pairs'][0]['captured_header_dependency_match']); self.assertTrue(record['native_participation_checked'])

    def test_nonboolean_actual_result_refuses_after_good_participation(self):
        actual = self.namespace['header_match_native'](); calls = 0
        def changed(*args):
            nonlocal calls
            calls += 1
            return actual(*args) if calls <= 100 else True
        proof = self.make_proof()
        with self.assertRaisesRegex(ValueError, 'query result is unsupported'): self.observe(proof, lambda: changed)
        self.assertNotIn('header_match_observation', proof)


class HeaderMatchPrivateTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputPrivateTests.setUpClass.__func__)
    setUp = headers.HeaderInputPrivateTests.setUp
    make_proof = headers.HeaderInputProofTests.make_proof
    make_proof_base = sources.TriggerSourceProofTests.make_proof
    proof = triggers.TriggerProofTests.proof
    rebind = headers.HeaderInputProofTests.rebind
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_actual_private_capture_binds_all_nine_original_byte_hashes(self):
        before = self.path.read_bytes(); proof = json.loads(self.run_guard().stdout)
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], hashlib.sha256(before).hexdigest())
        self.assertEqual(proof['header_match_observation']['pairs_queried'], 1)
        self.assertEqual(self.path.read_bytes(), before)

    def test_bad_native_participation_on_private_path_defers_with_zero_json(self):
        before = self.path.read_bytes()
        with patch.dict(os.environ, {'S4_HEADER_MATCH_MODEL_FAULT': 'positive'}): result = self.run_guard(expected=75)
        self.assertIn('Header match native participation control failed', result.stderr)
        self.assertEqual(result.stdout, ''); self.assertEqual(self.path.read_bytes(), before)


class HeaderMatchPipelineTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputPipelineTests.setUpClass.__func__)
    command = headers.HeaderInputPipelineTests.command
    configure = headers.HeaderInputPipelineTests.configure
    calls = headers.HeaderInputPipelineTests.calls
    setUp = headers.HeaderInputPipelineTests.setUp
    header = headers.HeaderInputPipelineTests.header
    prepare = headers.HeaderInputPipelineTests.prepare
    native_calls = headers.HeaderInputPipelineTests.native_calls
    shell = headers.HeaderInputPipelineTests.shell

    def test_fresh_test_actual_source_header_match_binds_same_owner_and_capture(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['header_match_observation']; self.assertEqual(receipt['pairs_queried'], 2)
        self.assertEqual([(row['source_owner']['kind'], row['captured_header_dependency_match']) for row in receipt['pairs']], [('installed', False), ('incoming', True)])
        self.assertEqual(receipt['native_query_calls'], 204)
        raw = copy.deepcopy(proof)
        for name in sources.RECEIPTS: raw.pop(name)
        digest = hashlib.sha256((json.dumps(raw, sort_keys=True) + '\n').encode()).hexdigest()
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], digest)
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
                       'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
                       'native_test_seen': True, 'ordinary_cleanup_verified': True, 'finite_model_not_vendor_rpm': True}

    def test_match_participation_fault_refuses_after_fresh_test_without_output(self):
        self.prepare(condition_ordinary=True, provider_positive=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes()
        result = self.shell('export S4_HEADER_MATCH_MODEL_FAULT=positive; s4_check_update_effects', expected=75)
        self.assertIn('Header match native participation control failed', result.stderr); self.assertEqual(result.stdout, '')
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stderr': result.stderr, 'stdout': result.stdout, 'native_test_seen': True,
                       'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
                       'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
                       'ordinary_cleanup_verified': True, 'finite_model_not_vendor_rpm': True}


if __name__ == '__main__': unittest.main()

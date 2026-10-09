import copy
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_update_baselines as baselines
import test_update_effects as effects
import test_update_header_inputs as headers
import test_update_header_matches as matches
import test_update_trigger_sources as sources
import test_update_triggers as triggers


class TriggerIteratorPlanTests(unittest.TestCase):
    setUpClass = classmethod(baselines.InstalledVersionInventoryTests.setUpClass.__func__)
    observations = staticmethod(baselines.InstalledVersionInventoryTests.observations)
    baseline = baselines.InstalledVersionInventoryTests.baseline

    def plan(self):
        values = self.observations()
        return self.namespace['trigger_iterator_plan'](values, self.baseline(values), [{'name': 'new', 'file': 'packages/0.rpm'}])

    def receipt(self, edit=None):
        inventory, rows = self.plan()
        sample = [{'count_start': row['inventory_count'], 'count_end': row['inventory_count'],
                   'order': row['installed_instances'].copy(), 'iterator_present': bool(row['inventory_count'])} for row in rows]
        after = copy.deepcopy(sample)
        if edit: edit(after)
        return self.namespace['trigger_iterator_receipt'](inventory, rows, sample, after)

    def test_complete_inventory_groups_scriptless_keys_multiple_kernel_instances_and_zero_incoming(self):
        inventory, rows = self.plan()
        self.assertEqual([(row['name'], row['installed_instances']) for row in rows],
                         [('gpg-pubkey', [3]), ('kernel', [9, 12]), ('new', [])])
        self.assertEqual(inventory['headers'], 3)

    def test_total_export_admission_precedes_native_work(self):
        with patch.dict(self.namespace, TRIGGER_ITERATOR_EXPORT_BYTES=0), self.assertRaisesRegex(ValueError, 'export work'):
            self.plan()

    def test_both_native_orders_are_retained_without_assuming_equal_iteration_order(self):
        receipt = self.receipt(lambda sample: sample[1]['order'].reverse())
        self.assertEqual(receipt['rows'][1]['before']['order'], [9, 12])
        self.assertEqual(receipt['rows'][1]['after']['order'], [12, 9])
        encoded = json.dumps(receipt['rows'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((receipt['rows_bytes'], receipt['rows_sha256']), (len(encoded), hashlib.sha256(encoded).hexdigest()))

    def test_missing_duplicate_foreign_bool_and_wrong_terminal_count_withhold_receipt(self):
        for edit in (lambda s: s.pop(), lambda s: s[1].update(order=[9, 9]), lambda s: s[1].update(order=[9, 99]),
                     lambda s: s[0].update(order=[True]), lambda s: s[0].update(count_end=True),
                     lambda s: s[1].update(count_end=1), lambda s: s[1].update(iterator_present=False)):
            with self.subTest(edit=edit), self.assertRaises(ValueError): self.receipt(edit)

    def test_nonnull_empty_iterator_is_distinct_from_null_zero_lookup(self):
        result = self.receipt(lambda s: s[2].update(iterator_present=True))
        self.assertFalse(result['rows'][2]['before']['iterator_present'])
        self.assertTrue(result['rows'][2]['after']['iterator_present'])
        self.assertEqual(result['owned_iterator_retirements'], 5)

    def test_empty_installed_inventory_refuses_without_changing_accepted_inventory_admission(self):
        baseline = {'headers': 0, 'sha256': hashlib.sha256(b'[]').hexdigest()}
        with self.assertRaisesRegex(ValueError, 'baseline is missing'):
            self.namespace['trigger_iterator_plan']({}, baseline, [])
        result = self.receipt()
        for name in self.namespace['TRIGGER_ITERATOR_AUTHORITIES']: self.assertIs(result[name], False)

    def test_serialized_receipt_cap_refuses_complete_result(self):
        with patch.dict(self.namespace, TRIGGER_ITERATOR_BYTES=0), self.assertRaisesRegex(ValueError, 'serialization'):
            self.receipt()


class TriggerIteratorNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        directory = tempfile.TemporaryDirectory(prefix='s4-name-iterator-model-', dir=Path.home() / '.cache')
        cls.addClassCleanup(directory.cleanup); cls.library = Path(directory.name) / 'iterators.so'
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.library)],
                       input=effects.LIBRARY, text=True, capture_output=True, check=True)
        cls.lib = C.CDLL(str(cls.library)); cls.namespace = {'__name__': 'fixture'}
        exec(compile(triggers.emitted(), '<actual-name-iterator-library>', 'exec'), cls.namespace)
        cls.lib.rpmtsCreate.restype = C.c_void_p; cls.lib.rpmtsCreate.argtypes = ()
        cls.lib.rpmtsFree.restype = C.c_void_p; cls.lib.rpmtsFree.argtypes = (C.c_void_p,)
        for name in ('Acquired', 'Retired', 'NullFrees'):
            function = getattr(cls.lib, 'triggerIteratorModel' + name); function.restype = C.c_uint; function.argtypes = ()
        cls.lib.triggerIteratorModelReset.restype = None; cls.lib.triggerIteratorModelReset.argtypes = ()
        cls.libc = C.CDLL(None); cls.libc.free.restype = None; cls.libc.free.argtypes = (C.c_void_p,)

    def setUp(self):
        self.lib.triggerIteratorModelReset(); self.api = self.namespace['trigger_iterator_bind'](self.lib)
        self.transaction = self.lib.rpmtsCreate(); self.addCleanup(lambda: self.assertIsNone(self.lib.rpmtsFree(self.transaction)))
        scan = self.lib.rpmtsCreate()
        try:
            header = self.api['rpmdbNextIterator'](scan); size = C.c_uint()
            material = self.api['headerExport'](header, C.byref(size))
            try: data = C.string_at(material, size.value)
            finally: self.libc.free(material)
        finally: self.assertIsNone(self.lib.rpmtsFree(scan))
        owner = {'instance': 1, 'name': 'userland', 'nevra': 'userland-0-1.x86_64',
                 'header_bytes': len(data), 'header_sha256': hashlib.sha256(data).hexdigest()}
        baseline = {'headers': 1, 'sha256': hashlib.sha256(json.dumps([(1, owner['header_sha256'])], separators=(',', ':')).encode()).hexdigest()}
        self.inventory, self.rows = self.namespace['trigger_iterator_plan']({1: owner}, baseline,
                [{'name': 'new', 'file': 'packages/0.rpm'}])
        self.frees = []
        def free(value): self.frees.append(value); self.libc.free(value)
        self.free = free

    def sample(self):
        return self.namespace['trigger_iterator_sample'](self.api, self.free, self.transaction, self.inventory, self.rows)

    def retired(self, count):
        self.assertEqual(self.lib.triggerIteratorModelAcquired(), count)
        self.assertEqual(self.lib.triggerIteratorModelRetired(), count)

    def test_actual_name_lookup_count_traversal_export_and_null_zero_lookup_match_complete_inventory(self):
        database, sample = self.sample(); second, after = self.sample()
        self.assertEqual(database, second); self.assertNotEqual(database, self.transaction)
        self.assertEqual(sample, after); self.assertEqual(sample[0]['order'], [])
        self.assertEqual(sample[1]['order'], [1]); self.assertEqual(len(self.frees), 2); self.retired(2)
        self.record = {'before': sample, 'after': after, 'owned_iterators_acquired': 2, 'owned_iterators_retired': 2,
                       'actual_export_frees': 2, 'caller_ownership_transferred': False, 'package_test_performed': False}

    def test_bad_null_participation_precedes_iterator_acquisition(self):
        with patch.dict(os.environ, iterator_null_count='1'), self.assertRaisesRegex(ValueError, 'NULL participation'): self.sample()
        self.retired(0); self.assertEqual(self.frees, [])

    def test_mismatch_early_end_and_foreign_instance_retire_owned_iterator_before_refusal(self):
        for flag in ('iterator_count_mismatch', 'iterator_early_end', 'iterator_foreign'):
            self.lib.triggerIteratorModelReset(); self.frees.clear()
            with self.subTest(flag=flag), patch.dict(os.environ, {flag: '1'}), self.assertRaises(ValueError): self.sample()
            self.retired(1); self.assertEqual(self.frees, [])

    def test_changed_export_bytes_are_refused_and_genuine_export_and_iterator_retired(self):
        self.inventory['entries'][0]['header_sha256'] = 'f' * 64
        with self.assertRaisesRegex(ValueError, 'export differs'): self.sample()
        self.retired(1); self.assertEqual(len(self.frees), 1)

    def test_wrong_export_length_is_refused_before_read_and_all_acquisitions_retire(self):
        self.inventory['entries'][0]['header_bytes'] += 1
        with patch.object(self.namespace['C'], 'string_at', side_effect=AssertionError('forbidden read')):
            with self.assertRaisesRegex(ValueError, 'export length'): self.sample()
        self.retired(1); self.assertEqual(len(self.frees), 1)

    def test_unexpected_extra_header_refuses_without_freeing_borrowed_headers(self):
        original = self.api['rpmdbNextIterator']; last = []
        def extra(iterator):
            result = original(iterator)
            if result: last[:] = [result]
            return result or (last[0] if iterator and last else None)
        self.api['rpmdbNextIterator'] = extra
        with self.assertRaisesRegex(ValueError, 'extra Header'): self.sample()
        self.retired(1); self.assertEqual(len(self.frees), 1)

    def test_duplicate_instance_refuses_before_second_export_and_retires_iterator(self):
        self.rows[-1]['inventory_count'] = 2; self.rows[-1]['installed_instances'] = [1, 2]
        count = self.api['rpmdbGetIteratorCount']; next_header = self.api['rpmdbNextIterator']; last = []
        self.api['rpmdbGetIteratorCount'] = lambda mi: 2 if mi else count(mi)
        def duplicate(mi):
            result = next_header(mi)
            if result: last[:] = [result]
            return result or (last[0] if mi and last else None)
        self.api['rpmdbNextIterator'] = duplicate
        with self.assertRaisesRegex(ValueError, 'foreign or duplicated'): self.sample()
        self.retired(1); self.assertEqual(len(self.frees), 1)

    def test_boolean_negative_and_changed_terminal_counts_refuse_typed_correspondence(self):
        ordinary = self.api['rpmdbGetIteratorCount']
        for fault in ('bool', 'negative', 'terminal'):
            self.lib.triggerIteratorModelReset(); calls = []
            def count(mi):
                value = ordinary(mi)
                if not mi: return value
                calls.append(mi)
                return True if fault == 'bool' else -1 if fault == 'negative' else value + (len(calls) == 2)
            self.api['rpmdbGetIteratorCount'] = count
            with self.subTest(fault=fault), self.assertRaisesRegex(ValueError, 'count'): self.sample()
            self.retired(1)

    def test_iterator_retirement_cannot_mutate_retained_python_name_buffer_before_success(self):
        original = self.api['rpmdbInitIterator']; retire = self.api['rpmdbFreeIterator']; held = []
        def init(db, tag, buffer, length):
            held[:] = [buffer]; return original(db, tag, buffer, length)
        def changed(mi):
            result = retire(mi)
            if mi: held[0][0] = b'Z'
            return result
        self.api['rpmdbInitIterator'] = init; self.api['rpmdbFreeIterator'] = changed
        with self.assertRaisesRegex(ValueError, 'retirement changed'): self.sample()
        self.retired(1); self.assertEqual(len(self.frees), 1)

    def test_known_database_and_caller_iterator_aliases_never_enter_owned_retirement(self):
        original = self.api['rpmdbInitIterator']; captured = []
        for kind in ('database', 'caller'):
            self.lib.triggerIteratorModelReset()
            def alias(db, tag, buffer, length):
                captured[:] = [buffer.raw]; return db if kind == 'database' else C.addressof(buffer)
            self.api['rpmdbInitIterator'] = alias
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, 'result aliases'): self.sample()
            self.retired(0); self.assertEqual(self.lib.triggerIteratorModelNullFrees(), 1)
            self.assertEqual(captured, [b'new\0']); self.assertEqual(self.frees, [])
        self.api['rpmdbInitIterator'] = original

    def test_all_known_export_base_aliases_refuse_before_read_or_free_and_retire_actual_iterator(self):
        original = self.api['rpmdbInitIterator']; original_next = self.api['rpmdbNextIterator']; acquired = {}
        def init(db, tag, buffer, length):
            acquired.update(database=db, caller=C.addressof(buffer), buffer=buffer)
            result = original(db, tag, buffer, length); acquired['iterator'] = result; return result
        def next_header(iterator):
            result = original_next(iterator); acquired['header'] = result; return result
        self.api['rpmdbInitIterator'] = init; self.api['rpmdbNextIterator'] = next_header
        for kind in ('transaction', 'database', 'caller', 'iterator', 'header', 'size'):
            self.lib.triggerIteratorModelReset(); self.frees.clear()
            def alias(header, size):
                return self.transaction if kind == 'transaction' else C.addressof(size._obj) if kind == 'size' else acquired[kind]
            self.api['headerExport'] = alias
            with self.subTest(kind=kind), patch.object(self.namespace['C'], 'string_at', side_effect=AssertionError('forbidden read')):
                with self.assertRaisesRegex(ValueError, 'export aliases'): self.sample()
            self.retired(1); self.assertEqual(self.frees, []); self.assertEqual(acquired['buffer'].raw, b'userland\0')
        self.record = {'last_alias': kind, 'forbidden_export_reads': 0, 'forbidden_export_frees': 0,
                       'owned_iterators_acquired': 1, 'owned_iterators_retired': 1, 'last_caller_bytes_hex': acquired['buffer'].raw.hex(),
                       'all_six_subtests_asserted_separately': True, 'package_test_performed': False}

    def test_caller_mutation_and_nonnull_retirement_receipt_refuse_complete_sample(self):
        original = self.api['rpmdbInitIterator']
        def changed(db, tag, buffer, length):
            result = original(db, tag, buffer, length); buffer[0] = b'Z'; return result
        self.api['rpmdbInitIterator'] = changed
        with self.assertRaisesRegex(ValueError, 'caller name'): self.sample()
        self.retired(0)
        self.api['rpmdbInitIterator'] = original; self.lib.triggerIteratorModelReset()
        with patch.dict(os.environ, iterator_free_failure='1'), self.assertRaisesRegex(ValueError, 'retirement'): self.sample()
        self.retired(1)

    def test_changed_context_and_missing_symbol_refuse(self):
        with patch.dict(os.environ, count_db_changed='1'), self.assertRaisesRegex(ValueError, 'context changed'): self.sample()
        self.retired(1)
        class Missing:
            def __getattr__(proxy, name):
                if name == 'rpmdbGetIteratorCount': raise AttributeError(name)
                return getattr(self.lib, name)
        with self.assertRaisesRegex(ValueError, 'symbol is missing'): self.namespace['trigger_iterator_bind'](Missing())


class TriggerIteratorProofTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    proof = triggers.TriggerProofTests.proof

    def observe(self, proof):
        return self.namespace['trigger_iterator_observe'](self.namespace['trigger_observe'](proof))['trigger_iterator_observation']

    def test_complete_current_receipt_does_not_replace_future_immediate_argument_unknown(self):
        proof = self.proof(trigger=False); receipt = self.observe(proof)
        self.assertTrue(receipt['count_and_complete_traversal_correspondence_observed'])
        self.assertEqual(receipt['headers_per_sample'], 1)
        self.assertFalse(receipt['runtime_iterator_cardinality_observed'])
        for name in self.namespace['TRIGGER_ITERATOR_AUTHORITIES']: self.assertIs(receipt[name], False)

    def test_missing_raw_receipt_cannot_borrow_stale_correspondence(self):
        proof = self.proof(trigger=False); del proof['effects']['installed_name_iterators']
        proof['trigger_iterator_observation'] = {'count_and_complete_traversal_correspondence_observed': True}
        with self.assertRaises(KeyError): self.observe(proof)

    def test_entire_typed_receipt_is_rebuilt_including_late_rows_commitments_and_false_flags(self):
        for kind in ('late', 'order', 'instance', 'bool', 'hash', 'authority'):
            proof = self.proof(trigger=False); raw = proof['effects']['installed_name_iterators']
            if kind == 'late': raw['rows'][-1]['after']['count_end'] += 1
            elif kind == 'order': raw['rows'].reverse()
            elif kind == 'instance': raw['rows'][0]['before']['order'] = [99]
            elif kind == 'bool': raw['rows'][0]['before']['count_start'] = True
            elif kind == 'hash': raw['rows_sha256'] = 'f' * 64
            else: raw['installation_authorized'] = True
            with self.subTest(kind=kind), self.assertRaises(ValueError): self.observe(proof)


class TriggerIteratorPrivateTests(unittest.TestCase):
    setUpClass = classmethod(headers.HeaderInputNativeTests.setUpClass.__func__)
    setUp = triggers.TriggerPrivateInputTests.setUp
    proof = triggers.TriggerProofTests.proof
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_real_private_snapshot_requires_current_iterator_raw_rows_zero_json_on_missing(self):
        proof = triggers.TriggerProofTests.proof(self, trigger=False)
        del proof['effects']['installed_name_iterators']; data = json.dumps(proof).encode(); self.path.write_bytes(data)
        result = self.run_guard(expected=75)
        self.assertEqual(result.stdout, ''); self.assertEqual(self.path.read_bytes(), data)

    def test_real_private_snapshot_success_binds_all_fourteen_original_byte_hashes(self):
        proof = triggers.TriggerProofTests.proof(self, trigger=False); data = json.dumps(proof).encode(); self.path.write_bytes(data)
        result = self.run_guard(); observed = json.loads(result.stdout)
        self.assertEqual(len(sources.RECEIPTS), 20)
        for name in sources.RECEIPTS: self.assertEqual(observed[name]['input_sha256'], hashlib.sha256(data).hexdigest())
        self.assertEqual(self.path.read_bytes(), data)


class TriggerIteratorPipelineTests(unittest.TestCase):
    setUpClass = classmethod(matches.HeaderMatchPipelineTests.setUpClass.__func__)
    command = matches.HeaderMatchPipelineTests.command
    configure = matches.HeaderMatchPipelineTests.configure
    calls = matches.HeaderMatchPipelineTests.calls
    setUp = matches.HeaderMatchPipelineTests.setUp
    header = matches.HeaderMatchPipelineTests.header
    prepare = matches.HeaderMatchPipelineTests.prepare
    native_calls = matches.HeaderMatchPipelineTests.native_calls
    shell = matches.HeaderMatchPipelineTests.shell

    def test_fresh_test_brackets_same_current_name_iterator_without_event_selection_or_arg2_inference(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['trigger_iterator_observation']; self.assertEqual(receipt['headers_per_sample'], 1)
        self.assertEqual(receipt['rows'][0]['before']['order'], [1]); self.assertEqual(receipt['rows'][0]['after']['order'], [1])
        self.assertEqual(receipt['owned_iterator_retirements'], 2); self.assertEqual(receipt['header_export_calls'], 2)
        self.assertIn('run 1', self.native_calls()); self.assertEqual(self.native_calls().count('name-iterator-open 1'), 2)
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], proof['trigger_input_observation']['input_sha256'])
        future = proof['trigger_argument_observation']['pairs'][1]['hypothetical_phases'][0]['hypothetical_corrections'][0]['immediate_if_unmarked']
        self.assertIsNone(future['conditional_arg2']); self.assertTrue(future['fresh_iterator_count_required'])
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'native_test_seen': True, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'finite_model_not_vendor_runtime': True}

    def test_post_test_iterator_disagreement_refuses_zero_json_and_preserves_retained_pointer(self):
        self.prepare(condition_ordinary=True, provider_positive=True); pointer = (self.root / 'state/updates/current.json').read_bytes()
        result = self.shell('export iterator_after_test=1; s4_check_update_effects', expected=75)
        self.assertIn('trigger iterator advertised count differs', result.stderr); self.assertEqual(result.stdout, '')
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'explicit_post_test_iterator_delivery_model': True}

    def test_pre_test_iterator_failure_precedes_run_and_keeps_pointer(self):
        self.prepare(); pointer = (self.root / 'state/updates/current.json').read_bytes()
        result = self.shell('export iterator_early_end=1; s4_check_update_effects', expected=75)
        self.assertIn('trigger iterator borrowed Header is missing', result.stderr); self.assertEqual(result.stdout, '')
        self.assertNotIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)


if __name__ == '__main__': unittest.main()

import copy
import ast
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import test_update_effects as effects
import test_update_provider_matches as providers
import test_update_trigger_sources as sources
import test_update_triggers as triggers

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / 'Updates.Tests/rpm_header_model.c'
MATCH_MODEL = ROOT / 'Updates.Tests/rpm_header_matches_model.c'
RENAMES = {'headerExport': 'originalHeaderExport', 'headerFree': 'originalHeaderFree',
           'headerIsEntry': 'originalHeaderIsEntry', 'rpmdsCount': 'originalDsCount',
           'rpmdsIx': 'originalDsIx', 'rpmdsTagN': 'originalDsTagN', 'rpmdsN': 'originalDsN',
           'rpmdsEVR': 'originalDsEVR', 'rpmdsFlags': 'originalDsFlags', 'rpmdsFree': 'originalDsFree',
           'rpmdsSingle': 'originalDsSingle'}


def header_model_source(source):
    if 'void *rpmdsSingle(' not in source:
        source += providers.MODEL.read_text()
    return ''.join('#define ' + name + ' ' + replacement + '\n' for name, replacement in RENAMES.items()) + source + '\n' + ''.join(
        '#undef ' + name + '\n' for name in RENAMES) + MODEL.read_text() + MATCH_MODEL.read_text()


class HeaderInputNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='s4-header-api-model-', dir=Path.home() / '.cache')
        cls.addClassCleanup(temporary.cleanup); cls.library = Path(temporary.name) / 'header-model.so'
        source = 'const char *RPMVERSION="4.18.2";\nvoid *headerExport(void *p,unsigned *s){return 0;}\nvoid *headerFree(void *p){return 0;}\nint headerIsEntry(void *p,int t){return 0;}\n'
        source += providers.ranges.VERSION_MODEL.read_text() + providers.ranges.MODEL.read_text()
        source = header_model_source(source)
        subprocess.run(['cc', '-shared', '-fPIC', '-x', 'c', '-', '-o', str(cls.library)],
                       input=source, text=True, capture_output=True, check=True)
        cls.lib = C.CDLL(str(cls.library))
        for name in ('headerModelImported', 'headerModelRetired', 'headerModelDsCreated', 'headerModelDsRetired'):
            getattr(cls.lib, name).restype = C.c_uint; getattr(cls.lib, name).argtypes = ()
        cls.lib.headerModelReset.restype = None; cls.lib.headerModelReset.argtypes = ()
        cls.namespace = providers.prefixes.library()
        ordinary = C.CDLL
        cls.namespace['C'] = type('DeliveredC', (), {name: getattr(C, name) for name in dir(C)})
        cls.namespace['C'].CDLL = staticmethod(lambda name, **options: ordinary(str(cls.library) if name else None, **options))
        cls.native_compare = staticmethod(cls.namespace['provider_native']())

    def setUp(self): self.lib.headerModelReset()

    def fixture(self, both=True):
        entries = providers.provides.entries((b'opaque\xff', b'probe', b'probe'), (b'', b'1-1', b''), (0, 0x80000008, 0))
        if both: entries += providers.conditions.entries(names=(b'probe', b'other'), versions=(b'1-1', b''), masks=(8, 0))
        material = effects.exported(entries)
        provided = self.namespace['provides_records'](self.namespace['provides_export'](material, self.namespace['audit_header'](material)))
        arrays = [(1047, [{'name_hex': r['name_hex'], 'evr_hex': r['evr_hex'], 'flags': r['declared_flags']} for r in provided]),
                  (1066, [{'name_hex': b'probe'.hex(), 'evr_hex': b'1-1'.hex(), 'flags': 65536 | 8, 'script_index': 1},
                          {'name_hex': b'other'.hex(), 'evr_hex': '', 'flags': 65536, 'script_index': 0}] if both else [])]
        return material, arrays

    def observe(self, both=True): self.namespace['header_input_native']()(*self.fixture(both))

    def assert_retired(self):
        self.assertEqual(self.lib.headerModelImported(), self.lib.headerModelRetired())
        self.assertEqual(self.lib.headerModelDsCreated(), self.lib.headerModelDsRetired())

    def test_complete_bytes_duplicate_positions_opaque_names_full_flags_and_script_indexes_read_back(self):
        self.observe(); self.assertEqual((self.lib.headerModelImported(), self.lib.headerModelDsCreated()), (1, 2)); self.assert_retired()

    def test_absent_trigger_set_is_null_without_inventing_an_empty_dependency(self):
        self.observe(False); self.assertEqual(self.lib.headerModelDsCreated(), 1); self.assert_retired()

    def test_import_failure_allocates_no_owned_header(self):
        with patch.dict(os.environ, {'S4_HEADER_MODEL_FAULT': 'import'}), self.assertRaisesRegex(ValueError, 'import failed'): self.observe()
        self.assertEqual(self.lib.headerModelImported(), 0); self.assert_retired()

    def test_null_export_and_wrong_size_or_bytes_refuse_before_dependency_allocation(self):
        for fault in ('export', 'export-size', 'export-bytes'):
            self.setUp()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_HEADER_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'export'):
                self.observe()
            self.assertEqual(self.lib.headerModelDsCreated(), 0); self.assert_retired()

    def test_every_dependency_receipt_including_script_index_is_checked(self):
        for fault in ('presence', 'ds-new', 'count', 'set-index', 'index', 'tag', 'name', 'evr', 'flags', 'script-index'):
            self.setUp()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_HEADER_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'dependency'):
                self.observe()
            self.assert_retired()

    def test_header_or_prior_dependency_alias_refuses_without_double_free(self):
        for fault in ('header-alias', 'ds-alias', 'export-alias', 'import-buffer'):
            self.setUp()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_HEADER_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'alias'):
                self.observe()
            self.assert_retired()

    def test_dependency_and_header_close_failures_withhold_success_and_retire_all_handles(self):
        for fault in ('ds-free', 'header-free'):
            self.setUp()
            with self.subTest(fault=fault), patch.dict(os.environ, {'S4_HEADER_MODEL_FAULT': fault}), self.assertRaisesRegex(ValueError, 'cleanup failed'):
                self.observe()
            self.assert_retired()

    def test_native_import_cannot_change_the_owned_caller_buffer(self):
        with patch.dict(os.environ, {'S4_HEADER_MODEL_FAULT': 'caller-change'}), self.assertRaisesRegex(ValueError, 'caller buffer'): self.observe()
        self.assert_retired()

    def test_unsupported_abi_and_unvetted_library_refuse_before_import(self):
        with patch.object(self.namespace['platform'], 'machine', return_value='riscv64'), self.assertRaisesRegex(ValueError, 'ABI'):
            self.observe()
        slot = C.c_void_p.in_dll(self.lib, 'RPMVERSION'); before = slot.value
        value = C.create_string_buffer(b'4.99-model'); slot.value = C.addressof(value)
        try:
            with self.assertRaisesRegex(ValueError, 'not vetted'): self.observe()
        finally: slot.value = before
        self.assertEqual(self.lib.headerModelImported(), 0)


class HeaderInputCallerAliasTests(unittest.TestCase):
    setUpClass = classmethod(HeaderInputNativeTests.setUpClass.__func__)
    setUp = HeaderInputNativeTests.setUp
    fixture = HeaderInputNativeTests.fixture

    def delivered_observer(self):
        for name in ('headerModelExportCreated', 'headerModelExportRetired', 'headerModelCallerFrees',
                     'headerModelCallerDsFrees', 'headerModelCallerReads'):
            getattr(self.lib, name).restype = C.c_uint; getattr(self.lib, name).argtypes = ()
        self.lib.headerModelFree.restype = None; self.lib.headerModelFree.argtypes = (C.c_void_p,)
        ordinary = self.namespace['C'].CDLL
        buffers, caller_reads = [], []
        def owned_buffer(*args):
            value = C.create_string_buffer(*args); buffers.append(value); return value
        def read(pointer, size):
            if any(pointer == C.addressof(value) for value in buffers): caller_reads.append((pointer, size))
            return C.string_at(pointer, size)
        with patch.object(self.namespace['C'], 'CDLL', staticmethod(
                lambda name, **options: ordinary(name, **options) if name else SimpleNamespace(free=self.lib.headerModelFree))), \
                patch.object(self.namespace['C'], 'create_string_buffer', staticmethod(owned_buffer)), \
                patch.object(self.namespace['C'], 'string_at', staticmethod(read)):
            observer = self.namespace['header_input_native']()
            yield observer, buffers, caller_reads

    def audit(self, buffers, caller_reads, material):
        self.assertEqual(len(buffers), 1); self.assertEqual(buffers[0].raw, material)
        values = {name: getattr(self.lib, 'headerModel' + name)() for name in
                  ('Imported', 'Retired', 'DsCreated', 'DsRetired', 'ExportCreated', 'ExportRetired',
                   'CallerFrees', 'CallerDsFrees', 'CallerReads')}
        self.assertEqual(values['Imported'], values['Retired'])
        self.assertEqual(values['DsCreated'], values['DsRetired'])
        self.assertEqual(values['ExportCreated'], values['ExportRetired'])
        return {**values, 'caller_export_reads': len(caller_reads), 'caller_buffer_unchanged': True,
                'caller_buffer_sha256': hashlib.sha256(buffers[0].raw).hexdigest(),
                'finite_private_native_and_free_delivery_model': True}

    def alias(self, fault, dependencies, exports):
        material, arrays = self.fixture()
        expected = 'Header input ' + ('export' if 'export' in fault else 'dependency') + ' aliases the caller buffer'
        with patch.dict(os.environ, {'S4_HEADER_MODEL_FAULT': fault, 'S4_HEADER_MODEL_AUDIT': '1'}):
            delivery = self.delivered_observer(); observer, buffers, reads = next(delivery)
            try:
                with self.assertRaisesRegex(ValueError, '^' + expected + '$'): observer(material, arrays)
                record = self.audit(buffers, reads, material)
                self.assertEqual((record['Imported'], record['DsCreated'], record['ExportCreated']), (1, dependencies, exports))
                for name in ('CallerFrees', 'CallerDsFrees', 'CallerReads', 'caller_export_reads'): self.assertEqual(record[name], 0)
                self.record = {**record, 'fault': fault, 'specific_refusal': expected}
            finally: delivery.close()

    def test_export_caller_buffer_refuses_before_read_or_free(self):
        self.alias('export-buffer', 0, 0)

    def test_second_export_caller_buffer_refuses_and_retires_both_real_dependencies(self):
        self.alias('later-export-buffer', 2, 1)

    def test_dependency_caller_buffer_refuses_before_readback_or_ownership(self):
        self.alias('ds-buffer', 0, 1)

    def test_second_dependency_caller_buffer_refuses_and_retires_first_real_dependency(self):
        self.alias('later-ds-buffer', 1, 1)

    def test_positive_delivery_retires_two_separate_exports_and_dependencies_once(self):
        material, arrays = self.fixture()
        with patch.dict(os.environ, {'S4_HEADER_MODEL_AUDIT': '1'}):
            delivery = self.delivered_observer(); observer, buffers, reads = next(delivery)
            try:
                observer(material, arrays); record = self.audit(buffers, reads, material)
                self.assertEqual((record['Imported'], record['DsCreated'], record['ExportCreated']), (1, 2, 2))
                for name in ('CallerFrees', 'CallerDsFrees', 'CallerReads', 'caller_export_reads'): self.assertEqual(record[name], 0)
                self.record = {**record, 'fault': None}
            finally: delivery.close()

    def sensitivity(self, returned_name, fault):
        tree = ast.parse((ROOT / 'Updates/header_inputs.py').read_text())
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'header_input_native')
        removed = []
        class OmitKnownCallerCheck(ast.NodeTransformer):
            def visit_If(self, node):
                test = node.test
                if (isinstance(test, ast.Compare) and isinstance(test.left, ast.Name) and test.left.id == returned_name
                        and len(test.comparators) == 1 and isinstance(test.comparators[0], ast.Name)
                        and test.comparators[0].id == 'caller_address'):
                    removed.append(ast.dump(node, include_attributes=False)); return ast.copy_location(ast.Pass(), node)
                return self.generic_visit(node)
        model = OmitKnownCallerCheck().visit(function); self.assertEqual(len(removed), 1)
        original = self.namespace['header_input_native']
        exec(compile(ast.fix_missing_locations(ast.Module(body=[model], type_ignores=[])), '<single-caller-check-omission-model>', 'exec'), self.namespace)
        material, arrays = self.fixture()
        try:
            with patch.dict(os.environ, {'S4_HEADER_MODEL_FAULT': fault, 'S4_HEADER_MODEL_AUDIT': '1'}):
                delivery = self.delivered_observer(); observer, buffers, reads = next(delivery)
                try:
                    if returned_name == 'pointer': observer(material, arrays)
                    else:
                        with self.assertRaisesRegex(ValueError, '^Header input dependency count differs$'): observer(material, arrays)
                    record = self.audit(buffers, reads, material)
                    if returned_name == 'pointer': self.assertEqual((record['CallerFrees'], record['caller_export_reads']), (2, 2))
                    else: self.assertEqual((record['CallerDsFrees'], record['CallerReads']), (1, 1))
                    self.record = {**record, 'explicit_single_check_omission_model': True, 'removed_node_ast': removed[0],
                                   'model_function_ast': ast.dump(model, include_attributes=False),
                                   'source_sha256': hashlib.sha256((ROOT / 'Updates/header_inputs.py').read_bytes()).hexdigest()}
                finally: delivery.close()
        finally: self.namespace['header_input_native'] = original

    def test_export_alias_control_is_sensitive_to_omission_of_its_single_check(self):
        self.sensitivity('pointer', 'export-buffer')

    def test_dependency_alias_control_is_sensitive_to_omission_of_its_single_check(self):
        self.sensitivity('handle', 'ds-buffer')


class HeaderInputProofTests(unittest.TestCase):
    setUpClass = classmethod(HeaderInputNativeTests.setUpClass.__func__)
    setUp = HeaderInputNativeTests.setUp
    make_proof_base = sources.TriggerSourceProofTests.make_proof
    proof = triggers.TriggerProofTests.proof
    rebind = providers.ProviderProofTests.rebind

    def make_proof(self):
        proof = self.make_proof_base(provide_names=(b'fixture', b'fixture'))
        owner = proof['effects']['installed_script_owners'][0]
        material = effects.exported(providers.conditions.entries(names=(b'fixture', b'absent'), versions=(b'', b''), masks=(0, 0))
                                    + providers.provides.entries((b'fixture', b'fixture'), (b'', b''), (0, 0)))
        self.assertEqual(hashlib.sha256(material).hexdigest(), owner['header_sha256'])
        proof['effects']['installed_header_exports'] = [{**proof['effects']['installed_versions']['entries'][0], 'header_export_hex': material.hex()}]
        proof['effects']['incoming'][0]['header_export_hex'] = effects.exported([(1023, 6, [b'body'])]).hex()
        return proof

    def observe(self, proof, factory=None):
        return self.namespace['header_input_observe'](self.namespace['trigger_observe'](proof),
            factory or self.namespace['header_input_native'], lambda: self.native_compare)['header_input_observation']

    def test_complete_installed_export_and_dependency_readback_binds_current_inventory(self):
        proof = self.make_proof(); receipt = self.observe(proof)
        self.assertEqual((receipt['headers_imported'], receipt['dependency_rows_read_back']), (2, 4))
        self.assertEqual(receipt['inventory_sha256'], proof['effects']['installed_versions']['entries_sha256'])
        self.assertEqual(receipt['baseline_sha256'], proof['baseline']['sha256'])
        self.assertTrue(receipt['complete_exports_reimported'])

    def test_missing_or_stale_export_projection_refuses_before_native_factory(self):
        for change in ('missing', 'digest', 'order', 'extra'):
            proof = self.make_proof(); row = proof['effects']['installed_header_exports'][0]
            if change == 'missing': del proof['effects']['installed_header_exports']
            elif change == 'digest': row['header_export_hex'] = row['header_export_hex'][:-2] + 'ff'
            elif change == 'order': row['instance'] = 2
            else: row['unsupported'] = True
            proof['header_input_observation'] = {'complete_exports_reimported': True}
            with self.subTest(change=change), self.assertRaises((KeyError, ValueError)):
                self.observe(proof, lambda: self.fail('factory before raw admission'))

    def test_noncanonical_hex_and_same_length_different_bytes_refuse(self):
        for change in ('uppercase', 'spaces', 'length'):
            proof = self.make_proof(); row = proof['effects']['installed_header_exports'][0]
            if change == 'uppercase': row['header_export_hex'] = row['header_export_hex'].upper()
            elif change == 'spaces': row['header_export_hex'] = '  ' + row['header_export_hex'][2:]
            else: row['header_export_hex'] += '00'
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, 'encoding|digest'):
                self.observe(proof, lambda: self.fail('factory before encoding'))

    def test_aggregate_byte_and_row_limits_precede_native_factory(self):
        for name in ('HEADER_INPUT_BYTES', 'HEADER_INPUT_ROWS'):
            old = self.namespace[name]; self.namespace[name] = 0
            try:
                with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'bound|size'):
                    self.observe(self.make_proof(), lambda: self.fail('factory before work bound'))
            finally: self.namespace[name] = old

    def test_no_ordinary_conditions_load_no_header_library_and_withhold_import_claim(self):
        proof = self.proof(); receipt = self.observe(proof, lambda: self.fail('no ordinary Header factory'))
        self.assertEqual(receipt['headers_imported'], 0); self.assertFalse(receipt['complete_exports_reimported'])
        self.assertFalse(receipt['native_dependency_fields_read_back'])

    def test_later_native_failure_withholds_complete_new_receipt(self):
        proof = self.make_proof()
        with patch.dict(os.environ, {'S4_HEADER_MODEL_FAULT': 'export-bytes'}), self.assertRaisesRegex(ValueError, 'export bytes'):
            self.observe(proof)
        self.assertNotIn('header_input_observation', proof)

    def test_complete_owner_commitment_and_all_seventeen_authorities_remain_false(self):
        receipt = self.observe(self.make_proof())
        raw = json.dumps(receipt['owners'], sort_keys=True, separators=(',', ':')).encode('ascii')
        self.assertEqual((receipt['owners_bytes'], receipt['owners_sha256']), (len(raw), hashlib.sha256(raw).hexdigest()))
        names = [name for name, value in receipt.items() if value is False]
        self.assertEqual(len(names), 17); self.assertIs(receipt['actual_header_dependency_matches_observed'], False)


class HeaderInputPrivateTests(unittest.TestCase):
    setUpClass = classmethod(HeaderInputNativeTests.setUpClass.__func__)
    proof = triggers.TriggerProofTests.proof
    rebind = providers.ProviderProofTests.rebind
    make_proof_base = sources.TriggerSourceProofTests.make_proof
    make_proof = HeaderInputProofTests.make_proof
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def setUp(self):
        triggers.TriggerPrivateInputTests.setUp(self)
        self.program.write_text(self.program.read_text().replace('C.CDLL("librpm.so.9",', 'C.CDLL(' + repr(str(self.library)) + ','))
        self.path.write_text(json.dumps(self.make_proof(), sort_keys=True) + '\n')

    def test_complete_actual_private_snapshot_binds_all_eight_hashes_without_mutation(self):
        before = self.path.read_bytes(); proof = json.loads(self.run_guard().stdout)
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], hashlib.sha256(before).hexdigest())
        self.assertEqual(proof['header_input_observation']['headers_imported'], 2)
        self.assertFalse(proof['header_input_observation']['actual_header_dependency_matches_observed'])
        self.assertEqual(self.path.read_bytes(), before)

    def test_missing_export_on_actual_private_path_refuses_despite_stale_receipt(self):
        proof = json.loads(self.path.read_text()); del proof['effects']['installed_header_exports']
        proof['header_input_observation'] = {'complete_exports_reimported': True}
        self.path.write_text(json.dumps(proof)); before = self.path.read_bytes()
        self.assertIn('installed_header_exports', self.run_guard(expected=75).stderr); self.assertEqual(self.path.read_bytes(), before)

    def test_native_dependency_change_on_private_path_withholds_all_json(self):
        before = self.path.read_bytes()
        with patch.dict(os.environ, {'S4_HEADER_MODEL_FAULT': 'script-index'}):
            self.assertIn('Header input dependency receipt differs', self.run_guard(expected=75).stderr)
        self.assertEqual(self.path.read_bytes(), before)

    def caller_alias(self, fault, kind):
        # The private delivery protects Python storage even if a check is
        # deliberately omitted; production still uses the ordinary libc free.
        source = self.program.read_text().replace('libc = C.CDLL(None)', 'libc = C.CDLL(' + repr(str(self.library)) + ')').replace('libc.free', 'libc.headerModelFree')
        self.program.write_text(source); before = self.path.read_bytes()
        with patch.dict(os.environ, {'S4_HEADER_MODEL_FAULT': fault, 'S4_HEADER_MODEL_AUDIT': '1'}): result = self.run_guard(expected=75)
        expected = 'Header input ' + kind + ' aliases the caller buffer'
        self.assertIn(expected, result.stderr); self.assertEqual(result.stdout, '')
        self.assertEqual(self.path.read_bytes(), before)
        self.record = {'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
                       'specific_refusal': expected, 'private_input_sha256_before': hashlib.sha256(before).hexdigest(),
                       'private_input_sha256_after': hashlib.sha256(self.path.read_bytes()).hexdigest(),
                       'library_and_free_delivery_model': True}

    def test_export_caller_alias_on_actual_private_snapshot_withholds_all_json(self):
        self.caller_alias('export-buffer', 'export')

    def test_dependency_caller_alias_on_actual_private_snapshot_withholds_all_json(self):
        self.caller_alias('ds-buffer', 'dependency')


class HeaderInputPipelineTests(unittest.TestCase):
    setUpClass = classmethod(providers.ProviderPipelineTests.setUpClass.__func__)
    command = providers.ProviderPipelineTests.command
    configure = providers.ProviderPipelineTests.configure
    calls = providers.ProviderPipelineTests.calls
    setUp = providers.ProviderPipelineTests.setUp
    header = providers.ProviderPipelineTests.header
    prepare = providers.ProviderPipelineTests.prepare
    native_calls = providers.ProviderPipelineTests.native_calls
    shell = providers.ProviderPipelineTests.shell

    def test_current_native_test_complete_export_readbacks_bind_eight_original_input_hashes(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['header_input_observation']; self.assertEqual(receipt['headers_imported'], 2)
        self.assertTrue(receipt['native_dependency_fields_read_back']); self.assertFalse(receipt['actual_header_dependency_matches_observed'])
        raw = copy.deepcopy(proof); names = (*sources.RECEIPTS, 'header_input_observation', 'header_match_observation')
        for name in dict.fromkeys(names): raw.pop(name)
        digest = hashlib.sha256((json.dumps(raw, sort_keys=True) + '\n').encode()).hexdigest()
        for name in names: self.assertEqual(proof[name]['input_sha256'], digest)
        installed = proof['effects']['installed_header_exports'][0]
        self.assertEqual(hashlib.sha256(bytes.fromhex(installed['header_export_hex'])).hexdigest(), installed['header_sha256'])
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'delivery_model_not_vendor_rpm': True}

    def test_current_test_native_export_mismatch_refuses_without_json_or_pointer_change(self):
        self.prepare(condition_ordinary=True, provider_positive=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes()
        result = self.shell('export S4_HEADER_MODEL_FAULT=export-bytes; s4_check_update_effects', expected=75)
        self.assertIn('Header input native export bytes differ', result.stderr); self.assertEqual(result.stdout, '')
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified': True, 'delivery_model_not_vendor_rpm': True}

    def test_removal_producer_path_does_not_enable_complete_header_projection(self):
        self.prepare(condition_ordinary=True)
        import shlex
        import test_update_interpreters as interpreters
        program = interpreters.emitted('s4_update_removals_program').replace('C.CDLL("librpm.so.9",', 'C.CDLL(' + repr(str(self.library)) + ',')
        path = self.root / 'removal-library-delivery.py'; path.write_text(program)
        result = self.shell('S4_REMOVALS_MODE=yes; s4_update_removals_program() { cat ' + shlex.quote(str(path)) + '; }; s4_check_update_effects')
        self.assertNotIn('installed_header_exports', json.loads(result.stdout)['effects'])
        self.assertNotIn('header_input_observation', json.loads(result.stdout))


if __name__ == '__main__': unittest.main()

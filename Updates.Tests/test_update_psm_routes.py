import copy
import ctypes as C
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_update_header_matches as matches
import test_update_psm_inputs as inputs
import test_update_trigger_sources as sources
import test_update_triggers as triggers


def route_proof(namespace, entries=None, removed=False, empty=False):
    fixture = triggers.TriggerProofTests(); fixture.namespace = namespace
    proof = fixture.proof(trigger=False, incoming=not empty)
    if not empty:
        material = triggers.effects.exported(entries or [(1000, 6, [b'future'])])
        owner = proof['effects']['incoming'][0]
        owner.update(namespace['audit_header'](material), header_export_hex=material.hex())
    if removed:
        material = triggers.effects.exported([(1151, 6, [b'opaque %{macro} $(false)']), (1154, 6, [b'/bin/sh'])])
        exported = proof['effects']['installed_header_exports'][0]
        exported.update({key: value for key, value in namespace['audit_header'](material).items() if key != 'tags'},
                        header_export_hex=material.hex())
        owner = {**exported, **namespace['audit_header'](material), 'provides': {'schema': 1, 'tags': []},
                 'file_trigger_prefix_bytes': [], 'trigger_condition_bytes': []}
        proof['effects']['installed_script_owners'] = [owner]
        proof['effects']['installed_provides'] = [{key: owner[key] for key in (*namespace['INSTALLED_VERSION_FIELDS'], 'provides')}]
        proof['baseline'] = {'headers': 1, 'sha256': hashlib.sha256(json.dumps(
            [(1, owner['header_sha256'])], separators=(',', ':')).encode()).hexdigest()}
        proof['effects']['installed_versions'] = namespace['installed_version_inventory']({1: owner}, proof['baseline'])
        proof['effects']['removals'] = [{**owner, 'classification': 'other-removal'}]
        proof['removals'] = [owner['nevra']]
    triggers.bind_count_delivery(namespace, proof)
    return proof


class PsmRouteForecastTests(unittest.TestCase):
    setUpClass = classmethod(triggers.TriggerArrayTests.setUpClass.__func__)

    def proof(self, **kwargs): return route_proof(self.namespace, **kwargs)
    def forecast(self, **kwargs): return self.namespace['psm_route_forecast'](self.proof(**kwargs))

    def test_main_caller_maps_complete_current_owner_kind_to_install_or_erase(self):
        result = self.forecast(removed=True)
        self.assertEqual([r['conditional_caller_routes'][0]['goal'] for r in result['rows']],
                         ['PKG_INSTALL', 'PKG_ERASE', 'PKG_INSTALL', 'PKG_ERASE'])
        self.assertEqual(result['rows'][1]['element']['owner']['instance'], 1)
        self.assertEqual(result['conditional_caller_cases'], 12)

    def test_program_only_body_only_both_and_absent_use_tag_presence_or(self):
        for entries, present in (([(1153, 6, [b'/bin/sh'])], True), ([(1151, 6, [b'body'])], True),
                                 ([(1151, 6, [b'']), (1153, 8, [b'/bin/sh', b'-e'])], True), (None, False)):
            with self.subTest(entries=entries):
                route = self.forecast(entries=entries)['rows'][0]['conditional_caller_routes'][1]
                self.assertIs(route['declared_transscript_present'], present)
                self.assertIs(route['conditional_open_attempt'], present)

    def test_flags_only_does_not_manufacture_transscript_presence(self):
        route = self.forecast(entries=[(5024, 4, [3]), (5025, 4, [2])])['rows'][0]['conditional_caller_routes']
        self.assertTrue(all(not r['declared_transscript_present'] for r in route[1:]))

    def test_removed_owner_with_both_transscript_declarations_is_not_added_caller(self):
        routes = self.forecast(removed=True)['rows'][1]['conditional_caller_routes'][1:]
        self.assertTrue(all(r['declared_transscript_present'] for r in routes))
        self.assertTrue(all(not r['caller_kind_matches'] and not r['conditional_open_attempt'] for r in routes))

    def test_posttrans_uses_its_own_body_program_pair_without_pretrans_promotion(self):
        routes = self.forecast(entries=[(1154, 8, [b'/bin/sh'])])['rows'][0]['conditional_caller_routes']
        self.assertFalse(routes[1]['conditional_open_attempt']); self.assertTrue(routes[2]['conditional_open_attempt'])

    def test_complete_export_and_matrix_digests_bind_full_owner_and_source_tags(self):
        result = self.forecast(entries=[(1151, 6, [b'opaque\xff'])], removed=True)
        for field in ('rows', 'headers'):
            material = json.dumps(result[field], sort_keys=True, separators=(',', ':')).encode('ascii')
            self.assertEqual((result[field + '_bytes'], result[field + '_sha256']),
                             (len(material), hashlib.sha256(material).hexdigest()))
        self.assertNotIn('opaque', json.dumps(result)); self.assertEqual(result['header_exports_audited'], 2)
        self.assertEqual([r['sample'] for r in result['rows']], ['before', 'before', 'after', 'after'])

    def test_empty_transaction_audits_current_headers_without_positive_caller_forecast(self):
        result = self.forecast(empty=True)
        self.assertEqual((result['conditional_caller_cases'], result['new_rpm_api_calls'], result['rows_bytes']), (0, 0, 2))
        self.assertEqual(result['header_exports_audited'], 1); self.assertFalse(result['conditional_routes_forecast'])

    def test_missing_partial_and_duplicated_installed_exports_refuse_even_without_conditions(self):
        for edit in (lambda p: p['effects'].pop('installed_header_exports'),
                     lambda p: p['effects']['installed_header_exports'].clear(),
                     lambda p: p['effects']['installed_header_exports'].append(copy.deepcopy(p['effects']['installed_header_exports'][0]))):
            proof = self.proof(); edit(proof)
            with self.subTest(edit=edit), self.assertRaises((ValueError, KeyError)): self.namespace['psm_route_forecast'](proof)

    def test_scriptless_installed_export_cannot_borrow_stale_positive_metadata(self):
        proof = self.proof()
        stale = self.namespace['audit_header'](triggers.effects.exported([(1151, 6, [b'old'])]))['tags']
        proof['effects']['installed_script_owners'] = [{**proof['effects']['installed_header_exports'][0], 'tags': stale}]
        with self.assertRaisesRegex(ValueError, 'scriptless export differs'): self.namespace['psm_route_forecast'](proof)

    def test_unreferenced_later_installed_export_is_audited_before_route_publication(self):
        proof = self.proof(); material = triggers.effects.exported([(1151, 4, [1])])
        owner = {'instance': 2, 'name': 'unrelated', 'nevra': 'unrelated-0-1.x86_64',
                 'header_bytes': len(material), 'header_sha256': hashlib.sha256(material).hexdigest()}
        previous = proof['effects']['installed_versions']['entries'][0]
        proof['baseline'] = {'headers': 2, 'sha256': hashlib.sha256(json.dumps(
            [(row['instance'], row['header_sha256']) for row in (previous, owner)], separators=(',', ':')).encode()).hexdigest()}
        proof['effects']['installed_versions'] = self.namespace['installed_version_inventory']({1: previous, 2: owner}, proof['baseline'])
        proof['effects']['installed_header_exports'].append({**owner, 'header_export_hex': material.hex()})
        triggers.bind_count_delivery(self.namespace, proof)
        with self.assertRaisesRegex(ValueError, 'tag type/count/identity'): self.namespace['psm_route_forecast'](proof)

    def test_incoming_export_tags_and_full_identity_must_correspond(self):
        for edit in (lambda p: p['effects']['incoming'][0].update(tags=[]),
                     lambda p: p['effects']['incoming'][0].update(header_export_hex='ff'),
                     lambda p: p['effects']['incoming'][0].update(file='packages/1.rpm')):
            proof = self.proof(entries=[(1153, 6, [b'/bin/sh'])]); edit(proof)
            with self.subTest(edit=edit), self.assertRaises(ValueError): self.namespace['psm_route_forecast'](proof)

    def test_later_installed_export_and_metadata_omissions_refuse_all_routes(self):
        for edit in (lambda p: p['effects']['installed_header_exports'][0].update(instance=True),
                     lambda p: p['effects']['installed_script_owners'].clear(),
                     lambda p: p['effects']['installed_script_owners'][0].update(tags=[])):
            proof = self.proof(removed=True); edit(proof)
            with self.subTest(edit=edit), self.assertRaises(ValueError): self.namespace['psm_route_forecast'](proof)

    def test_source_flags_and_stale_complete_current_element_receipts_refuse(self):
        for edit in (lambda p: p['effects']['current_psm_inputs']['before'][0].update(is_source=1),
                     lambda p: p['effects']['current_psm_inputs'].update(new_rpm_api_calls=True),
                     lambda p: p['effects']['ordered_transaction_elements'].update(rows_sha256='f' * 64)):
            proof = self.proof(); edit(proof)
            with self.subTest(edit=edit), self.assertRaises(ValueError): self.namespace['psm_route_forecast'](proof)

    def test_case_header_and_incremental_matrix_bounds_withhold_complete_result(self):
        for name, value, reason in (('PSM_ROUTE_CASES', 5, 'caller cases'), ('PSM_ROUTE_HEADER_BYTES', 0, 'Header bytes'),
                                    ('PSM_ROUTE_BYTES', 1, 'serialization')):
            with self.subTest(bound=name), patch.dict(self.namespace, {name: value}), self.assertRaisesRegex(ValueError, reason):
                self.forecast()

    def test_typed_caller_operands_refuse_without_goal_or_presence_coercion(self):
        for args in ((1, False, False, False, False), ('installed', False, False, False, False),
                     ('incoming', 1, False, False, False), ('removed', False, False, None, False)):
            with self.subTest(args=args), self.assertRaises(ValueError): self.namespace['psm_route_case'](*args)

    def test_all_authorities_false_and_future_runtime_flags_open_and_phase_remain_required(self):
        result = self.forecast()
        for name in self.namespace['PSM_ROUTE_AUTHORITIES']: self.assertIs(result[name], False)
        self.assertTrue(result['fresh_runtime_kind_header_open_phase_and_flags_required'])
        self.assertEqual(result['new_rpm_api_calls'], 0); self.assertIn('UNSELECTED', result['scope'])


class PsmRouteOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        triggers.TriggerArrayTests.setUpClass.__func__(cls)
        directory = tempfile.TemporaryDirectory(prefix='s4-psm-route-oracle-', dir=Path.home() / '.cache')
        cls.addClassCleanup(directory.cleanup); cls.library = Path(directory.name) / 'oracle.so'
        subprocess.run(['cc', '-shared', '-fPIC', str(Path(__file__).with_name('rpm_psm_routes_model.c')),
                        '-o', str(cls.library)], capture_output=True, text=True, check=True)
        cls.lib = C.CDLL(str(cls.library)); cls.oracle = cls.lib.model_psm_route
        cls.oracle.restype = C.c_int; cls.oracle.argtypes = (C.c_int,) * 5 + (C.POINTER(C.c_int),) * 2

    def call(self, kind, phase, body, program, fault=0):
        goal, attempted = C.c_int(), C.c_int()
        self.assertEqual(self.oracle(kind, phase, body, program, fault, C.byref(goal), C.byref(attempted)), 0)
        return goal.value, bool(attempted.value)

    def test_finite_source_oracle_covers_kind_phase_and_each_presence_combination(self):
        calls = 0
        for kind, label in ((1, 'incoming'), (2, 'removed')):
            for bits in range(16):
                values = [bool(bits & (1 << i)) for i in range(4)]
                routes = self.namespace['psm_route_case'](label, *values)
                for phase, route in enumerate(routes):
                    body, program = values[0:2] if phase == 1 else values[2:4]
                    goal, attempted = self.call(kind, phase, int(body), int(program)); calls += 1
                    self.assertEqual(goal, (kind, 1151, 1152)[phase])
                    self.assertIs(attempted, route['conditional_open_attempt'])
        self.assertEqual(calls, 96); self.record = {'finite_model_comparisons': calls, 'not_native_rpm': True}

    def test_unshipped_and_presence_sensitivity_disagrees_on_body_only_and_program_only(self):
        differences = []
        for body, program in ((1, 0), (0, 1)):
            intact = self.call(1, 1, body, program); model = self.call(1, 1, body, program, fault=1)
            self.assertEqual(intact, (1151, True)); self.assertEqual(model, (1151, False)); differences.append((intact, model))
        self.record = {'unshipped_modified_model': 'OR replaced by AND', 'differences': differences}


class PsmRoutePrivateTests(unittest.TestCase):
    setUpClass = classmethod(triggers.TriggerArrayTests.setUpClass.__func__)
    setUp = triggers.TriggerPrivateInputTests.setUp
    proof = triggers.TriggerProofTests.proof
    run_guard = triggers.TriggerPrivateInputTests.run_guard

    def test_owned_private_program_only_success_binds_nineteen_hashes_without_body_execution(self):
        proof = route_proof(self.namespace, entries=[(1153, 6, [b'/bin/sh'])])
        data = json.dumps(proof).encode(); self.path.write_bytes(data); observed = json.loads(self.run_guard().stdout)
        self.assertEqual(len(sources.RECEIPTS), 19)
        for name in sources.RECEIPTS: self.assertEqual(observed[name]['input_sha256'], hashlib.sha256(data).hexdigest())
        self.assertTrue(observed['psm_route_observation']['rows'][0]['conditional_caller_routes'][1]['conditional_open_attempt'])
        self.assertEqual(self.path.read_bytes(), data)
        for name in self.namespace['PSM_ROUTE_AUTHORITIES']: self.assertIs(observed['psm_route_observation'][name], False)

    def test_owned_private_stale_route_receipt_cannot_replace_missing_full_export(self):
        proof = route_proof(self.namespace); del proof['effects']['incoming'][0]['header_export_hex']
        proof['psm_route_observation'] = {'conditional_routes_forecast': True}
        data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
        self.assertIn('header_export_hex', result.stderr); self.assertEqual(result.stdout, ''); self.assertEqual(self.path.read_bytes(), data)

    def test_owned_private_export_tag_mismatch_refuses_before_any_json(self):
        proof = route_proof(self.namespace, entries=[(1153, 6, [b'/bin/sh'])]); proof['effects']['incoming'][0]['tags'] = []
        data = json.dumps(proof).encode(); self.path.write_bytes(data); result = self.run_guard(expected=75)
        self.assertIn('incoming tags differ', result.stderr); self.assertEqual(result.stdout, ''); self.assertEqual(self.path.read_bytes(), data)


class PsmRoutePipelineTests(unittest.TestCase):
    setUpClass = classmethod(matches.HeaderMatchPipelineTests.setUpClass.__func__)
    command = matches.HeaderMatchPipelineTests.command
    configure = matches.HeaderMatchPipelineTests.configure
    calls = matches.HeaderMatchPipelineTests.calls
    setUp = matches.HeaderMatchPipelineTests.setUp
    header = matches.HeaderMatchPipelineTests.header
    prepare = matches.HeaderMatchPipelineTests.prepare
    native_calls = matches.HeaderMatchPipelineTests.native_calls
    shell = matches.HeaderMatchPipelineTests.shell

    def test_fresh_test_binds_two_current_routes_nineteen_hashes_pointer_and_cleanup(self):
        self.prepare(condition_ordinary=True, provider_positive=True, userland_removal=True)
        pointer = (self.root / 'state/updates/current.json').read_bytes(); proof = json.loads(self.shell().stdout)
        receipt = proof['psm_route_observation']; self.assertEqual(receipt['conditional_caller_cases'], 12)
        self.assertEqual([r['conditional_caller_routes'][0]['goal'] for r in receipt['rows']],
                         ['PKG_INSTALL', 'PKG_ERASE', 'PKG_INSTALL', 'PKG_ERASE'])
        for name in sources.RECEIPTS: self.assertEqual(proof[name]['input_sha256'], proof['trigger_input_observation']['input_sha256'])
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'proof': proof, 'native_test_seen': True, 'ordinary_cleanup_verified': True,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest()}

    def test_explicit_caller_limit_model_refuses_after_test_without_json_and_preserves_pointer(self):
        self.prepare(userland_removal=True); pointer = (self.root / 'state/updates/current.json').read_bytes()
        program = triggers.emitted().replace('if trigger_execution:\n', 'PSM_ROUTE_CASES = 0\nif trigger_execution:\n').replace(
            'C.CDLL("librpm.so.9",', 'C.CDLL(' + repr(str(self.library)) + ',')
        path = self.root / 'psm-route-bound-model.py'; path.write_text(program)
        result = self.shell('s4_update_trigger_inputs_program() { cat ' + shlex.quote(str(path)) + '; }; s4_check_update_effects', expected=75)
        self.assertIn('PSM route caller cases exceed', result.stderr); self.assertEqual(result.stdout, '')
        self.assertIn('run 1', self.native_calls()); self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.record = {'exit': 75, 'stdout': result.stdout, 'stderr': result.stderr, 'native_test_seen': True,
            'ordinary_cleanup_verified': True, 'explicit_modified_parent_limit_model': True,
            'pointer_sha256_before': hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after': hashlib.sha256((self.root / 'state/updates/current.json').read_bytes()).hexdigest()}

    def test_empty_test_path_has_current_exports_but_no_caller_route_or_package_test(self):
        self.prepare(empty=True); proof = json.loads(self.shell().stdout)
        self.assertFalse(proof['rpm_test_performed']); self.assertFalse(proof['psm_route_observation']['conditional_routes_forecast'])
        self.assertEqual(proof['psm_route_observation']['conditional_caller_cases'], 0)

    def test_shipped_parent_always_calls_new_route_hook_and_native_bypasses_stay_exact(self):
        program = triggers.emitted()
        self.assertEqual(program.count('def psm_route_case('), 1)
        self.assertTrue(program.endswith('if trigger_execution:\n    raise SystemExit(trigger_main(psm_route_observe))\n'))
        self.assertEqual(program.count('def psm_input_sample('), 1)


if __name__ == '__main__': unittest.main()

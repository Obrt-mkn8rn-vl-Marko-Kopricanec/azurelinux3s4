"""SDK compile/fallback declarations never supply runtime selection authority."""

import collections
import copy
import hashlib
import json
import unittest

from test_deployment_policy import encoded
from test_deployment_releases import CAPTURES, ReleaseFixture
import test_deployment_services as service_delivery


FRAMEWORK = '.NETCoreApp,Version=v10.0'
TARGET = FRAMEWORK + '/linux-x64'
SDK_GRAPH = {
    'android-x64': ['android', 'linux-bionic-x64', 'linux-bionic', 'linux-x64',
                    'linux', 'unix-x64', 'unix', 'any', 'base'],
    'linux-bionic-x64': ['linux-bionic', 'linux-x64', 'linux', 'unix-x64', 'unix', 'any', 'base'],
    'linux-musl-x64': ['linux-musl', 'linux-x64', 'linux', 'unix-x64', 'unix', 'any', 'base'],
    'linux-x64': ['linux', 'unix-x64', 'unix', 'any', 'base'],
}


class DeploymentDependencyMetadataTests(ReleaseFixture):
    run_emitted = service_delivery.DeploymentApplicationServiceTests.run_emitted

    def dependency(self, app='mk8.sava', role='application'):
        program = self.n['REL_PROGRAMS'][app][role]
        name = role + '/' + program + '.deps.json'
        return name, json.loads((self.folder(app) / name).read_bytes())

    def sdk_declarations(self):
        hashes = {}
        for app, roles in self.n['REL_PROGRAMS'].items():
            for role in roles:
                name, value = self.dependency(app, role)
                value['targets'][FRAMEWORK] = {}
                value['runtimes'] = copy.deepcopy(SDK_GRAPH)
                data = encoded(value)[:-1]
                self.replace_file(name, data, app)
                hashes[app, name] = hashlib.sha256(data).hexdigest()
        return hashes

    def test_complete_all_role_declarations_keep_original_bytes_and_held_tree_commitments(self):
        hashes = self.sdk_declarations(); before = self.snapshot()
        for app in self.n['REL_PROGRAMS']:
            result = self.observe(app)
            self.assertEqual(len(result['runtime']), 2)
            self.assertTrue(result['complete_tree_observed'] and result['two_file_hash_passes']
                            and result['checked_closes_completed'])
            for row in result['files']:
                if (app, row['path']) in hashes:
                    self.assertEqual(row['sha256'], hashes[app, row['path']])
                    data = (self.folder(app) / row['path']).read_bytes()
                    self.assertFalse(data.endswith(b'\n'))
                    self.assertEqual(row['bytes'], len(data))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_optional_empty_compile_target_and_absent_or_empty_graph_preserve_rid_only_profile(self):
        name, original = self.dependency()
        for compile_target, graph in ((False, None), (True, None), (False, {}), (True, {})):
            with self.subTest(compile_target=compile_target, graph=graph):
                value = copy.deepcopy(original)
                if compile_target:
                    value['targets'][FRAMEWORK] = {}
                if graph is not None:
                    value['runtimes'] = graph
                self.replace_file(name, encoded(value)[:-1])
                self.assertEqual(self.observe()['runtime'][0]['runtime_target'], TARGET)

    def test_nonempty_or_wrong_kind_compile_target_cannot_supply_another_library_context(self):
        name, original = self.dependency()
        for compile_value in (None, [], False, 0, {'other/1.0': {}}, {'compile': {}}):
            with self.subTest(compile_value=compile_value):
                value = copy.deepcopy(original); value['targets'][FRAMEWORK] = compile_value
                self.replace_file(name, encoded(value)); self.refused(message='dependency target')

    def test_missing_wrong_or_extra_runtime_targets_refuse_despite_empty_compile_target(self):
        name, original = self.dependency()
        for targets in ({FRAMEWORK: {}}, {TARGET: {}, FRAMEWORK: {}},
                        {TARGET: original['targets'][TARGET], FRAMEWORK: {}, 'other': {}},
                        {FRAMEWORK + '/win-x64': original['targets'][TARGET], FRAMEWORK: {}}):
            with self.subTest(targets=targets.keys()):
                value = copy.deepcopy(original); value['targets'] = targets
                self.replace_file(name, encoded(value)); self.refused(message='dependency target')

    def test_runtime_graph_root_and_every_fallback_array_require_exact_types(self):
        name, original = self.dependency()
        for graph in (None, [], False, 0, {'linux-x64': None}, {'linux-x64': 'linux'},
                      {'linux-x64': {}}, {'linux-x64': [False]}, {'linux-x64': [1]}):
            with self.subTest(graph=graph):
                value = copy.deepcopy(original); value['runtimes'] = graph
                self.replace_file(name, encoded(value)); self.refused()

    def test_decoded_fallback_names_are_bounded_canonical_ascii_before_use(self):
        name, original = self.dependency()
        for label in ('', 'linux_x64', 'Linux-x64', 'linux\n  accept', 'linux\x7f',
                      'linux\u2028x64', 'linux/other', 'x' * 129):
            for key in (True, False):
                with self.subTest(label=label, key=key):
                    value = copy.deepcopy(original)
                    value['runtimes'] = {label: []} if key else {'linux-x64': [label]}
                    self.replace_file(name, encoded(value)); self.refused(message='manifest text')

    def test_duplicate_and_self_fallback_labels_refuse_without_normalizing_them(self):
        name, original = self.dependency()
        for graph in ({'linux-x64': ['linux', 'linux']}, {'linux-x64': ['linux-x64']}):
            with self.subTest(graph=graph):
                value = copy.deepcopy(original); value['runtimes'] = graph
                self.replace_file(name, encoded(value)); self.refused(message='duplicate or self')

    def test_graph_node_and_per_array_limits_refuse_one_past_the_declared_profile(self):
        admit = self.n['release_runtime_fallbacks']
        with self.assertRaisesRegex(ValueError, 'node bound'):
            admit({'rid-' + str(index): [] for index in range(129)})
        with self.assertRaisesRegex(ValueError, 'array type or bound'):
            admit({'linux-x64': ['fallback-' + str(index) for index in range(129)]})

    def test_total_fallback_reference_limit_counts_all_rows_and_preserves_missing_label_keys(self):
        admit = self.n['release_runtime_fallbacks']
        graph = {'rid-' + str(index): ['fallback-' + str(value) for value in range(128)]
                 for index in range(32)}
        self.assertIsNone(admit(graph))
        graph['extra'] = ['one-more']
        with self.assertRaisesRegex(ValueError, 'reference bound'):
            admit(graph)

    def test_whole_graph_is_checked_even_after_an_earlier_valid_linux_row(self):
        name, value = self.dependency()
        value['runtimes'] = {'linux-x64': ['linux', 'unix'], 'zz-later': [None]}
        data = encoded(value)
        self.assertEqual(list(json.loads(data)['runtimes']), ['linux-x64', 'zz-later'])
        self.replace_file(name, data); self.refused(message='manifest text')

    def test_foreign_graph_labels_do_not_approve_foreign_runtime_assets(self):
        name, value = self.dependency()
        value['targets'][FRAMEWORK] = {}; value['runtimes'] = copy.deepcopy(SDK_GRAPH)
        library = next(iter(value['targets'][TARGET].values()))
        library['runtimeTargets'] = {'program.dll': {'rid': 'linux-musl-x64', 'assetType': 'runtime'}}
        self.replace_file(name, encoded(value)); self.refused(message='unsupported runtime target asset')

    def test_library_membership_and_dependency_edges_remain_complete_under_sdk_graphs(self):
        name, original = self.dependency()
        for fault in ('library', 'edge'):
            with self.subTest(fault=fault):
                value = copy.deepcopy(original)
                value['targets'][FRAMEWORK] = {}; value['runtimes'] = copy.deepcopy(SDK_GRAPH)
                if fault == 'library':
                    value['libraries']['unlisted/1.0'] = {'type': 'project'}
                else:
                    next(iter(value['targets'][TARGET].values()))['dependencies'] = {'missing': '1.0'}
                self.replace_file(name, encoded(value)); self.refused(message='dependency')

    def test_complete_emitted_sdk_graph_candidate_retains_all_false_authorities_and_inputs(self):
        hashes = self.sdk_declarations()
        self.manifest_file.write_bytes(encoded(self.value)); before = self.snapshot()
        result = self.run_emitted()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(len(output['authority']), 27)
        self.assertTrue(all(value is False for value in output['authority'].values()))
        for release in output['releases']:
            for row in release['files']:
                if (release['app'], row['path']) in hashes:
                    self.assertEqual(row['sha256'], hashes[release['app'], row['path']])
        self.assertEqual(self.snapshot(), before)
        CAPTURES.append(self.capture)

    def test_complete_emitted_late_malformed_graph_refuses_no_json_and_preserves_original_bytes(self):
        self.sdk_declarations()
        name, value = self.dependency('mk8.email', 'gateway')
        value['runtimes']['zz-later'] = [None]
        data = encoded(value)[:-1]
        self.assertEqual(list(json.loads(data)['runtimes'])[-1], 'zz-later')
        self.replace_file(name, data, 'mk8.email')
        self.manifest_file.write_bytes(encoded(self.value)); before = self.snapshot()
        result = self.run_emitted()
        self.assertEqual(result.returncode, 75)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Application service candidate refused\n')
        self.assertEqual(self.snapshot(), before)
        CAPTURES.append(self.capture)


if __name__ == '__main__':
    unittest.main()

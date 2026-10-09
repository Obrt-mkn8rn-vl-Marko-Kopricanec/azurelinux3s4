"""Original SDK JSON bytes remain hash-bound; operator JSON keeps its LF profile."""

import collections
import hashlib
import json
import unittest

from test_deployment_policy import encoded
from test_deployment_releases import CAPTURES, ReleaseFixture
import test_deployment_services as service_delivery


class DeploymentRuntimeMetadataTests(ReleaseFixture):
    run_emitted = service_delivery.DeploymentApplicationServiceTests.run_emitted

    def without_metadata_lf(self):
        expected = {}
        for app, roles in self.n['REL_PROGRAMS'].items():
            for role, program in roles.items():
                for suffix in ('.deps.json', '.runtimeconfig.json'):
                    name = role + '/' + program + suffix
                    data = (self.folder(app) / name).read_bytes()
                    self.assertTrue(data.endswith(b'\n'))
                    self.replace_file(name, data[:-1], app)
                    expected[app, name] = hashlib.sha256(data[:-1]).hexdigest()
        return expected

    def test_all_roles_keep_exact_non_lf_metadata_bytes_and_complete_tree_commitments(self):
        expected = self.without_metadata_lf()
        before = self.snapshot()
        for app in self.n['REL_PROGRAMS']:
            result = self.observe(app)
            self.assertEqual(len(result['runtime']), 2)
            self.assertTrue(result['complete_tree_observed'] and result['two_file_hash_passes']
                            and result['checked_closes_completed'])
            for row in result['files']:
                if (app, row['path']) in expected:
                    self.assertEqual(row['sha256'], expected[app, row['path']])
                    data = (self.folder(app) / row['path']).read_bytes()
                    self.assertFalse(data.endswith(b'\n'))
                    self.assertEqual(row['bytes'], len(data))
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_default_operator_json_requires_lf_while_explicit_sdk_parse_preserves_values(self):
        document = b'{"runtimeOptions":{"configProperties":{"finite":0.5}}}'
        with self.assertRaisesRegex(ValueError, 'ASCII/LF'):
            self.n['release_json'](document)
        self.assertEqual(self.n['release_json'](document, final_lf=False), json.loads(document))
        self.assertEqual(self.n['release_json'](document + b'\n'), json.loads(document))

    def test_release_manifest_without_lf_refuses_even_with_correct_original_byte_digest(self):
        path = self.folder() / 'release.json'
        data = path.read_bytes()[:-1]
        path.chmod(0o600); path.write_bytes(data); path.chmod(0o400)
        self.value['releases']['mk8.sava']['manifest_sha256'] = hashlib.sha256(data).hexdigest()
        self.refused(message='ASCII/LF')

    def test_startup_configuration_without_lf_refuses_after_its_matching_digest(self):
        app = 'mk8.drava'; leaf = 'application.json'
        path = self.root / 'etc' / app / leaf
        data = path.read_bytes()[:-1]; path.write_bytes(data)
        self.documents[app]['configuration'][leaf] = hashlib.sha256(data).hexdigest(); self.seal(app)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'ASCII/LF'):
            self.n['application_bundle'](encoded(self.value), self.n['bundle'])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_sdk_no_lf_does_not_admit_duplicate_nonfinite_truncated_or_multiple_documents(self):
        name = 'application/Mk8.Sava.Application.runtimeconfig.json'
        for data in (b'{"runtimeOptions":{},"runtimeOptions":{}}',
                     b'{"runtimeOptions":NaN}', b'{"runtimeOptions":{"limit":1e400}}',
                     b'{"runtimeOptions":', b'{}\n{}'):
            with self.subTest(data=data):
                self.replace_file(name, data)
                self.refused()

    def test_sdk_no_lf_keeps_ascii_control_bom_and_size_admissions(self):
        parse = self.n['release_json']
        for data in (b'', b'{}\r\n', b'{}\t', b'{}\0', b'\xef\xbb\xbf{}', b'{"x":"\xc3\xa9"}'):
            with self.subTest(data=data):
                with self.assertRaisesRegex(ValueError, 'ASCII/LF'):
                    parse(data, final_lf=False)
        self.n['REL_MANIFEST_LIMIT'] = 1
        with self.assertRaisesRegex(ValueError, 'ASCII/LF'):
            parse(b'{}', final_lf=False)

    def test_non_lf_metadata_retains_hash_and_length_refusal_before_semantic_parsing(self):
        self.without_metadata_lf()
        path = self.folder() / 'application/Mk8.Sava.Application.deps.json'
        original = path.read_bytes(); path.write_bytes(b'X' * len(original))
        self.refused(message='digest')
        path.write_bytes(original + b' ')
        self.refused(message='length')

    def test_non_lf_metadata_still_requires_self_contained_role_and_linux_dependency_target(self):
        name = 'application/Mk8.Sava.Application.runtimeconfig.json'
        self.replace_file(name, encoded({'runtimeOptions': {'tfm': 'net10.0', 'framework': {
            'name': 'Microsoft.NETCore.App', 'version': '10.0.4'}}})[:-1])
        self.refused(message='self-contained')
        self.replace_file(name, encoded({'runtimeOptions': {'tfm': 'net10.0', 'includedFrameworks': [
            {'name': 'Microsoft.NETCore.App', 'version': '10.0.4'},
            {'name': 'Microsoft.AspNetCore.App', 'version': '10.0.4'}]}})[:-1])
        name = 'application/Mk8.Sava.Application.deps.json'
        value = json.loads((self.folder() / name).read_bytes())
        value['runtimeTarget']['name'] = '.NETCoreApp,Version=v10.0/win-x64'
        self.replace_file(name, encoded(value)[:-1]); self.refused(message='dependency target')

    def test_complete_emitted_candidate_keeps_non_lf_metadata_and_all_false_authorities(self):
        expected = self.without_metadata_lf()
        self.manifest_file.write_bytes(encoded(self.value)); before = self.snapshot()
        result = self.run_emitted()
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(len(output['authority']), 27)
        self.assertTrue(all(value is False for value in output['authority'].values()))
        for release in output['releases']:
            for row in release['files']:
                if (release['app'], row['path']) in expected:
                    self.assertEqual(row['sha256'], expected[release['app'], row['path']])
        self.assertEqual(self.snapshot(), before)
        CAPTURES.append(self.capture)

    def test_complete_emitted_malformed_non_lf_metadata_refuses_without_json_and_preserves_inputs(self):
        self.replace_file('application/Mk8.Sava.Application.runtimeconfig.json', b'{"runtimeOptions":NaN}')
        self.manifest_file.write_bytes(encoded(self.value)); before = self.snapshot()
        result = self.run_emitted()
        self.assertEqual(result.returncode, 75)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Application service candidate refused\n')
        self.assertEqual(self.snapshot(), before)
        CAPTURES.append(self.capture)


if __name__ == '__main__':
    unittest.main()

"""Complete synthetic release trees with real private IO and explicit root delivery."""

import collections
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest.mock import patch

from test_deployment_policy import LIBRARIES, PrivateOS, encoded, manifest


ROOT = Path(__file__).resolve().parents[1]
CAPTURES = []


def elf(kind=3, machine=62):
    data = bytearray(64)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', data, 16, kind, machine, 1)
    return bytes(data)


class ReleaseFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home() / '.cache')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.n = {'__name__': 'application_release_private_delivery'}
        for name in (*LIBRARIES, 'Deployment/releases.py', 'Deployment/dns_configuration.py', 'Deployment/credentials.py', 'Deployment/email_credentials.py', 'Deployment/email_role_policy.py', 'Deployment/email_transport.py', 'Deployment/email_presentation.py', 'Deployment/drava_bootstrap.py', 'Deployment/services.py'):
            exec(compile((ROOT / name).read_bytes(), name, 'exec'), self.n)
        self.delivery = PrivateOS(self.root)
        self.n['dep_os'] = self.delivery
        self.n['DEP_TRUSTED_UID'] = os.geteuid()
        self.value = manifest()
        self.documents = {}
        for app in self.n['DEP_APPS']:
            folder = self.root / 'opt' / app / 'releases' / ('1' * 40)
            folder.mkdir(parents=True)
            for parent in (folder, *folder.parents):
                if parent == self.root:
                    break
                parent.chmod(0o755)
            config = self.root / 'etc' / app
            config.mkdir(parents=True, mode=0o700)
            (self.root / 'etc').chmod(0o700)
            inputs = {leaf: encoded({'schemaVersion': 1}) for leaf in self.n['REL_CONFIGS'][app]}
            if app == 'mk8.drava':
                inputs = {leaf: encoded({'schemaVersion': 1, 'siteId': 'fixture-site',
                    'gatewayId': 'fixture-gateway', 'stateDirectory': '/var/lib/mk8.drava/' + role,
                    'httpPort': 80, 'httpsPort': 0, field: {
                    'unixSocketPath': '/var/lib/mk8.drava/application/application.sock',
                    'identityTokenPath': '/run/credentials/mk8-drava-' + role + '.service/ipc'},
                    **({'nodeId': 'fixture-node'} if role == 'application' else {'discoveryEnabled': False})})
                    for leaf, role, field in (('application.json', 'application', 'listen'),
                                              ('gateway.json', 'gateway', 'application'))}
                token = config / 'ipc-token.txt'; token.write_bytes(b'A' * 48 + b'\n'); token.chmod(0o600)
            if app == 'mk8.dns':
                zone = {'ZoneId': '11111111-1111-1111-1111-111111111111', 'Origin': 'example.test.'}
                common = {'Epoch': '22222222-2222-2222-2222-222222222222', 'TargetNode': 'r630-authoritative-replica', 'Zones': [zone]}
                inputs['control-plane.json'] = encoded({**common, 'PublicationSocket':
                    '/run/mk8.dns/authoritative-replica/publication.sock',
                    'KeyFile': '/run/mk8.dns/controller/inputs/key.pem',
                    'ConnectionStringFile': '/run/mk8.dns/controller/inputs/database.txt',
                    'Grants': [{'TenantId': '33333333-3333-3333-3333-333333333333', 'ZoneId': zone['ZoneId'],
                                'Origin': zone['Origin'], 'Actor': 'private-fixture', 'Expires': '2030-01-01T00:00:00Z',
                                'CredentialHash': 'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE='}]})
                inputs['authority.json'] = encoded({**common, 'KeyFile': '/run/mk8.dns/authoritative-replica/inputs/key.pem'})
                for role in ('controller', 'authoritative-replica'):
                    secrets = config / role; secrets.mkdir(mode=0o700)
                    key = secrets / 'key.pem'; key.write_bytes(b'finite key bytes, not authenticated PEM\n'); key.chmod(0o600)
                database = config / 'controller/database.txt'
                database.write_bytes(b'finite database input, not a usable connection\n'); database.chmod(0o600)
            if app == 'mk8.sava':
                inputs = {'policy.env': b'Sava__DefaultAccount=fixture\nSava__Accounts__fixture=not-a-runtime-proof\nApplicationTransport__Endpoint=http://127.0.0.1:18581/internal/application\n',
                          'application.env': b'Sava__DataPath=/var/lib/mk8.sava/application\nSava__DataEncryptionKeys__fixture=private-fixture-only\n',
                          'gateway.env': b'Gateway__StagingPath=/var/cache/mk8.sava-gateway/staging\n',
                          'rpc.key': b'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=\n'}
            if app == 'mk8.email':
                for role in ('worker', 'gateway'):
                    runtime = '/run/credentials/mk8-email-' + role + '.service/'
                    value = {'Database': {'PasswordFile': runtime + 'database-password.txt'},
                             'Smtp': {'Hostname': self.value['domains']['mk8.email']},
                             'Messaging': {'Enabled': True, 'EncryptionKeyId': 'primary',
                                           'EncryptionKeyFile': runtime + 'messaging-key.txt',
                                           'DecryptionKeys': [{'Id': 'old', 'KeyFile': runtime + 'messaging-decrypt-old.txt'}]},
                             'ObjectStorage': {'ConnectionStringFile': runtime + 'blob-connection.txt'}}
                    names = ['database-password.txt', 'messaging-key.txt', 'messaging-decrypt-old.txt', 'blob-connection.txt']
                    if role == 'worker':
                        value.update(OAuth={'EnableOAuth': True, 'EnableOpenIdConnect': True, 'SigningKeyFile': runtime + 'oauth-signing.txt'},
                                     Mfa={'EnableTotp': True, 'EncryptionKeyFile': runtime + 'mfa-key.txt'},
                                     Dkim={'EnableSigning': True, 'PrivateKeyPath': runtime + 'dkim-key.pem'})
                        names.extend(('oauth-signing.txt', 'mfa-key.txt', 'dkim-key.pem'))
                    else:
                        value['Smtp'].update(EnableSubmission=True, EnableStartTls=True)
                        value['Imap'] = {'EnableImap': False, 'EnableImplicitTls': True}
                        value['Jmap'] = {'Port': self.value['private_ports']['email_http']}
                        value['Tls'] = {'CertificatePath': runtime + 'tls-certificate.pem', 'CertificateKeyPath': runtime + 'tls-key.pem'}
                        value['Admin'] = {'AllowedNetworks': ['192.168.90.0/24'],
                                          'DataProtectionKeyPath': '/var/lib/mk8.email/gateway/data-protection',
                                          'AuditLogPath': '/var/lib/mk8.email/gateway/audit/admin.jsonl',
                                          'HealthStatusPath': '/var/lib/mk8.email/gateway/health/status.json'}
                        names.extend(('tls-certificate.pem', 'tls-key.pem'))
                    inputs[role + '.json'] = encoded(value)
                    secrets = config / role; secrets.mkdir(mode=0o700)
                    for name in names:
                        p = secrets / name; p.write_bytes(('finite opaque Email input ' + role + '/' + name + '\n').encode()); p.chmod(0o600)
            for leaf, data in inputs.items():
                p = config / leaf; p.write_bytes(data); p.chmod(0o600)
            document = {'schema': 1, 'app': app, 'commit': '1' * 40, 'tree': '2' * 40,
                        'profile': 'self-contained-net10-linux-x64', 'files': [],
                        'configuration': {leaf: hashlib.sha256(data).hexdigest() for leaf, data in inputs.items()}}
            for role, program in self.n['REL_PROGRAMS'][app].items():
                target = folder / role; target.mkdir(mode=0o755); target.chmod(0o755)
                frameworks = [{'name': 'Microsoft.NETCore.App', 'version': '10.0.4'}]
                if role != 'worker':
                    frameworks.append({'name': 'Microsoft.AspNetCore.App', 'version': '10.0.4'})
                deps = {'runtimeTarget': {'name': '.NETCoreApp,Version=v10.0/linux-x64', 'signature': ''},
                        'targets': {'.NETCoreApp,Version=v10.0/linux-x64': {
                            program + '/1.0': {'runtime': {program + '.dll': {}}},
                            'Microsoft.NETCore.App.Runtime.linux-x64/10.0.4': {
                                'runtime': {'System.Private.CoreLib.dll': {}},
                                'native': {leaf: {} for leaf in ('libhostfxr.so', 'libhostpolicy.so', 'libcoreclr.so')}}}},
                        'libraries': {program + '/1.0': {'type': 'project'},
                                      'Microsoft.NETCore.App.Runtime.linux-x64/10.0.4': {'type': 'package'}}}
                pieces = {program: elf(), program + '.dll': b'MZ synthetic managed fixture\n',
                          program + '.deps.json': encoded(deps),
                          program + '.runtimeconfig.json': encoded({'runtimeOptions': {
                              'tfm': 'net10.0', 'includedFrameworks': frameworks}}),
                          'System.Private.CoreLib.dll': b'MZ synthetic core fixture\n',
                          **{leaf: elf() for leaf in ('libhostfxr.so', 'libhostpolicy.so', 'libcoreclr.so')}}
                for leaf, data in pieces.items():
                    p = target / leaf; p.write_bytes(data); p.chmod(0o755 if leaf == program else 0o644)
                    document['files'].append({'path': role + '/' + leaf, 'bytes': len(data),
                        'sha256': hashlib.sha256(data).hexdigest(), 'mode': '0755' if leaf == program else '0644'})
            document['files'].sort(key=lambda row: row['path'])
            self.documents[app] = document
            self.seal(app)
        self.manifest_file = self.root / 'manifest.json'
        self.manifest_file.write_bytes(encoded(self.value)); self.manifest_file.chmod(0o600)

    def folder(self, app='mk8.sava'):
        return self.root / 'opt' / app / 'releases' / ('1' * 40)

    def seal(self, app='mk8.sava'):
        data = encoded(self.documents[app])
        target = self.folder(app) / 'release.json'
        target.chmod(0o600) if target.exists() else None
        target.write_bytes(data); target.chmod(0o400)
        self.value['releases'][app]['manifest_sha256'] = hashlib.sha256(data).hexdigest()

    def replace_file(self, name, data, app='mk8.sava'):
        p = self.folder(app) / name
        p.write_bytes(data)
        row = next(row for row in self.documents[app]['files'] if row['path'] == name)
        row.update(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.seal(app)

    def observe(self, app='mk8.sava'):
        return self.n['release_observe'](app, self.value['releases'][app])

    def refused(self, app='mk8.sava', message=None):
        with self.assertRaisesRegex((OSError, ValueError), message or '.'):
            self.observe(app)
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def snapshot(self):
        return {str(p.relative_to(self.root)): (hashlib.sha256(p.read_bytes()).hexdigest(),
                    stat.S_IMODE(p.stat().st_mode)) for p in self.root.rglob('*') if p.is_file() and not p.is_symlink()}


class DeploymentReleaseTests(ReleaseFixture):
    def test_all_four_complete_trees_close_descriptors_without_writing_or_execution(self):
        before = self.snapshot()
        for app in self.n['DEP_APPS']:
            result = self.observe(app)
            self.assertEqual(result['manifest_sha256'], self.value['releases'][app]['manifest_sha256'])
            self.assertEqual(result['file_count'], 16)
            for row in result['observed_files']:
                self.assertEqual(row['identity'], list(self.n['deployment_identity']((self.folder(app) / row['path']).stat())))
            self.assertEqual(result['payload_bytes'], sum(row['bytes'] for row in self.documents[app]['files']))
            self.assertEqual([row['path'] for row in result['files']], sorted(row['path'] for row in result['files']))
            self.assertTrue(result['complete_tree_observed'] and result['two_file_hash_passes'] and result['checked_closes_completed'])
            self.assertEqual(len(result['runtime']), 2)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_manifest_hash_refuses_before_any_role_file_is_opened(self):
        self.value['releases']['mk8.sava']['manifest_sha256'] = '0' * 64
        calls = []
        original = self.delivery.open
        def opened(path, flags, **kwargs):
            calls.append(path); return original(path, flags, **kwargs)
        self.delivery.open = opened
        self.refused(message='manifest digest')
        self.assertNotIn('application', calls)

    def test_commit_tree_app_and_profile_correspondence_is_mandatory(self):
        original = copy.deepcopy(self.documents['mk8.sava'])
        for key, value in (('commit', '4' * 40), ('tree', '4' * 40), ('app', 'mk8.email'), ('profile', 'framework-dependent')):
            with self.subTest(key=key):
                self.documents['mk8.sava'] = copy.deepcopy(original)
                self.documents['mk8.sava'][key] = value; self.seal(); self.refused(message='declaration')

    def test_boolean_size_and_unknown_fields_are_refused(self):
        self.documents['mk8.sava']['files'][0]['bytes'] = True
        self.seal(); self.refused(message='identity/type')
        self.documents['mk8.sava']['files'][0]['bytes'] = 1
        self.documents['mk8.sava']['unexpected'] = 0
        self.seal(); self.refused(message='exact manifest')

    def test_duplicate_unsorted_and_prefix_paths_refuse(self):
        original = copy.deepcopy(self.documents['mk8.sava'])
        for variant in ('duplicate', 'unsorted', 'prefix'):
            with self.subTest(variant=variant):
                self.documents['mk8.sava'] = copy.deepcopy(original)
                rows = self.documents['mk8.sava']['files']
                if variant == 'duplicate': rows.append(dict(rows[0]))
                if variant == 'unsorted': rows.reverse()
                if variant == 'prefix': rows[0]['path'] = 'application'
                self.seal(); self.refused()

    def test_traversal_unicode_and_separator_paths_refuse_before_walk(self):
        for value in ('application/../outside', 'application//outside', 'application/caf\u00e9', 'application/x\naccept', '/application/host'):
            with self.subTest(value=value):
                self.documents['mk8.sava']['files'][0]['path'] = value
                self.seal(); self.refused()

    def test_missing_role_and_core_runtime_files_refuse(self):
        original = copy.deepcopy(self.documents['mk8.sava'])
        for name in ('gateway/Mk8.Sava.Gateway', 'application/libhostfxr.so', 'gateway/Mk8.Sava.Gateway.dll'):
            with self.subTest(name=name):
                self.documents['mk8.sava'] = copy.deepcopy(original)
                self.documents['mk8.sava']['files'] = [row for row in original['files'] if row['path'] != name]
                self.seal(); self.refused(message='required')

    def test_extra_regular_hidden_and_empty_directory_are_not_ignored(self):
        for name, directory in (('extra', False), ('.hidden', False), ('extra-dir', True)):
            with self.subTest(name=name):
                p = self.folder() / name
                p.mkdir(mode=0o755) if directory else p.write_bytes(b'extra')
                self.refused(message='membership')
                p.rmdir() if directory else p.unlink()

    def test_symlink_directory_and_file_are_never_followed(self):
        p = self.folder() / 'application/Mk8.Sava.Application.dll'
        data = p.read_bytes(); p.unlink(); p.symlink_to(self.manifest_file)
        self.refused(message='unprotected')
        p.unlink(); p.write_bytes(data); p.chmod(0o644)
        folder = self.folder() / 'gateway'
        folder.rename(self.folder() / 'saved-gateway'); folder.symlink_to('saved-gateway')
        self.refused()

    def test_hardlinked_payload_refuses_even_with_matching_bytes(self):
        p = self.folder() / 'application/Mk8.Sava.Application.dll'
        os.link(p, self.root / 'linked')
        self.refused(message='unprotected')

    def test_fifo_payload_refuses_before_open(self):
        p = self.folder() / 'application/Mk8.Sava.Application.dll'
        p.unlink(); os.mkfifo(p, 0o644)
        calls = []; original = self.delivery.open
        def opened(path, flags, **kwargs): calls.append(path); return original(path, flags, **kwargs)
        self.delivery.open = opened
        self.refused(message='unprotected')
        self.assertNotIn('Mk8.Sava.Application.dll', calls)

    def test_writable_special_modes_and_protected_manifest_mode_refuse(self):
        p = self.folder() / 'application/Mk8.Sava.Application.dll'
        for mode in (0o666, 0o4644, 0o600):
            with self.subTest(mode=mode): p.chmod(mode); self.refused(message='unprotected')
        p.chmod(0o644); (self.folder() / 'release.json').chmod(0o600)
        self.refused(message='unprotected')

    def test_directory_execute_or_write_policy_refuses(self):
        p = self.folder() / 'application'
        for mode in (0o700, 0o775, 0o2755):
            with self.subTest(mode=mode): p.chmod(mode); self.refused(message='0755')

    def test_digest_length_and_actual_eof_correspondence_refuse(self):
        p = self.folder() / 'application/Mk8.Sava.Application.dll'
        data = p.read_bytes(); p.write_bytes(data + b'changed')
        self.refused(message='length')
        p.write_bytes(b'X' * len(data)); self.refused(message='digest')

    def test_same_bytes_new_inode_is_refused_while_original_fd_is_held(self):
        original = self.delivery.open
        target = self.folder() / 'application/Mk8.Sava.Application.dll'
        tracked = set(); replaced = [False]
        def opened(path, flags, **kwargs):
            fd = original(path, flags, **kwargs)
            if path == 'Mk8.Sava.Application.dll': tracked.add(fd)
            return fd
        self.delivery.open = opened
        def seek(fd, offset, origin):
            if fd in tracked and not replaced[0]:
                replaced[0] = True
                data = target.read_bytes(); target.rename(self.root / 'owned-previous-file')
                target.write_bytes(data); target.chmod(0o644)
            return os.lseek(fd, offset, origin)
        self.delivery.lseek = seek
        self.refused(message='metadata changed')

    def test_change_between_hash_passes_refuses(self):
        original = self.delivery.open
        target = self.folder() / 'application/Mk8.Sava.Application.dll'
        tracked = set()
        positions = collections.Counter()
        def opened(path, flags, **kwargs):
            fd = original(path, flags, **kwargs)
            if path == 'Mk8.Sava.Application.dll': tracked.add(fd); positions[fd] = 0
            return fd
        self.delivery.open = opened
        def seek(fd, offset, origin):
            positions[fd] += 1
            if fd in tracked and positions[fd] == 2: target.write_bytes(b'X' * target.stat().st_size)
            return os.lseek(fd, offset, origin)
        self.delivery.lseek = seek
        self.refused(message='readback')

    def test_checked_close_failure_cannot_return_a_release(self):
        original = self.delivery.close; hit = [False]
        def closed(fd):
            original(fd)
            if not hit[0]: hit[0] = True; raise OSError('delivered ordinary close failure')
        self.delivery.close = closed
        self.refused(message='close failure')

    def test_manifest_file_count_and_aggregate_limits_precede_payload_reads(self):
        original = self.n['REL_FILES']; self.n['REL_FILES'] = 15
        self.refused(message='count bound'); self.n['REL_FILES'] = original
        self.n['REL_TOTAL_LIMIT'] = 1; self.refused(message='aggregate')

    def test_scan_bound_spends_every_entry_before_selection(self):
        self.n['REL_ENTRIES'] = 100
        for index in range(201): (self.folder() / ('extra' + str(index))).touch()
        self.refused(message='scan entry bound')

    def test_wrong_architecture_or_nonelf_native_payload_refuses(self):
        self.replace_file('application/Mk8.Sava.Application', elf(machine=183))
        self.refused(message='ELF')
        self.replace_file('application/Mk8.Sava.Application', elf())
        self.replace_file('gateway/libcoreclr.so', b'opaque non-ELF fixture')
        self.refused(message='ELF')

    def test_framework_dependent_or_wrong_major_runtime_refuses(self):
        name = 'application/Mk8.Sava.Application.runtimeconfig.json'
        self.replace_file(name, encoded({'runtimeOptions': {'tfm': 'net10.0', 'framework': {'name': 'Microsoft.NETCore.App', 'version': '10.0.4'}}}))
        self.refused(message='self-contained')
        self.replace_file(name, encoded({'runtimeOptions': {'tfm': 'net10.0', 'includedFrameworks': [
            {'name': 'Microsoft.NETCore.App', 'version': '9.0.4'}, {'name': 'Microsoft.AspNetCore.App', 'version': '10.0.4'}]}}))
        self.refused(message='noncanonical')

    def test_duplicate_frameworks_or_omitted_aspnet_refuses(self):
        name = 'gateway/Mk8.Sava.Gateway.runtimeconfig.json'
        for frameworks in ([{'name': 'Microsoft.NETCore.App', 'version': '10.0.4'}],
                           [{'name': 'Microsoft.NETCore.App', 'version': '10.0.4'}] * 2):
            with self.subTest(frameworks=frameworks):
                self.replace_file(name, encoded({'runtimeOptions': {'tfm': 'net10.0', 'includedFrameworks': frameworks}})); self.refused()

    def test_dependency_asset_missing_and_wrong_rid_refuse(self):
        name = 'application/Mk8.Sava.Application.deps.json'
        value = json.loads((self.folder() / name).read_bytes())
        groups = next(iter(value['targets'].values()))['Mk8.Sava.Application/1.0']
        groups['native'] = {'absent.so': {}}
        self.replace_file(name, encoded(value)); self.refused(message='asset absent')
        del groups['native']; groups['runtimeTargets'] = {'absent.so': {'rid': 'win-x64', 'assetType': 'native'}}
        self.replace_file(name, encoded(value)); self.refused(message='runtime target asset')

    def test_flattened_native_asset_correspondence_and_ambiguity(self):
        name = 'application/Mk8.Sava.Application.deps.json'
        value = json.loads((self.folder() / name).read_bytes())
        groups = next(iter(value['targets'].values()))['Microsoft.NETCore.App.Runtime.linux-x64/10.0.4']
        groups['native'] = {'runtimes/linux-x64/native/' + leaf: {} for leaf in groups['native']}
        self.replace_file(name, encoded(value)); self.assertEqual(self.observe()['runtime'][0]['dependency_files'], 5)
        nested = 'application/runtimes/linux-x64/native/libcoreclr.so'
        p = self.folder() / nested; p.parent.mkdir(parents=True)
        for parent in p.parents:
            if parent == self.folder(): break
            parent.chmod(0o755)
        p.write_bytes(elf()); p.chmod(0o644)
        self.documents['mk8.sava']['files'].append({'path': nested, 'bytes': 64, 'sha256': hashlib.sha256(elf()).hexdigest(), 'mode': '0644'})
        self.documents['mk8.sava']['files'].sort(key=lambda row: row['path']); self.seal()
        self.refused(message='ambiguous')

    def test_duplicate_json_and_nonfinite_runtime_documents_refuse(self):
        name = 'application/Mk8.Sava.Application.runtimeconfig.json'
        for data in (b'{"runtimeOptions":{},"runtimeOptions":{}}\n', b'{"runtimeOptions":NaN}\n'):
            with self.subTest(data=data): self.replace_file(name, data); self.refused()

    def test_second_directory_scan_change_and_late_file_path_change_refuse(self):
        original = self.n['release_entries']; calls = collections.Counter()
        def entries(fd, budget):
            result = original(fd, budget); calls[fd] += 1
            return result + ['late'] if calls[fd] == 2 else result
        self.n['release_entries'] = entries; self.refused(message='scan changed')
        self.n['release_entries'] = original
        original_runtime = self.n['release_runtime']
        def runtime(*args):
            result = original_runtime(*args)
            p = self.folder() / 'application/Mk8.Sava.Application.dll'; data = p.read_bytes()
            p.unlink(); p.write_bytes(data); p.chmod(0o644)
            return result
        self.n['release_runtime'] = runtime; self.refused(message='held directory changed')

    def test_dependency_unknown_sections_and_unbound_edges_refuse(self):
        name = 'application/Mk8.Sava.Application.deps.json'
        original = json.loads((self.folder() / name).read_bytes())
        for variant in ('external-probe', 'unknown-assets', 'unbound-edge'):
            with self.subTest(variant=variant):
                value = copy.deepcopy(original)
                groups = next(iter(value['targets'].values()))['Mk8.Sava.Application/1.0']
                if variant == 'external-probe': value['runtimeStoreManifestNames'] = ['/outside']
                if variant == 'unknown-assets': groups['unprofiledAssets'] = {'/outside': {}}
                if variant == 'unbound-edge': groups['dependencies'] = {'Absent': '1.0'}
                self.replace_file(name, encoded(value)); self.refused()

    def test_dependency_reference_bound_and_manifest_library_set_correspondence(self):
        self.n['REL_DEP_REFERENCES'] = 4
        self.refused(message='reference bound')
        self.n['REL_DEP_REFERENCES'] = 8192
        name = 'application/Mk8.Sava.Application.deps.json'
        value = json.loads((self.folder() / name).read_bytes())
        value['libraries']['Unobserved/1.0'] = {'type': 'package'}
        self.replace_file(name, encoded(value)); self.refused(message='dependency target')

    def test_core_dependency_rows_cannot_be_replaced_by_an_empty_claim(self):
        name = 'gateway/Mk8.Sava.Gateway.deps.json'
        value = json.loads((self.folder() / name).read_bytes())
        groups = next(iter(value['targets'].values()))
        groups['Microsoft.NETCore.App.Runtime.linux-x64/10.0.4'].pop('runtime')
        self.replace_file(name, encoded(value)); self.refused(message='dependency rows required')

    def test_exponent_overflow_is_nonfinite_but_finite_configuration_numbers_remain_admitted(self):
        name = 'gateway/Mk8.Sava.Gateway.runtimeconfig.json'
        original = (self.folder() / name).read_bytes()
        for number in (b'1e400', b'-1e400'):
            with self.subTest(number=number):
                data = original.replace(b'"tfm":"net10.0"', b'"tfm":"net10.0","configProperties":{"fixture":' + number + b'}')
                self.replace_file(name, data); self.refused(message='nonfinite release number')
        data = original.replace(b'"tfm":"net10.0"', b'"tfm":"net10.0","configProperties":{"fixture":0.5}')
        self.replace_file(name, data)
        self.assertEqual(self.observe()['runtime'][1]['program'], 'Mk8.Sava.Gateway')

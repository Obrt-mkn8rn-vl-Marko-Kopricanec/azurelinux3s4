"""Source-grounded launch candidates and the actual emitted private entry."""

import deployment_fixture as net_fixture

import collections
import copy
import hashlib
import json
import os
import shlex
import shutil
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import Mock

from test_deployment_policy import emitted_program, encoded
from test_deployment_releases import CAPTURES, ROOT, ReleaseFixture


class DeploymentApplicationServiceTests(ReleaseFixture):
    def runtime_owners(self, units):
        owners = {}
        for row in units:
            values = [line.split('=', 1)[1] for line in row['content'].splitlines()
                      if line.startswith('RuntimeDirectory=')]
            for value in values:
                self.assertNotIn(' ', value)
                for previous in owners:
                    self.assertFalse(value == previous or value.startswith(previous + '/')
                                     or previous.startswith(value + '/'), 'overlapping runtime cleanup owners')
                owners[value] = row['file']
            self.assertNotIn('RuntimeDirectoryPreserve=restart', row['content'])
        return owners

    def unit_arguments(self, unit):
        return shlex.split(next(line.split('=', 1)[1] for line in unit.splitlines() if line.startswith('ExecStart=')))

    def candidate(self):
        return self.n['application_bundle'](encoded(self.value), self.n['bundle'])

    def replace_configuration(self, app, leaf, data):
        p = self.root / 'etc' / app / leaf; p.write_bytes(data)
        self.documents[app]['configuration'][leaf] = hashlib.sha256(data).hexdigest(); self.seal(app)

    def run_emitted(self):
        self.manifest_file.write_bytes(encoded(self.value))
        code = emitted_program()
        seam = "\nclass ApplicationPrivateRoot:\n    def __getattr__(self, name): return getattr(dep_os_original, name)\n    def open(self, path, flags, **kwargs):\n        if flags & (dep_os_original.O_WRONLY | dep_os_original.O_RDWR): raise ValueError('write forbidden by private delivery')\n        return dep_os_original.open(PRIVATE_ROOT if path == '/' else path, flags, **kwargs)\ndep_os_original = dep_os\nPRIVATE_ROOT = " + repr(str(self.root)) + "\ndep_os = ApplicationPrivateRoot()\nDEP_TRUSTED_UID = " + str(os.geteuid()) + "\n"
        code = code.replace("action = sys.argv[1]\n", seam + "action = sys.argv[1]\n")
        result = subprocess.run([sys.executable, '-I', '-', 'applications', '/manifest.json'],
                                input=code.encode(), capture_output=True, timeout=30, check=False)
        self.capture = {'kind': 'entire emitted program/private root-FD and UID delivery',
                        'program': code, 'original_program_sha256': hashlib.sha256(emitted_program().encode()).hexdigest(),
                        'input': self.manifest_file.read_bytes().decode('ascii'), 'wait': result.returncode,
                        'stdout': result.stdout.decode('ascii'), 'stderr': result.stderr.decode('ascii'),
                        'tree_after': self.snapshot()}
        return result

    def test_complete_nine_unit_candidate_binds_original_manifest_and_every_release(self):
        before = self.snapshot(); result = self.candidate()
        self.assertEqual(result['source']['sha256'], hashlib.sha256(encoded(self.value)).hexdigest())
        self.assertEqual(len(result['releases']), 4)
        self.assertEqual(len(result['files']), 9)
        self.assertEqual(len(result['configuration']), 10)
        self.assertEqual(len(result['authority']), 27)
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual(result['deployment_candidate_sha256'], hashlib.sha256(json.dumps(
            self.n['deployment_bundle'](encoded(self.value), self.n['bundle']), sort_keys=True, separators=(',', ':')).encode()).hexdigest())
        for row in result['files']:
            data = row['content'].encode('ascii')
            self.assertEqual(row['bytes'], len(data)); self.assertEqual(row['sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(row['mode'], '0644')
        self.assertEqual(before, self.snapshot())
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_launches_use_fixed_self_contained_programs_and_immutable_commit_paths(self):
        units = self.candidate()['files']
        for row in units:
            unit = row['content']; start = next(line for line in unit.splitlines() if line.startswith('ExecStart='))
            self.assertIn('/releases/' + '1' * 40 + '/', start)
            self.assertNotIn('/current', unit); self.assertNotIn('/usr/bin/dotnet', unit)
            self.assertIn('Type=exec\n', unit)
            self.assertIn('KillMode=control-group\n', unit)
            self.assertNotIn('MemoryDenyWriteExecute=', unit)
            self.assertNotIn('SystemCallFilter=', unit)
            self.assertIn('NoNewPrivileges=true\n', unit)

    def test_sava_separates_accounts_storage_and_only_exposes_private_gateway(self):
        units = {row['file']: row['content'] for row in self.candidate()['files']}
        application = units['systemd/mk8-sava-application.service']; gateway = units['systemd/mk8-sava-gateway.service']
        self.assertIn('User=mk8sava-application\n', application); self.assertIn('User=mk8sava-gateway\n', gateway)
        self.assertIn('StateDirectory=mk8.sava/application\n', application)
        self.assertIn('InaccessiblePaths=-/var/lib/mk8.sava/application\n', gateway)
        self.assertIn('--urls http://127.0.0.1:18580\n', gateway)
        self.assertNotIn('CAP_NET_BIND_SERVICE', application + gateway)
        for unit in (application, gateway):
            self.assertIn('LoadCredential=rpc-key:/etc/mk8.sava/rpc.key\n', unit)
            self.assertIn('Environment=ApplicationTransport__AccessKeyFile=%d/rpc-key\n', unit)

    def test_drava_bootstrap_and_email_configuration_use_manager_credentials(self):
        units = {row['file']: row['content'] for row in self.candidate()['files']}
        for role in ('application', 'gateway'):
            unit = units['systemd/mk8-drava-' + role + '.service']
            self.assertIn('--bootstrap %d/bootstrap.json\n', unit)
            self.assertIn('LoadCredential=bootstrap.json:/etc/mk8.drava/' + role + '.json\n', unit)
        gateway = units['systemd/mk8-email-gateway.service']; worker = units['systemd/mk8-email-worker.service']
        self.assertIn('mk8.email.Application.Worker --serve\n', worker)
        self.assertNotIn('--serve', gateway)
        self.assertIn('Environment=MK8EMAIL_CONFIG_FILE=%d/config.json\n', gateway)
        self.assertIn('LoadCredential=config.json:/etc/mk8.email/worker.json\n', worker)
        self.assertIn('http://127.0.0.1:18081\n', gateway)
        self.assertIn('CAP_NET_BIND_SERVICE', gateway); self.assertNotIn('CAP_NET_BIND_SERVICE', worker)

    def test_dns_keeps_controller_authority_and_public_gateway_distinct(self):
        units = {row['file']: row['content'] for row in self.candidate()['files']}
        controller = units['systemd/mk8-dns-controller.service']
        authority = units['systemd/mk8-dns-authoritative-replica.service']
        gateway = units['systemd/mk8-dns-gateway4.service']
        self.assertIn('--role controller --control /run/mk8.dns/controller/inputs/control.json\n', controller)
        self.assertIn('--role authoritative-replica --control /run/mk8.dns/authoritative-replica/inputs/control.json --publication-socket /run/mk8.dns/authoritative-replica/publication.sock\n', authority)
        self.assertNotIn('--dns-address', controller + authority)
        self.assertIn(('--socket /run/mk8.dns/authoritative-replica/control.sock --health-port 18053 --dns-address ' + (net_fixture.nat4()) + ' --dns-port 53\n'), gateway)
        self.assertNotIn('CAP_NET_BIND_SERVICE', controller + authority)
        self.assertIn('CAP_NET_BIND_SERVICE', gateway)

    def test_two_public_families_receive_distinct_dns_health_ports(self):
        self.value['public']['ipv6'] = net_fixture.PUBLIC6
        units = {row['file']: row['content'] for row in self.candidate()['files']}
        self.assertEqual(len(units), 10)
        self.assertIn(('--health-port 18053 --dns-address ' + (net_fixture.nat4())), units['systemd/mk8-dns-gateway4.service'])
        self.assertIn(('--health-port 18054 --dns-address ' + (net_fixture.PUBLIC6)), units['systemd/mk8-dns-gateway6.service'])
        self.value['private_ports']['email_http'] = 18054
        with self.assertRaisesRegex(ValueError, 'per-family DNS health'): self.candidate()

    def test_ipv6_only_public_and_null_admin_ipv6_are_preserved(self):
        self.value['admin']['ipv6'] = None
        self.value['public'].update(ipv4=None, ipv6=net_fixture.PUBLIC6)
        units = {row['file']: row['content'] for row in self.candidate()['files']}
        self.assertNotIn('systemd/mk8-dns-gateway4.service', units)
        self.assertIn(('--health-port 18053 --dns-address ' + (net_fixture.PUBLIC6)), units['systemd/mk8-dns-gateway6.service'])

    def test_configuration_hashes_are_bound_and_secret_bytes_are_not_serialized(self):
        result = self.candidate(); output = json.dumps(result)
        self.assertNotIn('private-fixture-only', output); self.assertNotIn('not-a-runtime-proof', output)
        self.assertNotIn('QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=', output)
        for row in result['configuration']:
            actual = (self.root / row['file'][1:]).read_bytes()
            self.assertEqual(row['bytes'], len(actual)); self.assertEqual(row['sha256'], hashlib.sha256(actual).hexdigest())
        p = self.root / 'etc/mk8.email/worker.json'; p.write_bytes(encoded({'changed': True}))
        with self.assertRaisesRegex(ValueError, 'configuration digest'): self.candidate()

    def test_missing_raw_release_refuses_even_if_old_candidate_is_supplied(self):
        old = self.candidate()
        self.value['stale_positive_application_receipt'] = old
        with self.assertRaisesRegex(ValueError, 'exact manifest'): self.candidate()
        del self.value['stale_positive_application_receipt']
        (self.folder('mk8.email') / 'release.json').unlink()
        with self.assertRaises(FileNotFoundError): self.candidate()

    def test_address_admission_precedes_release_observation(self):
        observer = Mock(); self.n['release_observe'] = observer
        self.value['public']['ipv6'] = ((net_fixture.PUBLIC6) + '%x\n  accept')
        with self.assertRaises(ValueError): self.candidate()
        observer.assert_not_called()

    def test_sava_environment_rejects_process_injection_and_unsafe_values(self):
        for body in (b'LD_PRELOAD=/evil.so\n', b'Gateway__StagingPath=/tmp/evil\nDOTNET_STARTUP_HOOKS=/evil.dll\n',
                     b'Gateway__StagingPath="/var/cache/mk8.sava-gateway/staging"\n',
                     b'Gateway__StagingPath=/var/cache/mk8.sava-gateway/staging\nGateway__StagingPath=/other\n'):
            with self.subTest(body=body):
                self.replace_configuration('mk8.sava', 'gateway.env', body)
                with self.assertRaisesRegex(ValueError, 'EnvironmentFile'): self.candidate()

    def test_sava_environment_cannot_override_manager_rpc_key_or_private_endpoint(self):
        original = (self.root / 'etc/mk8.sava/policy.env').read_bytes()
        for body in (original + b'ApplicationTransport__AccessKeyFile=/etc/private\n',
                     original.replace(b'127.0.0.1:18581', b'0.0.0.0:18581'),
                     original + b'Sava__DataEncryptionKeys__fixture=disclosed-to-gateway\n'):
            with self.subTest(body=body):
                self.replace_configuration('mk8.sava', 'policy.env', body)
                with self.assertRaisesRegex(ValueError, 'launch environment'): self.candidate()

    def test_rpc_key_and_startup_json_profiles_refuse_before_units_escape(self):
        for body in (b'AA==\n', b'QUFB\n\n', b'invalid!\n'):
            with self.subTest(body=body):
                self.replace_configuration('mk8.sava', 'rpc.key', body)
                with self.assertRaises(ValueError): self.candidate()
        self.replace_configuration('mk8.sava', 'rpc.key', b'QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=\n')
        self.replace_configuration('mk8.drava', 'gateway.json', b'{"schemaVersion":1,"schemaVersion":1}\n')
        with self.assertRaisesRegex(ValueError, 'duplicate'): self.candidate()

    def test_output_bound_withholds_the_whole_candidate(self):
        self.n['APP_OUTPUT_LIMIT'] = 1
        with self.assertRaisesRegex(ValueError, 'output bound'): self.candidate()

    def test_complete_emitted_program_observes_private_releases_and_produces_only_inactive_bytes(self):
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        value = json.loads(result.stdout)
        self.assertEqual(len(value['files']), 9); self.assertEqual(len(value['releases']), 4)
        self.assertEqual(value['source']['sha256'], hashlib.sha256(self.manifest_file.read_bytes()).hexdigest())
        self.assertTrue(all(flag is False for flag in value['authority'].values()))
        self.assertEqual(self.snapshot(), before)

    def test_complete_emitted_program_partial_fourth_release_is_specific_refusal_without_json(self):
        p = self.folder('mk8.email') / 'gateway/libcoreclr.so'; p.unlink()
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 75)
        self.assertEqual(result.stdout, b''); self.assertEqual(result.stderr, b'Application service candidate refused\n')
        self.assertEqual(self.snapshot(), before)

    def test_complete_emitted_program_changed_protected_configuration_is_refusal_without_json(self):
        (self.root / 'etc/mk8.drava/gateway.json').write_bytes(encoded({'changed': True}))
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 75)
        self.assertEqual(result.stdout, b''); self.assertEqual(result.stderr, b'Application service candidate refused\n')
        self.assertEqual(self.snapshot(), before)

    def test_new_cli_arity_and_help_are_explicit_before_host_preflight(self):
        data = (ROOT / 'Bootstrap/main.sh').read_text()
        self.assertLess(data.index('--application-service-policy)'), data.index('s4_preflight'))
        shell = (ROOT / 'Bootstrap/config.sh').read_text() + '\n' + data.split('if [[ ${BASH_SOURCE[0]} == "$0" ]]; then')[0] + '\n'
        shell += "s4_preflight() { return 99; }\ns4_application_service_policy() { printf '%s\\n' \"$1\"; }\ns4_main \"$@\"\n"
        wrong = subprocess.run(['bash', '-c', shell, 'private-cli', '--application-service-policy'], capture_output=True, check=False)
        right = subprocess.run(['bash', '-c', shell, 'private-cli', '--application-service-policy', '/manifest.json'], capture_output=True, check=False)
        self.assertEqual(wrong.returncode, 64); self.assertEqual(wrong.stdout, b'')
        self.assertEqual(right.returncode, 0); self.assertEqual(right.stdout, b'/manifest.json\n')
        help_result = subprocess.run(['bash', '-c', shell, 'private-cli', '--help'], capture_output=True, check=False)
        self.assertIn(b'--application-service-policy ROOT_MANIFEST_JSON', help_result.stdout)

    def test_runtime_owners_are_disjoint_for_each_public_family_delivery(self):
        for ipv4, ipv6 in ((net_fixture.nat4(), None), (None, net_fixture.PUBLIC6),
                           (net_fixture.nat4(), net_fixture.PUBLIC6)):
            with self.subTest(ipv4=ipv4, ipv6=ipv6):
                self.value['public'].update(ipv4=ipv4, ipv6=ipv6)
                result = self.candidate(); units = {row['file']: row['content'] for row in result['files']}
                self.assertEqual(self.runtime_owners(result['files']), {
                    'mk8.drava': 'systemd/mk8-drava-application.service',
                    'mk8.dns/controller': 'systemd/mk8-dns-controller.service',
                    'mk8.dns/authoritative-replica': 'systemd/mk8-dns-authoritative-replica.service'})
                for role in ('controller', 'authoritative-replica'):
                    args = self.unit_arguments(units['systemd/mk8-dns-' + role + '.service'])
                    self.assertEqual(args[args.index('--socket') + 1], '/run/mk8.dns/' + role + '/control.sock')
                replica = self.unit_arguments(units['systemd/mk8-dns-authoritative-replica.service'])
                self.assertEqual(replica[replica.index('--publication-socket') + 1],
                                 '/run/mk8.dns/authoritative-replica/publication.sock')
                control = json.loads((self.root / 'etc/mk8.dns/control-plane.json').read_bytes())
                self.assertEqual(control['PublicationSocket'], replica[replica.index('--publication-socket') + 1])
                self.assertIsNone(json.loads((self.root / 'etc/mk8.dns/authority.json').read_bytes()).get('PublicationSocket'))
                for family, present in ((4, ipv4), (6, ipv6)):
                    name = 'systemd/mk8-dns-gateway' + str(family) + '.service'
                    self.assertEqual(name in units, present is not None)
                    if present:
                        args = self.unit_arguments(units[name])
                        self.assertEqual(args[args.index('--socket') + 1], replica[replica.index('--socket') + 1])
                        self.assertNotIn('RuntimeDirectory=', units[name])
                self.assertNotIn('RuntimeDirectory=', units['systemd/mk8-drava-gateway.service'])
                self.assertTrue(all(flag is False for flag in result['authority'].values()))

    def test_modeled_dns_controller_stop_preserves_live_replica_endpoints(self):
        result = self.candidate(); owners = self.runtime_owners(result['files'])
        private = self.root / 'runtime-cleanup-model'; private.mkdir()
        for value in owners:
            (private / value).mkdir(parents=True)
        controller = private / 'mk8.dns/controller/control.sock'
        control = private / 'mk8.dns/authoritative-replica/control.sock'
        publication = private / 'mk8.dns/authoritative-replica/publication.sock'
        for p in (controller, control, publication):
            p.write_bytes(b'finite endpoint marker, not a socket or service\n')
        before = (control.read_bytes(), publication.read_bytes())
        shutil.rmtree(private / 'mk8.dns/controller')
        self.assertFalse(controller.exists())
        self.assertEqual((control.read_bytes(), publication.read_bytes()), before)
        self.assertTrue((private / 'mk8.dns').is_dir())

    def test_modeled_drava_gateway_stop_preserves_application_endpoint_and_configs(self):
        result = self.candidate(); owners = self.runtime_owners(result['files'])
        private = self.root / 'runtime-cleanup-model'; endpoint = private / 'mk8.drava/application.sock'
        endpoint.parent.mkdir(parents=True); endpoint.write_bytes(b'finite endpoint marker\n')
        configurations = {leaf: (self.root / 'etc/mk8.drava' / leaf).read_bytes()
                          for leaf in ('application.json', 'gateway.json')}
        for path, owner in owners.items():
            if owner == 'systemd/mk8-drava-gateway.service':
                shutil.rmtree(private / path)
        self.assertEqual(endpoint.read_bytes(), b'finite endpoint marker\n')
        for leaf, field in (('application.json', 'listen'), ('gateway.json', 'application')):
            self.assertEqual(json.loads(configurations[leaf])[field]['unixSocketPath'], '/var/lib/mk8.drava/application/application.sock')
            self.assertEqual((self.root / 'etc/mk8.drava' / leaf).read_bytes(), configurations[leaf])
        shutil.rmtree(private / 'mk8.drava')
        self.assertFalse(endpoint.exists())

    def test_runtime_owner_control_detects_shared_and_nested_cleanup_targets(self):
        result = self.candidate()
        for family in ('dns', 'drava'):
            with self.subTest(family=family):
                units = copy.deepcopy(result['files'])
                if family == 'dns':
                    unit = next(row for row in units if row['file'] == 'systemd/mk8-dns-controller.service')
                    unit['content'] = unit['content'].replace('RuntimeDirectory=mk8.dns/controller', 'RuntimeDirectory=mk8.dns')
                else:
                    unit = next(row for row in units if row['file'] == 'systemd/mk8-drava-gateway.service')
                    unit['content'] += 'RuntimeDirectory=mk8.drava\n'
                with self.assertRaisesRegex(AssertionError, 'overlapping runtime cleanup owners'):
                    self.runtime_owners(units)

    def test_drava_socket_binding_refuses_missing_mismatch_and_other_transports(self):
        for body in ({'schemaVersion': 1}, {'application': None},
                     {'application': {'unixSocketPath': '/run/mk8.drava/gateway.sock'}},
                     {'application': {'unixSocketPath': '/var/lib/mk8.drava/application/application.sock', 'namedPipeName': 'other'}},
                     {'application': {'unixSocketPath': '/var/lib/mk8.drava/application/application.sock', 'httpsAddress': 'https://127.0.0.1/'}}):
            with self.subTest(body=body):
                self.replace_configuration('mk8.drava', 'gateway.json', encoded(body))
                with self.assertRaisesRegex(ValueError, 'application-owned Unix socket'):
                    self.candidate()
        self.replace_configuration('mk8.drava', 'gateway.json', encoded({
            'application': {'unixSocketPath': '/var/lib/mk8.drava/application/application.sock'}}))
        self.replace_configuration('mk8.drava', 'application.json', encoded({
            'listen': {'unixSocketPath': '/run/mk8.drava/gateway.sock'}}))
        with self.assertRaisesRegex(ValueError, 'application-owned Unix socket'):
            self.candidate()

    def test_complete_emitted_program_bound_socket_mismatch_refuses_without_json(self):
        self.replace_configuration('mk8.drava', 'gateway.json', encoded({
            'application': {'unixSocketPath': '/run/mk8.drava/gateway.sock'}}))
        self.manifest_file.write_bytes(encoded(self.value))
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 75)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Application service candidate refused\n')
        self.assertEqual(self.snapshot(), before)

    def test_dns_publication_configuration_binds_replica_socket_and_refuses_legacy_or_wrong_role_paths(self):
        for value in (None, '/run/mk8.dns/publication.sock', '/run/mk8.dns/controller/publication.sock'):
            with self.subTest(value=value):
                self.replace_configuration('mk8.dns', 'control-plane.json', encoded({'PublicationSocket': value}))
                with self.assertRaisesRegex(ValueError, 'replica-owned publication socket'):
                    self.candidate()
        self.replace_configuration('mk8.dns', 'control-plane.json', encoded({
            'PublicationSocket': '/run/mk8.dns/authoritative-replica/publication.sock'}))
        self.replace_configuration('mk8.dns', 'authority.json', encoded({
            'PublicationSocket': '/run/mk8.dns/authoritative-replica/publication.sock'}))
        with self.assertRaisesRegex(ValueError, 'replica-owned publication socket'):
            self.candidate()

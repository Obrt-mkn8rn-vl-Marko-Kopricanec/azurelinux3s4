"""Inactive DNS credential correspondence and finite private preparation IO."""

import collections
import hashlib
import inspect
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from test_deployment_policy import encoded
from test_deployment_releases import ROOT, ReleaseFixture
import test_deployment_services as service_fixture


CAPTURES = []
namespace = {'__name__': 'credential_candidate_library'}
exec(compile((ROOT / 'Deployment/credentials.py').read_bytes(), 'Deployment/credentials.py', 'exec'), namespace)
PROGRAM = namespace['DNS_CREDENTIAL_PROGRAM']


class DNSCredentialCandidateTests(ReleaseFixture):
    runtime_owners = service_fixture.DeploymentApplicationServiceTests.runtime_owners
    unit_arguments = service_fixture.DeploymentApplicationServiceTests.unit_arguments
    candidate = service_fixture.DeploymentApplicationServiceTests.candidate
    replace_configuration = service_fixture.DeploymentApplicationServiceTests.replace_configuration
    run_emitted = service_fixture.DeploymentApplicationServiceTests.run_emitted
    def test_exact_role_unit_inputs_are_original_bound_and_secrets_stay_out_of_json(self):
        before = self.snapshot(); value = self.candidate()
        self.assertEqual([row['role'] for row in value['dns_credentials']], ['controller', 'authoritative-replica'])
        units = {row['file']: row['content'] for row in value['files']}
        for plan in value['dns_credentials']:
            unit = units['systemd/' + plan['unit']]
            self.assertEqual(len(plan['authority']), 11)
            self.assertTrue(all(flag is False for flag in plan['authority'].values()))
            command = shlex.split(next(line.split('=', 1)[1] for line in unit.splitlines() if line.startswith('ExecStartPre=')))
            self.assertEqual(command[:4], ['/usr/bin/python3', '-I', namespace['DNS_CREDENTIAL_HELPER_PATH'], plan['role']])
            expected = []
            for row in plan['inputs']:
                original = (self.root / row['source'][1:]).read_bytes()
                self.assertEqual((row['bytes'], row['sha256']), (len(original), hashlib.sha256(original).hexdigest()))
                self.assertEqual(row['destination'], '/run/mk8.dns/' + plan['role'] + '/inputs/' + row['id'])
                self.assertEqual(row['destination_mode'], '0400')
                self.assertIn('LoadCredential=' + row['id'] + ':' + row['source'] + '\n', unit)
                expected.append(row['id'] + ':' + str(len(original)) + ':' + row['sha256'])
            self.assertEqual(command[4:], expected)
        helper = value['dns_credential_helper']
        self.assertEqual(helper['mode'], '0755'); self.assertEqual(helper['content'], PROGRAM)
        self.assertEqual(helper['sha256'], hashlib.sha256(PROGRAM.encode('ascii')).hexdigest())
        self.assertNotIn('finite database input', json.dumps(value)); self.assertNotIn('finite key bytes', json.dumps(value))
        self.assertEqual(before, self.snapshot())
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_all_family_units_keep_disjoint_runtime_owners_and_matching_helper_paths(self):
        for ipv4, ipv6 in (('192.168.1.20', None), (None, '2606:4700:4700::1111'), ('192.168.1.20', '2606:4700:4700::1111')):
            with self.subTest(ipv4=ipv4, ipv6=ipv6):
                self.value['public'].update(ipv4=ipv4, ipv6=ipv6)
                value = self.candidate(); self.runtime_owners(value['files'])
                for row in value['dns_credentials']:
                    unit = next(item['content'] for item in value['files'] if item['file'] == 'systemd/' + row['unit'])
                    args = self.unit_arguments(unit)
                    self.assertEqual(args[args.index('--control') + 1], row['runtime_directory'] + '/control.json')
                    self.assertNotIn('RuntimeDirectory=mk8.dns\n', unit)

    def test_missing_nested_raw_input_refuses_even_with_stale_positive_plan(self):
        self.n['STALE_CREDENTIAL_PLAN'] = self.candidate()['dns_credentials']
        (self.root / 'etc/mk8.dns/controller/key.pem').unlink()
        before = self.snapshot()
        with self.assertRaises(FileNotFoundError): self.candidate()
        self.assertEqual(before, self.snapshot())

    def test_cross_role_and_unprofiled_configuration_references_refuse(self):
        original = json.loads((self.root / 'etc/mk8.dns/control-plane.json').read_bytes())
        for key, wrong in (('KeyFile', '/run/mk8.dns/authoritative-replica/inputs/key.pem'),
                           ('ConnectionStringFile', '/etc/mk8.dns/password'), ('KeyFile', '%d/key.pem')):
            with self.subTest(key=key, wrong=wrong):
                value = dict(original); value[key] = wrong
                self.replace_configuration('mk8.dns', 'control-plane.json', encoded(value))
                with self.assertRaisesRegex(ValueError, 'role-owned'): self.candidate()

    def test_replica_cannot_receive_database_or_signing_key(self):
        original = json.loads((self.root / 'etc/mk8.dns/authority.json').read_bytes())
        for changed in ('ConnectionStringFile', 'SigningKeyFile'):
            with self.subTest(changed=changed):
                value = json.loads(json.dumps(original))
                if changed == 'ConnectionStringFile': value[changed] = '/run/mk8.dns/authoritative-replica/inputs/database.txt'
                else: value['Zones'][0][changed] = '/run/mk8.dns/authoritative-replica/inputs/zone-11111111-1111-1111-1111-111111111111.pk8'
                self.replace_configuration('mk8.dns', 'authority.json', encoded(value))
                with self.assertRaisesRegex(ValueError, 'replica cannot|controller-owned'): self.candidate()

    def test_zone_signing_files_bind_original_binary_without_claiming_key_authentication(self):
        value = json.loads((self.root / 'etc/mk8.dns/control-plane.json').read_bytes())
        name = 'zone-' + value['Zones'][0]['ZoneId'] + '.pk8'
        value['Zones'][0]['SigningKeyFile'] = '/run/mk8.dns/controller/inputs/' + name
        file = self.root / 'etc/mk8.dns/controller' / name; data = b'\x00\xffbinary private delivery, not PKCS8 proof'
        file.write_bytes(data); file.chmod(0o600)
        self.replace_configuration('mk8.dns', 'control-plane.json', encoded(value))
        result = self.candidate(); row = next(row for row in result['dns_credentials'][0]['inputs'] if row['id'] == name)
        self.assertEqual(row['sha256'], hashlib.sha256(data).hexdigest())
        self.assertFalse(result['dns_credentials'][0]['authority']['key_material_authenticated'])
        self.assertFalse(result['dns_credentials'][0]['authority']['key_role_and_scope_validated'])

    def test_nested_file_kind_mode_link_and_size_refuse_before_candidate_publication(self):
        path = self.root / 'etc/mk8.dns/controller/key.pem'; original = path.read_bytes()
        for fault in ('mode', 'link', 'symlink', 'empty', 'large'):
            with self.subTest(fault=fault):
                path.unlink(); path.write_bytes(original); path.chmod(0o600)
                extra = path.parent / 'extra'
                if fault == 'mode': path.chmod(0o640)
                elif fault == 'link': os.link(path, extra)
                elif fault == 'symlink': path.unlink(); path.symlink_to('../authoritative-replica/key.pem')
                elif fault == 'empty': path.write_bytes(b'')
                elif fault == 'large': path.write_bytes(b'x' * 4097)
                with self.assertRaises((OSError, ValueError)): self.candidate()
                if extra.exists(): extra.unlink()

    def test_late_malformed_zone_refuses_after_earlier_valid_reference(self):
        original = json.loads((self.root / 'etc/mk8.dns/control-plane.json').read_bytes())
        for zones in (original['Zones'] * 2, original['Zones'] + [{'ZoneId': 'bad'}], original['Zones'] * 65, []):
            with self.subTest(zones=zones):
                value = dict(original); value['Zones'] = zones
                self.replace_configuration('mk8.dns', 'control-plane.json', encoded(value))
                with self.assertRaisesRegex(ValueError, 'zone'): self.candidate()

    def test_entire_emitted_candidate_has_helper_without_executing_it_or_writing_inputs(self):
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['dns_credential_helper']['content'], PROGRAM)
        self.assertEqual(len(value['dns_credentials']), 2)
        self.assertTrue(all(flag is False for flag in value['authority'].values()))
        self.assertEqual(before, self.snapshot())

    def test_entire_emitted_missing_nested_input_has_specific_no_json_refusal(self):
        (self.root / 'etc/mk8.dns/authoritative-replica/key.pem').unlink()
        before = self.snapshot(); result = self.run_emitted()
        self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Application service candidate refused\n')
        self.assertEqual(before, self.snapshot())


class HelperOS:
    """Root ancestry UID delivery; private files/IO and service UID are ordinary."""
    def __init__(self, root, runtime):
        self.root, self.runtime = root, runtime
        self.acquired, self.closed = [], []
        self.environ = {'CREDENTIALS_DIRECTORY': '/run/credentials/mk8-dns-controller.service'}

    def __getattr__(self, name): return getattr(os, name)

    def open(self, path, flags, *args, **kwargs):
        fd = os.open(str(self.root) if path == '/' else path, flags, *args, **kwargs)
        self.acquired.append(fd); return fd

    def close(self, fd):
        self.closed.append(fd); os.close(fd)

    def delivered(self, info):
        owned = {self.runtime.stat().st_ino} | {p.stat().st_ino for p in self.runtime.rglob('*') if p.is_dir()}
        if stat.S_ISDIR(info.st_mode) and info.st_ino not in owned:
            # Forward metadata exactly; only ancestry UID is a delivery model.
            class Info:
                st_uid = 0
                def __getattr__(self, name): return getattr(info, name)
            return Info()
        return info

    def fstat(self, fd): return self.delivered(os.fstat(fd))
    def stat(self, path, **kwargs): return self.delivered(os.stat(path, **kwargs))


class DNSCredentialHelperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path.home() / '.cache'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o700)
        self.runtime = self.root / 'run/mk8.dns/controller'; self.runtime.mkdir(parents=True, mode=0o700)
        self.source = self.root / 'run/credentials/mk8-dns-controller.service'; self.source.mkdir(parents=True, mode=0o700)
        for path in self.root.rglob('*'):
            if path.is_dir(): path.chmod(0o700)
        self.originals = {'control.json': b'{"finite":"control input"}\n', 'database.txt': b'finite secret\n', 'key.pem': b'finite key\n'}
        for name, data in self.originals.items():
            path = self.source / name; path.write_bytes(data); path.chmod(0o440)
        self.arguments = ['controller'] + [name + ':' + str(len(data)) + ':' + hashlib.sha256(data).hexdigest() for name, data in sorted(self.originals.items())]
        self.n = {'__name__': 'dns_credential_private_delivery'}; exec(compile(PROGRAM, 'candidate-helper', 'exec'), self.n)
        self.delivery = HelperOS(self.root, self.runtime); self.n['os'] = self.delivery

    def prepare(self): return self.n['prepare'](self.arguments)

    def source_snapshot(self):
        return {p.name: (p.read_bytes(), stat.S_IMODE(p.stat().st_mode)) for p in self.source.iterdir() if p.is_file() and not p.is_symlink()}

    def checked_closes(self):
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_acl_mask_mode_input_becomes_exact_owner_only_bytes_without_source_change(self):
        before = self.source_snapshot(); self.prepare()
        target = self.runtime / 'inputs'; self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
        self.assertEqual({p.name for p in target.iterdir()}, set(self.originals))
        for name, data in self.originals.items():
            file = target / name; self.assertEqual(file.read_bytes(), data)
            self.assertEqual(stat.S_IMODE(file.stat().st_mode), 0o400); self.assertEqual(file.stat().st_uid, os.geteuid())
            self.assertEqual(file.stat().st_nlink, 1)
        self.assertEqual(before, self.source_snapshot()); self.checked_closes()

    def test_existing_foreign_or_partial_inputs_refuse_without_overwrite_or_cleanup(self):
        target = self.runtime / 'inputs'; target.mkdir(mode=0o700)
        marker = target / 'peer.sock'; marker.write_bytes(b'finite foreign endpoint marker')
        before = self.source_snapshot()
        with self.assertRaises(FileExistsError): self.prepare()
        self.assertEqual(marker.read_bytes(), b'finite foreign endpoint marker')
        self.assertEqual(before, self.source_snapshot()); self.checked_closes()

    def test_wrong_input_hash_refuses_before_runtime_directory_creation(self):
        path = self.source / 'key.pem'; path.chmod(0o600); path.write_bytes(b'changed key'); path.chmod(0o440)
        with self.assertRaisesRegex(ValueError, 'commitment|read-only'): self.prepare()
        self.assertFalse((self.runtime / 'inputs').exists()); self.checked_closes()

    def test_source_alias_kind_mode_and_extra_entries_refuse(self):
        for fault in ('symlink', 'hardlink', 'writable', 'fifo', 'extra'):
            with self.subTest(fault=fault):
                path = self.source / 'key.pem'; path.unlink(); path.write_bytes(self.originals['key.pem']); path.chmod(0o440)
                extra = self.source / 'extra'
                if fault == 'symlink': path.unlink(); path.symlink_to('database.txt')
                elif fault == 'hardlink': os.link(path, self.source / 'alias')
                elif fault == 'writable': path.chmod(0o640)
                elif fault == 'fifo': path.unlink(); os.mkfifo(path)
                else: extra.write_bytes(b'extra')
                with self.assertRaises((OSError, ValueError)): self.prepare()
                self.assertFalse((self.runtime / 'inputs').exists()); self.checked_closes()
                for name in ('alias', 'extra'):
                    p = self.source / name
                    if p.exists(): p.unlink()

    def test_short_and_zero_writes_leave_partial_data_without_success(self):
        original = self.delivery.write; calls = []
        def written(fd, data):
            calls.append(len(data))
            if len(calls) == 1: return original(fd, data[:1])
            return 0
        self.delivery.write = written
        before = self.source_snapshot()
        with self.assertRaisesRegex(ValueError, 'short write'): self.prepare()
        self.assertTrue((self.runtime / 'inputs').is_dir())
        self.assertEqual((self.runtime / 'inputs/control.json').read_bytes(), self.originals['control.json'][:1])
        self.assertEqual(before, self.source_snapshot()); self.checked_closes()

    def test_checked_close_failure_prevents_success_after_written_file(self):
        original = self.delivery.close; fired = []
        def closed(fd):
            writable = (stat.S_ISREG(os.fstat(fd).st_mode)
                        and os.readlink('/proc/self/fd/' + str(fd)).startswith(str(self.runtime / 'inputs') + '/'))
            original(fd)
            if writable and not fired:
                fired.append(fd); raise OSError('finite checked-close fault after actual close')
        self.delivery.close = closed
        with self.assertRaisesRegex(OSError, 'checked-close'): self.prepare()
        self.assertEqual(len(fired), 1)
        self.assertEqual((self.runtime / 'inputs/control.json').read_bytes(), self.originals['control.json'])
        self.checked_closes()

    def test_post_copy_source_change_refuses_without_cleanup(self):
        original = self.delivery.mkdir
        def created(path, *args, **kwargs):
            original(path, *args, **kwargs)
            source = self.source / 'key.pem'; source.chmod(0o600); source.write_bytes(b'changed after admission'); source.chmod(0o440)
        self.delivery.mkdir = created
        with self.assertRaises(ValueError): self.prepare()
        self.assertEqual((self.runtime / 'inputs/key.pem').read_bytes(), self.originals['key.pem'])
        self.checked_closes()

    def run_entire_helper(self):
        # The entire returned program executes only on private paths. The seam
        # redirects its root FD and delivers root ancestry UID metadata, without
        # an actual PID1/ACL/account/installed helper or application invocation.
        body = PROGRAM.replace("if __name__ == '__main__':", "if __name__ == 'unshipped_private_guard':")
        delivered = inspect.getsource(HelperOS).replace('os.', 'actual_os.').replace('getattr(os,', 'getattr(actual_os,')
        seam = '\nfrom pathlib import Path\nactual_os = os\n' + delivered
        seam += '\nos = HelperOS(Path(' + repr(str(self.root)) + '), Path(' + repr(str(self.runtime)) + '))\nraise SystemExit(main())\n'
        program = body + seam
        result = subprocess.run([sys.executable, '-I', '-', *self.arguments], input=program.encode('ascii'),
                                capture_output=True, timeout=10, check=False)
        self.capture = {'program': program, 'original_program_sha256': hashlib.sha256(PROGRAM.encode('ascii')).hexdigest(),
                        'arguments': self.arguments, 'wait': result.returncode,
                        'stdout': result.stdout.decode('ascii'), 'stderr': result.stderr.decode('ascii')}
        return result

    def test_entire_private_helper_prepares_exact_bytes_with_empty_output(self):
        before = self.source_snapshot(); result = self.run_entire_helper()
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(result.stdout, b''); self.assertEqual(result.stderr, b'')
        for name, data in self.originals.items():
            path = self.runtime / 'inputs' / name
            self.assertEqual(path.read_bytes(), data); self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o400)
        self.assertEqual(before, self.source_snapshot())

    def test_entire_private_helper_bad_hash_refuses_without_output_or_runtime_write(self):
        self.arguments[-1] = self.arguments[-1].rsplit(':', 1)[0] + ':' + '0' * 64
        before = self.source_snapshot(); result = self.run_entire_helper()
        self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'DNS credential preparation refused\n')
        self.assertFalse((self.runtime / 'inputs').exists()); self.assertEqual(before, self.source_snapshot())

    def test_replica_copies_only_control_and_verification_input_into_its_own_leaf(self):
        role = 'authoritative-replica'
        self.runtime = self.root / 'run/mk8.dns' / role; self.runtime.mkdir(mode=0o700)
        self.source = self.root / 'run/credentials' / ('mk8-dns-' + role + '.service'); self.source.mkdir(mode=0o700)
        self.originals = {name: data for name, data in self.originals.items() if name != 'database.txt'}
        for name, data in self.originals.items():
            path = self.source / name; path.write_bytes(data); path.chmod(0o400)
        self.delivery = HelperOS(self.root, self.runtime); self.n['os'] = self.delivery
        self.delivery.environ['CREDENTIALS_DIRECTORY'] = '/run/credentials/mk8-dns-' + role + '.service'
        self.arguments = [role] + [name + ':' + str(len(data)) + ':' + hashlib.sha256(data).hexdigest() for name, data in sorted(self.originals.items())]
        before = self.source_snapshot(); self.prepare()
        self.assertEqual({p.name for p in (self.runtime / 'inputs').iterdir()}, {'control.json', 'key.pem'})
        self.assertFalse((self.root / 'run/mk8.dns/controller/inputs').exists())
        self.assertEqual(before, self.source_snapshot()); self.checked_closes()

    def test_maximum_controller_signing_set_is_complete_and_excess_refuses_before_new_io(self):
        for index in range(64):
            name = 'zone-' + format(index, '08x') + '-1111-1111-1111-111111111111.pk8'
            data = bytes((index, 0, 255))
            self.originals[name] = data
            path = self.source / name; path.write_bytes(data); path.chmod(0o440)
        self.arguments = ['controller'] + [name + ':' + str(len(data)) + ':' + hashlib.sha256(data).hexdigest() for name, data in sorted(self.originals.items())]
        self.assertEqual(len(self.arguments), 68); self.prepare()
        self.assertEqual({p.name for p in (self.runtime / 'inputs').iterdir()}, set(self.originals))
        before = len(self.delivery.acquired)
        with self.assertRaisesRegex(ValueError, 'bounded DNS role'): self.n['prepare'](self.arguments + [self.arguments[-1]])
        self.assertEqual(len(self.delivery.acquired), before); self.checked_closes()

    def test_runtime_leaf_mode_and_symlink_ancestry_refuse_without_cleanup(self):
        before = self.source_snapshot(); self.runtime.chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'owner-only runtime'): self.prepare()
        self.runtime.chmod(0o700)
        held = self.runtime.with_name('controller-held'); self.runtime.rename(held)
        self.runtime.symlink_to(held.name, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'directory'): self.prepare()
        self.assertTrue(self.runtime.is_symlink()); self.assertFalse((held / 'inputs').exists())
        self.assertEqual(before, self.source_snapshot()); self.checked_closes()

    def test_mismatched_environment_root_identity_and_role_sets_refuse_before_io(self):
        for changed in ('environment', 'root', 'role', 'duplicate', 'order', 'size', 'hash'):
            with self.subTest(changed=changed):
                args = list(self.arguments); env = self.delivery.environ['CREDENTIALS_DIRECTORY']
                uid = self.delivery.geteuid
                if changed == 'environment': self.delivery.environ['CREDENTIALS_DIRECTORY'] += '/other'
                elif changed == 'root': self.delivery.geteuid = lambda: 0
                elif changed == 'role': args[0] = 'authoritative-replica'
                elif changed == 'duplicate': args.append(args[-1])
                elif changed == 'order': args[1:] = args[:0:-1]
                elif changed == 'size': args[-1] = args[-1].replace(':11:', ':99999:')
                else: args[-1] = args[-1][:-1] + 'X'
                with self.assertRaises(ValueError): self.n['prepare'](args)
                self.assertFalse((self.runtime / 'inputs').exists())
                self.delivery.environ['CREDENTIALS_DIRECTORY'] = env; self.delivery.geteuid = uid
        self.checked_closes()


if __name__ == '__main__': unittest.main()

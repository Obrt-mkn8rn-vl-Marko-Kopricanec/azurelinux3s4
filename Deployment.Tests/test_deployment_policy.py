"""Explicit manifest, private FD deliveries and candidate policy regressions."""

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
LIBRARIES = ('SSH/policy.py', 'SSH/service.py', 'Deployment/configuration.py', 'Deployment/policy.py', 'Deployment/postgresql_profile.py')
CAPTURES = []


def library():
    namespace = {'__name__': 'deployment_private_library'}
    for name in LIBRARIES:
        exec(compile((ROOT / name).read_bytes(), str(ROOT / name), 'exec'), namespace)
    return namespace


def manifest(ipv6=True):
    return {'schema': 1, 'hardware': 'Dell R630', 'architecture': 'x86_64', 'os': 'Azure Linux 3',
            'admin': {'ipv4': {'interface': 'eno1.90', 'address': '192.168.90.10', 'routers': ['192.168.90.1']},
                      'ipv6': {'interface': 'eno1.90', 'address': 'fd51:b089:f5e0:90::10', 'routers': ['fd51:b089:f5e0:90::1']} if ipv6 else None},
            'public': {'interface': 'eno2', 'topology': 'nat', 'ipv4': '192.168.1.20', 'ipv6': None},
            'domains': {app: app.split('.')[1] + '.example.test' for app in ('mk8.sava', 'mk8.drava', 'mk8.dns', 'mk8.email')},
            'dns_zone': 'example.test',
            'releases': {app: {'commit': '1' * 40, 'tree': '2' * 40, 'manifest_sha256': '3' * 64} for app in ('mk8.sava', 'mk8.drava', 'mk8.dns', 'mk8.email')},
            'private_ports': {'sava_gateway': 18580, 'sava_application': 18581, 'email_http': 18081, 'email_admin': 18082, 'dns_health': 18053},
            'mail': {'implicit_submission': False, 'pop3s': False, 'sieve': False}}


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


def emitted_program():
    # Inspect the actual shared emitted Python text, not an alternate compiler.
    data = (ROOT / 'azurelinux3s4.sh').read_text()
    start = data.index('s4_ssh_candidate() {\n')
    return data[start:].split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0] + '\n'


class PrivateOS:
    """Delivery model for root FD/UID; all private IO otherwise stays ordinary."""

    def __init__(self, root):
        self.root = str(root)
        self.acquired = []
        self.closed = []

    def __getattr__(self, name):
        return getattr(os, name)

    def open(self, path, flags, **kwargs):
        fd = os.open(self.root if path == '/' else path, flags, **kwargs)
        self.acquired.append(fd)
        return fd

    def close(self, fd):
        self.closed.append(fd)
        os.close(fd)


class DeploymentPolicyTests(unittest.TestCase):
    def setUp(self):
        self.n = library()

    def candidate(self, value=None):
        return self.n['deployment_bundle'](encoded(manifest() if value is None else value), self.n['bundle'])

    def refuse(self, value):
        with self.assertRaises((ValueError, TypeError)):
            self.candidate(value)

    def test_complete_candidate_hashes_domains_authorities_and_single_ingress(self):
        data = encoded(manifest()); result = self.candidate()
        self.assertEqual(result['source'], {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
        self.assertEqual(len(result['files']), 5)
        for entry in result['files']:
            actual = entry['content'].encode('ascii')
            self.assertTrue(actual.endswith(b'\n'))
            self.assertEqual(entry['bytes'], len(actual))
            self.assertEqual(entry['sha256'], hashlib.sha256(actual).hexdigest())
        self.assertEqual(len(result['authority']), 24)
        self.assertTrue(all(value is False for value in result['authority'].values()))
        contract = json.loads(result['files'][-1]['content'])
        self.assertEqual(len(contract['applications']), 4)
        self.assertIn('mk8.drava ONLY', contract['port_owners']['http_80_https_443'])
        self.assertIn('SQLite', contract['storage']['mk8.sava'])
        self.assertIn('JIT', contract['runtime'])

    def test_exact_admin_prefixes_exclude_general_private_and_ula(self):
        result = self.candidate()
        self.assertEqual(result['ssh_policy']['source_prefixes'], ['192.168.90.0/24', 'fd51:b089:f5e0:90::/64'])
        ssh = result['files'][0]['content']
        self.assertIn('ListenAddress 192.168.90.10\n', ssh)
        self.assertIn('ListenAddress fd51:b089:f5e0:90::10\n', ssh)
        self.assertNotIn('fc00::/7', ssh)
        self.assertNotIn('192.168.0.0/16', ssh)
        self.assertNotIn('ListenAddress 0.0.0.0', ssh)

    def test_unassigned_admin_ipv6_omits_listener_independently_of_public_ipv6(self):
        value = manifest(False); value['public']['ipv6'] = '2606:4700:4700::1111'
        result = self.candidate(value)
        self.assertEqual(result['ssh_policy']['listen_addresses'], ['192.168.90.10'])
        nft = result['files'][1]['content']
        self.assertNotIn('fd51:b089:f5e0:90', nft)
        self.assertIn('ip6 daddr 2606:4700:4700::1111', nft)
        self.assertIn('packet-too-big', nft)

    def test_ssh_router_and_destination_checks_precede_stateful_and_loopback_accept(self):
        nft = self.candidate()['files'][1]['content']
        self.assertLess(nft.index('saddr { 192.168.90.1 } tcp dport 22 drop'), nft.index('saddr 192.168.90.0/24'))
        self.assertIn('iifname "eno1.90" ip saddr 192.168.90.0/24 ip daddr 192.168.90.10 tcp dport 22 accept', nft)
        self.assertLess(nft.index('  tcp dport 22 drop'), nft.index('iifname "lo" accept'))
        self.assertLess(nft.index('  tcp dport 22 drop'), nft.index('ct state established,related accept'))

    def test_dns_both_transports_mail_options_default_drop_and_no_flush(self):
        result = self.candidate(); nft = result['files'][1]['content']
        self.assertIn('tcp dport { 25, 53, 80, 443, 587, 993 }', nft)
        self.assertIn('udp dport 53 accept', nft)
        self.assertEqual(nft.count('policy drop;'), 2)
        self.assertNotIn('flush', '\n'.join(nft.splitlines()[1:]))
        value = manifest(); value['mail'] = {key: True for key in value['mail']}
        self.assertIn('tcp dport { 25, 53, 80, 443, 465, 587, 993, 995, 4190 }', self.candidate(value)['files'][1]['content'])

    def test_postgresql_private_independent_scram_roles_and_explicit_final_reject(self):
        result = self.candidate(); config = result['files'][2]['content']; hba = result['files'][3]['content']
        self.assertIn("listen_addresses = '127.0.0.1,::1'", config)
        self.assertEqual(hba.count('scram-sha-256'), 5)
        self.assertIn('host mk8dns mk8dns', hba)
        self.assertIn('host mk8email mk8email', hba)
        self.assertTrue(hba.endswith('host all all 0.0.0.0/0 reject\nhost all all ::0/0 reject\n'))
        self.assertNotIn('trust', hba)

    def test_unknown_missing_and_wrong_target_profile(self):
        for change in ('extra', 'missing', 'bool_schema', 'arm', 'debian', 'other_hardware'):
            with self.subTest(change=change):
                value = manifest()
                if change == 'extra': value['command'] = 'systemctl start sshd'
                elif change == 'missing': del value['releases']
                elif change == 'bool_schema': value['schema'] = True
                elif change == 'arm': value['architecture'] = 'aarch64'
                elif change == 'debian': value['os'] = 'Debian 13'
                else: value['hardware'] = 'another host'
                self.refuse(value)

    def test_admin_wildcard_public_linklocal_other_prefix_boundary_or_mapped_refuses(self):
        for version, addresses in (('ipv4', ('0.0.0.0', '8.8.8.8', '192.168.91.10', '192.168.90.0', '192.168.90.255', '192.168.090.10')),
                                   ('ipv6', ('::', 'fe80::10', '::ffff:c0a8:5a0a', 'fd51:b089:f5e0:91::10', 'fd51:b089:f5e0:90::', 'fd51:b089:f5e0:90::10%eno1'))):
            for address in addresses:
                with self.subTest(address=address):
                    value = manifest(); value['admin'][version]['address'] = address; self.refuse(value)

    def test_interface_syntax_and_admin_public_collision(self):
        for interface in ('lo', 'eno1.90', 'eno2" accept', 'eno2\n', 'e' * 16, '*', '../eno2'):
            with self.subTest(interface=interface):
                value = manifest(); value['public']['interface'] = interface; self.refuse(value)

    def test_router_exclusion_requires_unique_exact_same_prefix_nonlistener_addresses(self):
        for routers in ([], ['192.168.90.10'], ['192.168.91.1'], ['192.168.90.1'] * 2, ['192.168.90.255'], '192.168.90.1'):
            with self.subTest(routers=routers):
                value = manifest(); value['admin']['ipv4']['routers'] = routers; self.refuse(value)

    def test_public_listener_mode_and_address_admission(self):
        for public in ({'topology': 'direct'}, {'ipv4': '192.168.90.20'}, {'ipv4': '127.0.0.1'},
                       {'ipv4': None}, {'ipv6': 'fd51:b089:f5e0:90::20'}, {'topology': 'vpn'}):
            with self.subTest(public=public):
                value = manifest(); value['public'].update(public); self.refuse(value)
        value = manifest(); value['public'].update(topology='direct', ipv4='8.8.8.8')
        self.assertEqual(self.candidate(value)['manifest']['topology'], 'direct')

    def test_public_ipv6_site_local_and_reserved_refuse_before_candidate_producers(self):
        for address in ('fec0::1', 'feff::1', '4000::1', '8000::1', '1fff::1'):
            with self.subTest(address=address):
                value = manifest(); value['public']['ipv6'] = address
                producer = Mock(wraps=self.n['bundle'])
                with self.assertRaisesRegex(ValueError, 'public IPv6 GUA profile'):
                    self.n['deployment_bundle'](encoded(value), producer)
                producer.assert_not_called()

    def test_supported_unscoped_public_gua_preserves_dual_family_and_null_admin_profiles(self):
        for admin6, public4 in ((True, '192.168.1.20'), (False, '192.168.1.20'), (False, None)):
            with self.subTest(admin6=admin6, public4=public4):
                value = manifest(admin6)
                value['public'].update(ipv4=public4, ipv6='2001:4860::1')
                result = self.candidate(value)
                public6 = [row for row in result['manifest']['public'] if row['version'] == 6]
                self.assertEqual(public6, [{'version': 6, 'address': '2001:4860::1', 'interface': 'eno2'}])
                self.assertIn('ip6 daddr 2001:4860::1 tcp dport', result['files'][1]['content'])
                self.assertEqual(result['ssh_policy']['listen_addresses'], ['192.168.90.10']
                                 + (['fd51:b089:f5e0:90::10'] if admin6 else []))
                self.assertTrue(all(item is False for item in result['authority'].values()))

    def test_public_ipv6_scope_suffix_refuses_before_candidate_producers(self):
        for suffix in ('%eth0', '%1', '%x accept'):
            with self.subTest(suffix=suffix):
                value = manifest(); value['public']['ipv6'] = '2001:4860::1' + suffix
                producer = Mock(wraps=self.n['bundle'])
                with self.assertRaises(ValueError):
                    self.n['deployment_bundle'](encoded(value), producer)
                producer.assert_not_called()

    def test_public_ipv6_json_escaped_newline_scope_refuses_before_serialization(self):
        value = manifest(); value['public']['ipv6'] = '2001:4860::1%x\n  accept'
        data = encoded(value)
        self.assertIn(b'\\n  accept', data)
        self.assertEqual(data.count(b'\n'), 1)
        decoded, _ = self.n['deployment_decode'](data)
        self.assertEqual(decoded['public']['ipv6'], value['public']['ipv6'])
        producer = Mock(wraps=self.n['bundle'])
        with self.assertRaises(ValueError):
            self.n['deployment_bundle'](data, producer)
        producer.assert_not_called()

    def test_admin_ipv6_router_scope_suffix_refuses_before_candidate_producers(self):
        for suffix in ('%eth0', '%1', '%x accept'):
            with self.subTest(suffix=suffix):
                value = manifest()
                value['admin']['ipv6']['routers'].append('fd51:b089:f5e0:90::2' + suffix)
                producer = Mock(wraps=self.n['bundle'])
                with self.assertRaises(ValueError):
                    self.n['deployment_bundle'](encoded(value), producer)
                producer.assert_not_called()

    def test_admin_ipv6_router_json_escaped_controls_refuse_before_serialization(self):
        for control in ('\n  accept', '\r drop', '\t #', '\x00', '\x1f', '\x7f', '\u0085', '\u2028', '\u2029'):
            with self.subTest(control=repr(control)):
                value = manifest()
                value['admin']['ipv6']['routers'].append('fd51:b089:f5e0:90::2%x' + control)
                data = encoded(value)
                self.assertEqual(data.count(b'\n'), 1)
                self.assertTrue(all(byte < 128 for byte in data))
                decoded, _ = self.n['deployment_decode'](data)
                self.assertEqual(decoded['admin']['ipv6']['routers'], value['admin']['ipv6']['routers'])
                producer = Mock(wraps=self.n['bundle'])
                with self.assertRaises(ValueError):
                    self.n['deployment_bundle'](data, producer)
                producer.assert_not_called()

    def test_admin_ipv6_listener_scope_and_decoded_whitespace_refuse_before_ssh(self):
        for suffix in ('%eth0', '%1', '%x\n  accept', '\n', ' ', '\t'):
            with self.subTest(suffix=suffix):
                value = manifest(); value['admin']['ipv6']['address'] += suffix
                producer = Mock(wraps=self.n['bundle'])
                with self.assertRaises(ValueError):
                    self.n['deployment_bundle'](encoded(value), producer)
                producer.assert_not_called()

    def test_domains_distinct_canonical_bounded_under_declared_zone(self):
        for domain in ('Sava.example.test', 'sava.example.test.', 'sava.other.test', '-sava.example.test', 'email.example.test', 'a' * 64 + '.example.test', 'sava\n.example.test'):
            with self.subTest(domain=domain):
                value = manifest(); value['domains']['mk8.sava'] = domain; self.refuse(value)

    def test_release_commit_tree_and_manifest_hash_are_required_not_current_links(self):
        for key, bad in (('commit', 'HEAD'), ('tree', '2' * 39), ('manifest_sha256', 'G' * 64), ('commit', '../a')):
            with self.subTest(key=key, bad=bad):
                value = manifest(); value['releases']['mk8.sava'][key] = bad; self.refuse(value)
        contract = json.loads(self.candidate()['files'][-1]['content'])
        self.assertTrue(all('/releases/' + '1' * 40 in app['release_directory'] for app in contract['applications']))
        self.assertTrue(all(app['release_contents_observed'] is False for app in contract['applications']))

    def test_private_backend_ports_refuse_collisions_privileged_postgresql_and_bools(self):
        for port in (True, 80, 5432, 4190, 65536, 18581, '18081'):
            with self.subTest(port=port):
                value = manifest(); value['private_ports']['email_http'] = port; self.refuse(value)

    def test_mail_switches_are_typed_no_plaintext_imap_or_pop_listeners(self):
        value = manifest(); value['mail']['pop3s'] = 1; self.refuse(value)
        nft = self.candidate()['files'][1]['content']
        self.assertNotIn(', 110,', nft)
        self.assertNotIn(', 143,', nft)

    def test_duplicate_nonfinite_unicode_controls_limits_and_missing_final_lf_refuse(self):
        data = encoded(manifest())
        for bad in (data.replace(b'"schema":1', b'"schema":1,"schema":1'),
                    data.replace(b'"schema":1', b'"schema":NaN'), data[:-1], data + b'\r',
                    data.replace(b'example.test', 'exam\u2028ple.test'.encode()), b' ' * (64 * 1024) + b'\n',
                    data.replace(b'example.test', b'example\\u0085.test')):
            with self.subTest(hash=hashlib.sha256(bad).hexdigest()):
                with self.assertRaises(ValueError):
                    self.n['deployment_bundle'](bad, self.n['bundle'])

    def test_old_ssh_service_and_policy_functions_keep_exact_globals_and_behavior(self):
        old = {'__name__': 'deployment_private_library'}
        for name in LIBRARIES[:2]: exec(compile((ROOT / name).read_bytes(), name, 'exec'), old)
        for key, value in old.items():
            if isinstance(value, types.FunctionType):
                self.assertEqual(value.__code__, self.n[key].__code__)
            elif key not in ('__builtins__', '__doc__'):
                self.assertEqual(value, self.n[key])
        self.assertEqual(old['bundle'](), self.n['bundle']())
        self.assertEqual(old['service_bundle'](old['bundle']), self.n['service_bundle'](self.n['bundle']))


class ProtectedManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='s4-deployment-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.n = library(); self.delivery = PrivateOS(self.root)
        self.n['dep_os'] = self.delivery
        self.n['DEP_TRUSTED_UID'] = os.geteuid()
        self.path = self.root / 'inputs'; self.path.mkdir(mode=0o700)
        self.file = self.path / 'manifest.json'; self.data = encoded(manifest())
        self.file.write_bytes(self.data); self.file.chmod(0o600)

    def read(self):
        return self.n['deployment_read']('/inputs/manifest.json')

    def assert_closed(self):
        self.assertEqual(sorted(self.delivery.acquired), sorted(self.delivery.closed))

    def test_positive_actual_eof_repeated_bytes_and_all_private_descriptors_closed(self):
        self.assertEqual(self.read(), self.data)
        self.assertEqual(self.file.read_bytes(), self.data)
        self.assert_closed()
        self.assertEqual(len(self.delivery.acquired), 4)

    def test_euid_refusal_before_open(self):
        self.n['DEP_TRUSTED_UID'] = os.geteuid() + 1
        with self.assertRaises(ValueError): self.read()
        self.assertEqual(self.delivery.acquired, [])

    def test_path_profile_refuses_relative_traversal_empty_unicode_and_component_bounds(self):
        for path in ('inputs/manifest.json', '//inputs/manifest.json', '/inputs/../manifest.json', '/inputs/./manifest.json',
                     '/inputs/', '/in\u2028puts/manifest.json', '/a/' + 'x' * 256, '/' + '/'.join(['a'] * 17)):
            with self.subTest(path=path):
                with self.assertRaises(ValueError): self.n['deployment_read'](path)
        self.assertEqual(self.delivery.acquired, [])

    def test_directory_symlink_or_writable_ancestry_refuses(self):
        self.path.chmod(0o777)
        with self.assertRaises(ValueError): self.read()
        self.path.chmod(0o700)
        self.path.rename(self.root / 'real'); self.path.symlink_to(self.root / 'real', target_is_directory=True)
        with self.assertRaises(ValueError): self.read()
        self.assert_closed()

    def test_leaf_symlink_fifo_multiple_links_empty_oversize_or_non0600_refuses(self):
        for kind in ('symlink', 'fifo', 'hardlink', 'empty', 'oversize', '0644'):
            with self.subTest(kind=kind):
                self.file.unlink(missing_ok=True)
                if kind == 'symlink': self.file.symlink_to(self.root / 'outside')
                elif kind == 'fifo': os.mkfifo(self.file, 0o600)
                else:
                    self.file.write_bytes(b'' if kind == 'empty' else b'x' * (65537 if kind == 'oversize' else 10)); self.file.chmod(0o600)
                    if kind == 'hardlink': os.link(self.file, self.root / 'extra')
                    if kind == '0644': self.file.chmod(0o644)
                before = len(self.delivery.acquired)
                with self.assertRaises(ValueError): self.read()
                self.assertEqual(len(self.delivery.acquired) - before, 2)
        self.assert_closed()

    def test_actual_overflow_not_stat_size_is_bounded(self):
        fd = os.open(self.file, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        with patch.object(self.delivery, 'read', return_value=b'x' * 8192):
            with self.assertRaisesRegex(ValueError, 'EOF bound'):
                self.n['deployment_bytes'](fd)

    def test_two_read_byte_drift_and_equal_byte_metadata_drift_refuse(self):
        actual_read = os.read
        changed = False
        def read(fd, count):
            nonlocal changed
            value = actual_read(fd, count)
            if value and not changed:
                changed = True; self.file.write_bytes(self.data.replace(b'Dell R630', b'Dell R631'))
            return value
        with patch.object(self.delivery, 'read', side_effect=read):
            with self.assertRaises(ValueError): self.read()
        self.assert_closed()
        self.file.write_bytes(self.data)
        changed = False
        original_mtime = self.file.stat().st_mtime_ns
        def same_bytes(fd, count):
            nonlocal changed
            value = actual_read(fd, count)
            if value and not changed:
                changed = True; self.file.write_bytes(self.data)
                info = self.file.stat()
                os.utime(self.file, ns=(info.st_atime_ns, original_mtime + 1_000_000_000))
                self.assertNotEqual(self.file.stat().st_mtime_ns, original_mtime)
            return value
        with patch.object(self.delivery, 'read', side_effect=same_bytes):
            with self.assertRaisesRegex(ValueError, 'leaf changed'): self.read()
        self.assert_closed()

    def test_wrong_leaf_uid_or_gid_refuses_before_leaf_open(self):
        original = os.stat
        for field in ('st_uid', 'st_gid'):
            with self.subTest(field=field):
                def wrong(path, **kwargs):
                    info = original(path, **kwargs)
                    if path == 'manifest.json':
                        values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                        values[field] = os.geteuid() + 1
                        return types.SimpleNamespace(**values)
                    return info
                before = len(self.delivery.acquired)
                with patch.object(self.delivery, 'stat', side_effect=wrong):
                    with self.assertRaises(ValueError): self.read()
                self.assertEqual(len(self.delivery.acquired) - before, 2)
        self.assert_closed()

    def test_path_replacement_and_directory_drift_after_read_refuse(self):
        original = self.n['deployment_bytes']
        def replace(fd):
            value = original(fd)
            replacement = self.path / 'new'; replacement.write_bytes(self.data); replacement.chmod(0o600)
            os.replace(replacement, self.file)
            return value
        self.n['deployment_bytes'] = replace
        with self.assertRaises(ValueError): self.read()
        self.assert_closed()

    def test_checked_close_failure_withholds_return_and_remaining_fds_retire(self):
        original = self.delivery.close; failed = False
        def fail(fd):
            nonlocal failed
            original(fd)
            if not failed:
                failed = True; raise OSError('private checked-close failure')
        self.delivery.close = fail
        with self.assertRaises(OSError): self.read()
        self.assert_closed()


class DeploymentDeliveryTests(unittest.TestCase):
    def run_private(self, data, close_failure=False):
        with tempfile.TemporaryDirectory(prefix='s4-deployment-cli-') as temporary:
            root = Path(temporary); source = root / 'manifest.json'; source.write_bytes(data); source.chmod(0o600)
            program = emitted_program()
            seam = "raise SystemExit(deployment_main(bundle))"
            self.assertEqual(program.count(seam), 1)
            delivery = '''import os as private_os
    class PrivateDelivery:
        def __getattr__(self, key): return getattr(private_os, key)
        def open(self, path, flags, **kwargs): return private_os.open(PRIVATE_ROOT if path == '/' else path, flags, **kwargs)
        def close(self, fd):
            private_os.close(fd)
            if PRIVATE_CLOSE_FAILURE: raise OSError('private close failure')
    DEP_TRUSTED_UID = private_os.geteuid()
    dep_os = PrivateDelivery()
    '''
            delivery = delivery.replace('PRIVATE_ROOT', repr(temporary)).replace('PRIVATE_CLOSE_FAILURE', repr(close_failure))
            delivered = program.replace(seam, delivery + seam)
            script = root / 'candidate.py'; script.write_text(delivered)
            before = source.read_bytes()
            result = subprocess.run([sys.executable, '-I', '-B', str(script), 'deployment', '/manifest.json'],
                                    capture_output=True, timeout=10, check=False)
            after = source.read_bytes()
            self.assertEqual(before, after)
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o600)
            return result, {'input_hex': before.hex(), 'input_sha256': hashlib.sha256(before).hexdigest(),
                            'input_after_sha256': hashlib.sha256(after).hexdigest(),
                            'ordinary_emitted_bytes': len(program.encode()), 'ordinary_emitted_sha256': hashlib.sha256(program.encode()).hexdigest(),
                            'delivered_program': delivered, 'delivery': 'private root-FD/current UID and optional checked-close MODEL; ordinary Python and private filesystem',
                            'close_failure': close_failure, 'stdout_hex': result.stdout.hex(), 'stderr_hex': result.stderr.hex(),
                            'actual_wait': result.returncode}

    def test_complete_private_cli_positive_binds_actual_source_and_fixed_authorities(self):
        result, capture = self.run_private(encoded(manifest()))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        output = json.loads(result.stdout)
        self.assertEqual(output['source']['sha256'], capture['input_sha256'])
        self.assertTrue(all(value is False for value in output['authority'].values()))
        self.assertEqual(output['ssh_policy']['listen_addresses'], ['192.168.90.10', 'fd51:b089:f5e0:90::10'])
        CAPTURES.append(capture)

    def test_duplicate_and_wrong_network_private_cli_refuse_without_json(self):
        wrong = manifest(); wrong['admin']['ipv4']['address'] = '192.168.91.10'
        for data in (encoded(manifest()).replace(b'"schema":1', b'"schema":1,"schema":1'), encoded(wrong)):
            with self.subTest(sha=hashlib.sha256(data).hexdigest()):
                result, capture = self.run_private(data)
                self.assertEqual(result.returncode, 75)
                self.assertEqual(result.stdout, b'')
                self.assertEqual(result.stderr, b'Deployment candidate refused\n')
                CAPTURES.append(capture)

    def test_private_cli_checked_close_refuses_before_json(self):
        result, capture = self.run_private(encoded(manifest()), close_failure=True)
        self.assertEqual(result.returncode, 75)
        self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'Deployment candidate refused\n')
        CAPTURES.append(capture)

    def test_private_cli_supported_unscoped_public_gua_with_null_admin_ipv6(self):
        value = manifest(False); value['public']['ipv6'] = '2001:4860::1'
        result, capture = self.run_private(encoded(value))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b'')
        output = json.loads(result.stdout)
        self.assertEqual(output['source']['sha256'], capture['input_sha256'])
        self.assertEqual(output['ssh_policy']['listen_addresses'], ['192.168.90.10'])
        self.assertIn('ip6 daddr 2001:4860::1 tcp dport', output['files'][1]['content'])
        self.assertTrue(all(item is False for item in output['authority'].values()))
        CAPTURES.append(capture)

    def test_private_cli_public_site_local_and_reserved_refuse_without_json(self):
        for address in ('fec0::1', '4000::1'):
            with self.subTest(address=address):
                value = manifest(); value['public']['ipv6'] = address
                result, capture = self.run_private(encoded(value))
                self.assertEqual(result.returncode, 75)
                self.assertEqual(result.stdout, b'')
                self.assertEqual(result.stderr, b'Deployment candidate refused\n')
                CAPTURES.append(capture)

    def test_private_cli_public_and_router_scopes_including_escaped_newline_refuse(self):
        for field, suffix in (('public', '%eth0'), ('public', '%x\n  accept'),
                              ('router', '%eth0'), ('router', '%x\n  accept')):
            with self.subTest(field=field, suffix=suffix):
                value = manifest()
                if field == 'public': value['public']['ipv6'] = '2001:4860::1' + suffix
                else: value['admin']['ipv6']['routers'].append('fd51:b089:f5e0:90::2' + suffix)
                data = encoded(value)
                self.assertEqual(data.count(b'\n'), 1)
                result, capture = self.run_private(data)
                self.assertEqual(result.returncode, 75)
                self.assertEqual(result.stdout, b'')
                self.assertEqual(result.stderr, b'Deployment candidate refused\n')
                CAPTURES.append(capture)

    def test_standalone_public_cli_arity_precedes_preflight_state_and_python(self):
        for arguments in (['--deployment-policy'], ['--deployment-policy', '/missing', 'extra']):
            result = subprocess.run(['bash', str(ROOT / 'azurelinux3s4.sh'), *arguments], capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 64)
            self.assertEqual(result.stdout, b'')
            self.assertEqual(result.stderr, b'')

    def test_emitted_libraries_once_and_old_branch_argv_remains_argless(self):
        program = emitted_program()
        for name in LIBRARIES:
            self.assertEqual(program.count((ROOT / name).read_text()), 1)
        self.assertIn("sys.argv = [sys.argv[0]]\nraise SystemExit(main() if action == 'configuration' else service_main(bundle))", program)
        self.assertIn('[[ $# == 2 ]] || return 64\n            s4_deployment_policy "$2"', (ROOT / 'Bootstrap/main.sh').read_text())

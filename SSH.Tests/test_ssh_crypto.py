import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('s4_ssh_crypto_policy', ROOT / 'SSH/policy.py')
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)
EXPECTED = {
    'KexAlgorithms': 'sntrup761x25519-sha512@openssh.com',
    'Ciphers': 'aes256-gcm@openssh.com,aes128-gcm@openssh.com',
    'MACs': 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com',
    'HostKeyAlgorithms': 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256',
    'PubkeyAcceptedAlgorithms': 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256',
    'CASignatureAlgorithms': 'ssh-ed25519,rsa-sha2-512,rsa-sha2-256',
    'RequiredRSASize': '3072', 'FingerprintHash': 'sha256', 'RekeyLimit': '256M 1h',
}
EFFECTIVE = {name.lower(): value for name, value in EXPECTED.items()}
EFFECTIVE['rekeylimit'] = '268435456 3600'
EFFECTIVE['fingerprinthash'] = 'SHA256'


class SSHCryptoCandidateTests(unittest.TestCase):
    def test_explicit_crypto_profile_and_false_authorities_are_bound_to_file(self):
        bundle = POLICY.bundle()
        profile = bundle['cryptography']
        self.assertEqual(profile['profile'], 'hybrid-required-aes-gcm-ed25519-rsa-sha2-v1')
        self.assertEqual(profile['directives'], EXPECTED)
        self.assertEqual(len(profile['authority']), 7)
        self.assertTrue(all(value is False for value in profile['authority'].values()))
        self.assertTrue(all(value is False for value in bundle['authority'].values()))
        entry = bundle['files'][0]
        self.assertEqual(entry['sha256'], hashlib.sha256(entry['content'].encode()).hexdigest())
        self.assertEqual(entry['bytes'], len(entry['content'].encode()))

    def test_every_crypto_directive_is_a_single_absolute_replacement(self):
        content = POLICY.bundle()['files'][0]['content']
        for name, value in EXPECTED.items():
            self.assertEqual([line for line in content.splitlines() if line.split(' ', 1)[0].lower() == name.lower()], [name + ' ' + value])
            self.assertNotIn(value[0], '+-^')
        self.assertNotIn('Include ', content)
        self.assertNotIn('Match ', content)

    def test_key_exchange_has_no_classical_or_unknown_version_fallback(self):
        kex = POLICY.bundle()['cryptography']['directives']['KexAlgorithms'].split(',')
        self.assertEqual(kex, ['sntrup761x25519-sha512@openssh.com'])
        for name in ('curve25519-sha256', 'diffie-hellman-group14-sha1', 'mlkem768x25519-sha256'):
            self.assertNotIn(name, kex)

    def test_only_aes_gcm_transport_ciphers_and_sha2_etm_macs_are_declared(self):
        directives = POLICY.bundle()['cryptography']['directives']
        self.assertEqual(set(directives['Ciphers'].split(',')), {'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com'})
        for value in directives['MACs'].split(','):
            self.assertTrue(value.startswith('hmac-sha2-'))
            self.assertTrue(value.endswith('-etm@openssh.com'))
        for token in ('chacha20', '-cbc', '-ctr', '3des', 'hmac-sha1', 'umac'):
            self.assertNotIn(token, directives['Ciphers'] + directives['MACs'])

    def test_signature_lists_exclude_sha1_blob_name_certificates_and_foreign_key_types(self):
        directives = POLICY.bundle()['cryptography']['directives']
        for name in ('HostKeyAlgorithms', 'PubkeyAcceptedAlgorithms', 'CASignatureAlgorithms'):
            values = directives[name].split(',')
            self.assertEqual(values, ['ssh-ed25519', 'rsa-sha2-512', 'rsa-sha2-256'])
            self.assertNotIn('ssh-rsa', values)
            self.assertFalse(any('cert-' in value or value.startswith(('sk-', 'ecdsa', 'ssh-dss')) for value in values))

    def test_rsa_minimum_agrees_with_accepted_public_snapshot_policy(self):
        self.assertEqual(POLICY.bundle()['cryptography']['directives']['RequiredRSASize'], '3072')
        spec = importlib.util.spec_from_file_location('s4_crypto_key_parameters', ROOT / 'SSH/keys.py')
        keys = importlib.util.module_from_spec(spec); spec.loader.exec_module(keys)
        # Genuine negative/positive wire models are already maintained in key tests.
        sys.path.insert(0, str(ROOT / 'SSH.Tests'))
        self.addCleanup(sys.path.remove, str(ROOT / 'SSH.Tests'))
        import test_ssh_keys as fixtures
        with self.assertRaises(ValueError): keys.parse(fixtures.rsa(2048))
        self.assertEqual(keys.parse(fixtures.rsa(3072))[0]['bits'], 3072)

    def test_rekey_and_fingerprint_limits_are_explicit_not_readiness(self):
        directives = POLICY.bundle()['cryptography']['directives']
        self.assertEqual(directives['RekeyLimit'], '256M 1h')
        self.assertEqual(directives['FingerprintHash'], 'sha256')
        text = ' '.join(POLICY.bundle()['cryptography']['limits'])
        for fragment in ('not a FIPS profile', 'signatures remain classical', 'own authentication',
                         "client's preference", 'provider usability', 'physical session deadlines'):
            self.assertIn(fragment, text)

    def test_ca_signature_declaration_does_not_create_a_ca_trust_route(self):
        content = POLICY.bundle()['files'][0]['content']
        for line in ('TrustedUserCAKeys none', 'AuthorizedPrincipalsFile none', 'AuthorizedPrincipalsCommand none', 'AuthorizedKeysCommand none'):
            self.assertIn(line + '\n', content)

    def test_explicit_local_source_models_cannot_change_crypto_profile(self):
        default = POLICY.bundle()['cryptography']
        lan = POLICY.bundle(['10.4.0.0/24', 'fd34:5::/64'], ['10.4.0.2', 'fd34:5::2'])
        self.assertEqual(lan['cryptography'], default)
        self.assertTrue(all(flag is False for flag in lan['authority'].values()))

    def test_source_crypto_mutation_of_returned_bundle_does_not_change_next_candidate(self):
        bundle = POLICY.bundle()
        bundle['cryptography']['directives']['Ciphers'] = 'aes128-ctr'
        bundle['files'][0]['content'] = 'operator variant'
        self.assertEqual(POLICY.bundle()['cryptography']['directives'], EXPECTED)

    def test_standalone_emission_has_exact_crypto_bytes_without_checkout_or_preflight(self):
        with tempfile.TemporaryDirectory(prefix='s4-crypto-delivery-') as directory:
            script = Path(directory) / 'setup.sh'
            script.write_bytes((ROOT / 'azurelinux3s4.sh').read_bytes()); script.chmod(0o755)
            result = subprocess.run([str(script), '--ssh-policy'], capture_output=True, cwd=directory, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stderr, b'')
            self.assertEqual(json.loads(result.stdout), POLICY.bundle())
            self.assertEqual(sorted(path.name for path in Path(directory).iterdir()), ['setup.sh'])

    def test_crypto_cli_overrides_refuse_before_output(self):
        result = subprocess.run([str(ROOT / 'azurelinux3s4.sh'), '--ssh-policy', '--ciphers=aes128-ctr'], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 64)
        self.assertEqual(result.stdout, b'')


class NativeSSHCryptoTests(unittest.TestCase):
    def parse(self, bundle, model=None, fixture_kind='ed25519', fixture_rsa_bits=None):
        entry = bundle['files'][0]
        source = entry['content']
        with tempfile.TemporaryDirectory(prefix='s4-crypto-native-', dir='/dev/shm') as directory:
            key = Path(directory) / 'owned_fixture_host_key'
            generation = ['/usr/bin/ssh-keygen', '-q', '-t', fixture_kind, '-N', '', '-f', str(key)]
            if fixture_rsa_bits is not None: generation += ['-b', str(fixture_rsa_bits)]
            generated = subprocess.run(generation, capture_output=True, timeout=15)
            self.assertEqual(generated.returncode, 0, generated.stderr.decode())
            self.assertEqual(generated.stdout + generated.stderr, b'')
            public = key.with_suffix('.pub').read_bytes()
            fingerprint = subprocess.run(['/usr/bin/ssh-keygen', '-l', '-f', str(key.with_suffix('.pub')), '-E', 'sha256'],
                                         capture_output=True, timeout=10)
            self.assertEqual(fingerprint.returncode, 0, fingerprint.stderr.decode())
            self.assertEqual(fingerprint.stderr, b'')
            fp_lines = fingerprint.stdout.decode().splitlines()
            self.assertEqual(len(fp_lines), 1)
            self.assertEqual(int(fp_lines[0].split()[0]), fixture_rsa_bits if fixture_kind == 'rsa' else 256)
            substitutions, lines = [], []
            for line in source.splitlines(keepends=True):
                if line.startswith('HostKey '):
                    substitutions.append({'original': line.strip(), 'delivered': 'HostKey ' + str(key)})
                    line = 'HostKey ' + str(key) + '\n'
                lines.append(line)
            self.assertEqual(len(substitutions), 2)
            delivered = ''.join(lines)
            command = ['/usr/sbin/sshd', '-T', '-f', str(Path(directory) / 'sshd_config'), '-C',
                       'user=azurelinux3s4-admin,host=fixture.invalid,addr=192.0.2.7,laddr=' + bundle['listen_addresses'][0] + ',lport=22']
            if model == 'prepend-cipher': delivered = 'Ciphers aes128-ctr\n' + delivered
            elif model == 'argv-cipher': command += ['-o', 'Ciphers=aes128-ctr']
            elif model == 'invalid-kex':
                original = 'KexAlgorithms ' + EXPECTED['KexAlgorithms'] + '\n'
                self.assertEqual(delivered.count(original), 1)
                delivered = delivered.replace(original, 'KexAlgorithms nonexistent-crypto-fixture\n')
            elif model is not None: raise AssertionError('unknown native model')
            config = Path(directory) / 'sshd_config'; config.write_text(delivered); config.chmod(0o600)
            result = subprocess.run(command, capture_output=True, timeout=10)
            correspondence = False
            short_rsa = fixture_kind == 'rsa' and fixture_rsa_bits == 2048
            if model == 'invalid-kex' or short_rsa:
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, b'')
                if short_rsa:
                    self.assertIn(b'Invalid key length', result.stderr)
                    self.assertIn(b'no hostkeys available', result.stderr)
                else:
                    self.assertIn(b'Bad SSH2 KexAlgorithms', result.stderr)
                    self.assertIn(b'nonexistent-crypto-fixture', result.stderr)
                effective = {}
            else:
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(result.stderr, b'')
                effective = {}
                for line in result.stdout.decode().splitlines():
                    name, value = line.split(' ', 1)
                    effective.setdefault(name, []).append(value)
                for name, expected in EFFECTIVE.items():
                    value = 'aes128-ctr' if name == 'ciphers' and model else expected
                    self.assertEqual(effective[name], [value])
                self.assertEqual(effective['trustedusercakeys'], ['none'])
                self.assertEqual(effective['authenticationmethods'], ['publickey'])
                self.assertEqual(effective['allowusers'], [POLICY.ADMIN + '@' + prefix for prefix in bundle['source_prefixes']])
                self.assertEqual(sorted(effective['listenaddress']), sorted(
                    (('[' + address + ']') if ':' in address else address) + ':22' for address in bundle['listen_addresses']))
                correspondence = all(effective.get(name) == [value] for name, value in EFFECTIVE.items())
                self.assertEqual(correspondence, model is None)
            record = {
                'actual_parser_wait_exit': result.returncode, 'actual_fixture_keygen_wait_exit': generated.returncode,
                'fixture_key_kind': fixture_kind, 'fixture_rsa_bits': fixture_rsa_bits,
                'fixture_public_content': public.decode(), 'fixture_public_sha256': hashlib.sha256(public).hexdigest(),
                'actual_public_fingerprint_wait_exit': fingerprint.returncode, 'public_fingerprint_stdout': fingerprint.stdout.decode(),
                'candidate': bundle, 'candidate_source_sha256': hashlib.sha256(source.encode()).hexdigest(),
                'delivered_config_sha256': hashlib.sha256(delivered.encode()).hexdigest(),
                'hostkey_path_delivery_substitutions': substitutions,
                'model': model, 'parser_command': command, 'effective_stdout': result.stdout.decode(),
                'effective_stderr': result.stderr.decode(), 'effective_crypto_correspondence': correspondence,
                'native_parser_version': subprocess.run(['/usr/sbin/sshd', '-V'], capture_output=True, check=True).stderr.decode().strip(),
                'ssh_authentication_executed': False, 'listener_activated': False, 'accounts_created': False,
                'production_keys_provisioned': False, 'native_azure_policy_proven': False,
                'native_provider_usable_proven': False, 'peer_compatibility_proven': False,
            }
        self.assertFalse(Path(directory).exists())
        self.record = {'owned_private_fixture_directory_removed': True, **record}

    def test_native_effective_default_has_exact_cryptographic_replacement_policy(self):
        self.parse(POLICY.bundle())

    def test_native_effective_lan_model_preserves_exact_crypto_policy(self):
        self.parse(POLICY.bundle(['10.4.0.0/24', 'fd34:5::/64'], ['10.4.0.2', 'fd34:5::2']))

    def test_native_first_value_model_exposes_weaker_cipher_outside_candidate(self):
        self.parse(POLICY.bundle(), 'prepend-cipher')

    def test_native_argv_override_model_exposes_weaker_cipher_outside_candidate(self):
        self.parse(POLICY.bundle(), 'argv-cipher')

    def test_native_unknown_kex_model_refuses_without_effective_output(self):
        self.parse(POLICY.bundle(), 'invalid-kex')

    def test_native_rsa3072_host_key_passes_offline_loader_and_crypto_parser(self):
        self.parse(POLICY.bundle(), fixture_kind='rsa', fixture_rsa_bits=3072)

    def test_native_rsa2048_host_key_refuses_under_required_minimum(self):
        self.parse(POLICY.bundle(), fixture_kind='rsa', fixture_rsa_bits=2048)

    def test_native_client_name_tables_contain_selected_candidate_algorithms(self):
        crypto = POLICY.cryptography()['directives']
        queries = {'KexAlgorithms': crypto['KexAlgorithms'].split(','), 'Ciphers': crypto['Ciphers'].split(','),
                   'MACs': crypto['MACs'].split(','), 'key-sig': crypto['HostKeyAlgorithms'].split(',')}
        records = []
        for query, required in queries.items():
            command = ['/usr/bin/ssh', '-Q', query]
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(result.stderr, b'')
            names = result.stdout.decode().splitlines()
            self.assertEqual(len(names), len(set(names)))
            self.assertTrue(set(required) <= set(names))
            records.append({'query': query, 'command': command, 'required': required,
                            'actual_wait_exit': result.returncode, 'stdout': result.stdout.decode(), 'stderr': result.stderr.decode()})
        self.record = {
            'queries': records, 'registry_names_only': True, 'ssh_authentication_executed': False,
            'listener_activated': False, 'native_provider_usable_proven': False, 'native_azure_policy_proven': False,
            'peer_compatibility_proven': False,
        }


if __name__ == '__main__':
    unittest.main()

"""Actual local sysusers dry-runs using exclusively private synthetic databases."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

import test_deployment_releases as fixture
from test_deployment_policy import encoded


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_account_preflight', ROOT/'Bootstrap/account_preflight.py')
ACCOUNT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACCOUNT)
CAPTURES = []


class AccountPreflightTests(fixture.ReleaseFixture):
    def setUp(self):
        super().setUp()
        self.work_temp = tempfile.TemporaryDirectory(dir=Path.home()/'.cache')
        self.addCleanup(self.work_temp.cleanup)
        self.work = Path(self.work_temp.name); self.work.chmod(0o700)
        self.pin = hashlib.sha256(Path(ACCOUNT.PARSER).read_bytes()).hexdigest()
        units = self.n['application_bundle'](encoded(self.value), self.n['bundle'])['files']
        self.names = [row['name'] for row in self.n['application_account_policy'](units)['accounts']]
        self.records = {'passwd': b'root:x:0:0:root:/root:/bin/sh\n', 'group': b'root:x:0:\n',
                        'shadow': b'root:!:20000:0:99999:7:::\n', 'gshadow': b'root:!::\n',
                        'nsswitch.conf': b'passwd: files\ngroup: files\nshadow: files\ngshadow: files\n'}
        self.write_records()

    def write_records(self):
        for name, raw in self.records.items():
            path = self.root/'etc'/name; path.write_bytes(raw); path.chmod(ACCOUNT.DATABASES[name])

    def existing(self):
        for number, name in enumerate(self.names, 6000):
            self.records['passwd'] += f'{name}:x:{number}:{number}:Application:/:/usr/sbin/nologin\n'.encode()
            self.records['group'] += f'{name}:x:{number}:\n'.encode()
            self.records['shadow'] += f'{name}:!:20000:0:99999:7:::\n'.encode()
            self.records['gshadow'] += f'{name}:!::\n'.encode()
        self.write_records()

    def audit(self, proposed='300-399'):
        # Finite unrelated synthetic range only, never an installation default.
        return ACCOUNT.audit(self.root, '/manifest.json', self.work, self.pin, proposed)

    def test_complete_cli_dry_run_proposals_match_without_original_or_fixture_mutation(self):
        before = self.snapshot()
        args = [sys.executable, '-I', '-B', str(ROOT/'Bootstrap/account_preflight.py'), '--root', str(self.root),
                '--manifest', '/manifest.json', '--work-parent', str(self.work), '--parser-sha256', self.pin,
                '--allocation-range', '300-399']
        child = subprocess.run(args, capture_output=True, timeout=20)
        self.assertEqual((child.returncode, child.stderr), (0, b''), child.stderr)
        result = json.loads(child.stdout)
        self.assertEqual([row['name'] for row in result['proposals']], self.names)
        self.assertTrue(all(row['status'] == 'would-create' and 300 <= row['uid'] <= 399 and row['uid'] == row['gid']
                            for row in result['proposals']))
        self.assertEqual(len({row['uid'] for row in result['proposals']}), len(self.names))
        self.assertTrue(all(result['checks'].values()))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual([row['actual_returncode'] for row in result['parser']['commands']], [0, 0])
        arguments = result['parser']['commands'][-1]['arguments']
        self.assertEqual(arguments[0], '--dry-run'); self.assertEqual(arguments[2], '--no-pager')
        self.assertTrue(Path(arguments[1].split('=', 1)[1]).is_relative_to(self.work))
        for path in arguments[3:]: self.assertTrue(Path(path).is_relative_to(self.work))
        self.assertEqual(set(result['fixture']), {'allocation.conf', 'applications.conf', *('etc/'+name for name in ACCOUNT.DATABASES)})
        self.assertEqual(result['fixture']['applications.conf']['sha256'], result['configuration']['sha256'])
        self.assertNotIn(b'20000:0:99999', child.stdout)
        self.assertEqual(self.snapshot(), before); self.assertEqual(list(self.work.iterdir()), [])
        CAPTURES.append(result)
        before_plan = ACCOUNT.PREFLIGHT.preflight(self.root, '/manifest.json', kind='accounts', include_candidate=True)
        _, observation, namespace = ACCOUNT.inputs(before_plan)
        databases = {name: namespace['account_rows'](self.records[name], name) for name in ('passwd', 'group')}
        raw = result['parser']['dry_run_diagnostics'].encode('ascii')
        damaged = (raw + raw.splitlines(True)[0], raw.replace(b'GID 399.', b'GID 0.'),
                   raw.replace(b'Would write /etc/shadow...\n', b''), raw + b'Would write /etc/foreign...\n')
        for data in damaged:
            with self.subTest(data=data[-100:]), self.assertRaises(ValueError):
                ACCOUNT.reconcile(data, observation, databases, (300,399))

    def test_existing_accounts_need_no_writes_and_occupied_numeric_ids_are_skipped(self):
        self.records['passwd'] += b'unrelated:x:399:399:Unrelated:/:/usr/sbin/nologin\n'
        self.records['group'] += b'unrelated:x:399:\n'; self.write_records()
        before = self.snapshot(); result = self.audit()
        self.assertTrue(all(row['uid'] != 399 for row in result['proposals']))
        self.assertEqual(self.snapshot(), before)
        self.existing(); before = self.snapshot(); result = self.audit()
        self.assertTrue(all(row['status'] == 'existing-local-declarations' for row in result['proposals']))
        self.assertEqual(result['parser']['dry_run_diagnostics'], '')
        self.assertEqual(result['parser']['commands'][-1]['stderr_bytes'], 0)
        self.assertEqual(self.snapshot(), before); self.assertEqual(list(self.work.iterdir()), [])
        CAPTURES.append(result)

    def test_account_conflicts_nss_changes_and_bad_ranges_refuse_before_native(self):
        self.existing()
        original = self.records['shadow']
        self.records['shadow'] = original.replace((self.names[0]+':!:').encode(), (self.names[0]+':not-locked:').encode())
        self.write_records()
        with patch.object(ACCOUNT.NATIVE, 'PinnedExecutable', side_effect=AssertionError('early native')) as native:
            with self.assertRaisesRegex(ValueError, 'conflicting'): self.audit()
            native.assert_not_called()
        self.records['shadow'] = original
        self.records['nsswitch.conf'] = self.records['nsswitch.conf'].replace(b'passwd: files', b'passwd: files systemd')
        self.write_records()
        with patch.object(ACCOUNT.NATIVE, 'PinnedExecutable', side_effect=AssertionError('early native')) as native:
            with self.assertRaisesRegex(ValueError, 'nonlocal'): self.audit()
            native.assert_not_called()
        for value in ('', '0-399', '0300-399', '399-300', '300-65534', '1-4294967294', '300-399\n'):
            with self.subTest(value=value), self.assertRaises(ValueError): ACCOUNT.allocation_range(value)
        self.assertEqual(list(self.work.iterdir()), [])

    def test_exhausted_range_cannot_report_success_and_private_files_are_retired(self):
        original = ACCOUNT.NATIVE.PinnedExecutable.run; captures = []
        def observed(native, arguments, *args, **kwargs):
            try: return original(native, arguments, *args, **kwargs)
            finally:
                if '--dry-run' in arguments:
                    captures.append({'commands': list(native.commands), 'stderr': native.last_stderr.decode('ascii')})
        before = self.snapshot()
        with patch.object(ACCOUNT.NATIVE.PinnedExecutable, 'run', observed):
            with self.assertRaises(ValueError): self.audit('300-300')
        self.assertEqual(len(captures), 1)
        self.assertIn('No free', captures[0]['stderr'])
        self.assertEqual(self.snapshot(), before); self.assertEqual(list(self.work.iterdir()), [])
        CAPTURES.append({'scope': 'EXPECTED EXHAUSTED RANGE REFUSAL', **captures[0]})

    def test_original_account_drift_is_rejected_and_no_credential_environment_is_inherited(self):
        original = ACCOUNT.NATIVE.PinnedExecutable.run; calls = []
        def observed(native, arguments, *args, **kwargs):
            self.assertEqual(native.environment, ACCOUNT.ENVIRONMENT)
            self.assertNotIn('CREDENTIALS_DIRECTORY', native.environment)
            self.assertNotIn('LD_PRELOAD', native.environment)
            result = original(native, arguments, *args, **kwargs); calls.append(arguments)
            if '--dry-run' in arguments:
                path = self.root/'etc/shadow'; path.write_bytes(path.read_bytes()+b'\n')
            return result
        with patch.object(ACCOUNT.NATIVE.PinnedExecutable, 'run', observed):
            with self.assertRaisesRegex(ValueError, 'changed since admission'): self.audit()
        self.assertEqual(len(calls), 2); self.assertEqual(list(self.work.iterdir()), [])

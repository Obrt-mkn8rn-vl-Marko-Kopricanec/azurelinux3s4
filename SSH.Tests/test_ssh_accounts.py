import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('s4_ssh_accounts', ROOT / 'SSH/accounts.py')
ACCOUNTS = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(ACCOUNTS)
ROOT_PASSWD = b'root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n'
ROOT_GROUP = b'root:x:0:\nnogroup:x:65534:\n'
ROOT_SHELLS = b'# registered spellings only\n/bin/sh\n/bin/bash\n/usr/bin/bash\n'
ADMIN_PASSWD = (ACCOUNTS.ADMIN + ':x:1003:1004:private-gecos-not-output:' + ACCOUNTS.HOME_PATH + ':/bin/bash\n').encode()
ADMIN_GROUP = (ACCOUNTS.ADMIN + ':x:1004:\n').encode()


def tables(present=False):
    return {'passwd': ROOT_PASSWD + (ADMIN_PASSWD if present else b''),
            'group': ROOT_GROUP + (ADMIN_GROUP if present else b''), 'shells': ROOT_SHELLS}


class SSHAccountRecordTests(unittest.TestCase):
    def test_absent_local_records_do_not_authorize_creation(self):
        self.assertEqual(ACCOUNTS.classify(tables()), {'local_status': 'absent', 'account': None, 'local_supplementary_groups': []})

    def test_present_private_local_profile_is_observed_not_adopted(self):
        proof = ACCOUNTS.classify(tables(True))
        self.assertEqual(proof['local_status'], 'present')
        self.assertEqual(proof['account'], {'name': ACCOUNTS.ADMIN, 'uid': 1003, 'gid': 1004, 'home': ACCOUNTS.HOME_PATH, 'shell': '/bin/bash'})
        self.assertNotIn('private-gecos', json.dumps(proof))

    def test_matching_private_primary_member_is_not_supplementary_entitlement(self):
        data = tables(True); data['group'] = ROOT_GROUP + (ACCOUNTS.ADMIN + ':x:1004:' + ACCOUNTS.ADMIN + '\n').encode()
        self.assertEqual(ACCOUNTS.classify(data)['local_supplementary_groups'], [])

    def test_group_name_residue_without_account_refuses(self):
        data = tables(); data['group'] += ADMIN_GROUP
        with self.assertRaisesRegex(ValueError, 'residue'): ACCOUNTS.classify(data)

    def test_dangling_sudo_membership_cannot_authorize_new_name(self):
        data = tables(); data['group'] += ('sudo:x:27:' + ACCOUNTS.ADMIN + '\n').encode()
        with self.assertRaisesRegex(ValueError, 'residue'): ACCOUNTS.classify(data)

    def test_existing_supplementary_group_entitlement_refuses(self):
        data = tables(True); data['group'] += ('wheel:x:10:' + ACCOUNTS.ADMIN + '\n').encode()
        with self.assertRaisesRegex(ValueError, 'shared or privileged'): ACCOUNTS.classify(data)

    def test_root_system_dynamic_or_excessive_admin_identities_refuse(self):
        for uid, gid in ((0, 1004), (1003, 0), (999, 1004), (1003, 999), (60001, 1004), (1003, 61184)):
            data = tables(True)
            data['passwd'] = ROOT_PASSWD + ADMIN_PASSWD.replace(b':1003:1004:', (':' + str(uid) + ':' + str(gid) + ':').encode())
            data['group'] = ROOT_GROUP + ADMIN_GROUP.replace(b':1004:', (':' + str(gid) + ':').encode())
            with self.subTest(uid=uid, gid=gid), self.assertRaises(ValueError): ACCOUNTS.classify(data)

    def test_alias_uid_shared_primary_gid_and_alias_group_gid_refuse(self):
        for passwd, group in ((b'alias:x:1003:2000::/tmp:/bin/bash\n', b''),
                              (b'other:x:2000:1004::/tmp:/bin/bash\n', b''),
                              (b'', b'alias:x:1004:\n')):
            data = tables(True); data['passwd'] += passwd; data['group'] += group
            with self.assertRaisesRegex(ValueError, 'shared or privileged'): ACCOUNTS.classify(data)

    def test_primary_group_missing_or_mismatched_and_extra_members_refuse(self):
        for group in (ROOT_GROUP, ROOT_GROUP + ADMIN_GROUP.replace(b'1004', b'1005'),
                      ROOT_GROUP + ADMIN_GROUP.replace(b'1004:', b'1004:other')):
            data = tables(True); data['group'] = group
            with self.assertRaises(ValueError): ACCOUNTS.classify(data)

    def test_foreign_home_shell_missing_registration_or_implicit_shell_refuse(self):
        for home, shell, shells in (('/root', '/bin/bash', ROOT_SHELLS),
                                    (ACCOUNTS.HOME_PATH, '/bin/sh', ROOT_SHELLS),
                                    (ACCOUNTS.HOME_PATH, '', ROOT_SHELLS),
                                    (ACCOUNTS.HOME_PATH, '/bin/bash', b'/bin/sh\n')):
            data = tables(True)
            data['passwd'] = ROOT_PASSWD + (ACCOUNTS.ADMIN + ':x:1003:1004::' + home + ':' + shell + '\n').encode()
            data['shells'] = shells
            with self.assertRaises(ValueError): ACCOUNTS.classify(data)

    def test_registered_usr_bash_spelling_is_a_declaration_only(self):
        data = tables(True); data['passwd'] = data['passwd'].replace(b':/bin/bash\n', b':/usr/bin/bash\n')
        self.assertEqual(ACCOUNTS.classify(data)['account']['shell'], '/usr/bin/bash')

    def test_duplicate_names_nis_forms_and_ambiguous_records_refuse(self):
        for kind, data in (('passwd', ROOT_PASSWD + ROOT_PASSWD), ('group', ROOT_GROUP + ROOT_GROUP),
                           ('passwd', ROOT_PASSWD + b'+::::::\n'), ('group', ROOT_GROUP + b'+:::\n'),
                           ('passwd', b'root:x:0:0:/root:/bin/bash\n')):
            with self.subTest(kind=kind), self.assertRaises(ValueError): ACCOUNTS.records(data, kind)

    def test_inline_password_hashes_are_refused_without_output(self):
        for kind, data in (('passwd', ROOT_PASSWD.replace(b'root:x:', b'root:$6$PRIVATEHASH:')),
                           ('group', ROOT_GROUP.replace(b'root:x:', b'root:$6$PRIVATEHASH:'))):
            with self.assertRaises(ValueError): ACCOUNTS.records(data, kind)

    def test_numeric_records_require_canonical_uint32_without_minus_one(self):
        for value in ('01', '+1', '-1', '4294967295', '１', '', ' 1'):
            with self.subTest(value=value), self.assertRaises(ValueError): ACCOUNTS.number(value)
        self.assertEqual(ACCOUNTS.number('4294967294'), 4294967294)

    def test_duplicate_or_malformed_group_members_refuse(self):
        for members in ('one,one', ',one', 'one,', 'one, bad', 'one:+legacy'):
            with self.assertRaises(ValueError): ACCOUNTS.records(('group:x:1000:' + members + '\n').encode(), 'group')

    def test_missing_or_nonzero_root_baseline_refuses(self):
        for kind, body in (('passwd', b'nobody:x:65534:65534::/:/bin/sh\n'),
                           ('passwd', ROOT_PASSWD.replace(b'root:x:0:0:', b'root:x:1:0:')),
                           ('group', ROOT_GROUP.replace(b'root:x:0:', b'root:x:1:'))):
            data = tables(); data[kind] = body
            with self.assertRaises(ValueError): ACCOUNTS.classify(data)

    def test_shell_registration_duplicates_relative_and_boundary_paths_refuse(self):
        for body in (b'/bin/bash\n/bin/bash\n', b'bin/bash\n', b'/bin/../bash\n', b'/bin//bash\n', b'/bin/bash/\n', b'/bin/bash #entry\n'):
            data = tables(); data['shells'] = body
            with self.assertRaises(ValueError): ACCOUNTS.classify(data)

    def test_encoding_line_and_record_bounds_refuse(self):
        for data in (b'', b'no final LF', b'bad\r\n', b'bad\0\n', b'bad\xff\n', b'x' * 4097 + b'\n', b'\n' * 16385):
            with self.assertRaises(ValueError): ACCOUNTS.lines(data)


class SSHAccountSnapshotTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='s4-account-snapshot-')
        self.root = Path(self.directory.name); (self.root / 'etc').mkdir(mode=0o700)
        for name, data in tables(True).items():
            path = self.root / 'etc' / name; path.write_bytes(data); path.chmod(0o644)
        self.addCleanup(self.directory.cleanup)
        original = ACCOUNTS.os.open
        self.root_delivery = lambda: original(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(ACCOUNTS, 'root_open', side_effect=self.root_delivery).start()
        mock.patch.object(ACCOUNTS, 'TRUSTED_UID', os.geteuid()).start()

    def test_actual_regular_snapshots_two_reads_and_checked_closes(self):
        before = {name: ACCOUNTS.identity((self.root / 'etc' / name).stat()) for name in tables()}
        proof = ACCOUNTS.observe()
        self.assertEqual(proof['local_status'], 'present')
        self.assertTrue(all(flag is False for flag in proof['authority'].values()))
        self.assertEqual(len(proof['authority']), 16)
        self.assertEqual({name: ACCOUNTS.identity((self.root / 'etc' / name).stat()) for name in tables()}, before)
        self.assertNotIn('private-gecos', json.dumps(proof))

    def test_actual_symlink_fifo_directory_socket_leaves_refuse_before_open(self):
        path = self.root / 'etc/passwd'; path.unlink()
        with socket.socket(socket.AF_UNIX) as listener:
            for kind in ('symlink', 'fifo', 'directory', 'socket'):
                if kind == 'symlink': path.symlink_to(self.root / 'etc/group')
                elif kind == 'fifo': os.mkfifo(path, 0o600)
                elif kind == 'directory': path.mkdir(mode=0o700)
                else: listener.bind(str(path))
                before = ACCOUNTS.identity(path.lstat())
                with self.subTest(kind=kind), self.assertRaises(ValueError): ACCOUNTS.observe()
                self.assertEqual(ACCOUNTS.identity(path.lstat()), before)
                path.rmdir() if kind == 'directory' else path.unlink()

    def test_writable_or_foreign_owner_sources_refuse(self):
        path = self.root / 'etc/passwd'; path.chmod(0o666)
        with self.assertRaises(ValueError): ACCOUNTS.observe()
        path.chmod(0o644)
        with mock.patch.object(ACCOUNTS, 'TRUSTED_UID', os.geteuid() + 1), self.assertRaises(ValueError): ACCOUNTS.observe()

    def test_writable_root_or_etc_ancestry_refuses(self):
        for path in (self.root, self.root / 'etc'):
            path.chmod(0o777)
            with self.assertRaises(ValueError): ACCOUNTS.observe()
            path.chmod(0o700)

    def test_linked_or_wrong_kind_etc_ancestry_is_not_followed(self):
        original = self.root / 'etc'; held = self.root / 'original'; original.rename(held)
        original.symlink_to(held)
        with self.assertRaises(ValueError): ACCOUNTS.observe()
        self.assertTrue(original.is_symlink())

    def test_missing_empty_or_excessive_file_is_not_absence(self):
        path = self.root / 'etc/passwd'
        for size in (None, 0, ACCOUNTS.SOURCE_LIMIT + 1):
            if path.exists(): path.unlink()
            if size is not None:
                with path.open('wb') as stream: stream.truncate(size)
                path.chmod(0o600)
            with self.assertRaises((OSError, ValueError)): ACCOUNTS.observe()

    def test_leaf_open_requires_nofollow_nonblock_and_cloexec(self):
        original = ACCOUNTS.os.open
        calls = []
        def checked(name, flags, **kwargs):
            if str(name) in ('passwd', 'group', 'shells'):
                self.assertEqual(flags, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                self.assertIn('dir_fd', kwargs); calls.append(name)
            return original(name, flags, **kwargs)
        with mock.patch.object(ACCOUNTS.os, 'open', side_effect=checked): ACCOUNTS.observe()
        self.assertEqual(calls, ['passwd', 'group', 'shells'])

    def test_regular_leaf_race_to_fifo_refuses_before_read_without_blocking(self):
        original = ACCOUNTS.os.open; path = self.root / 'etc/passwd'
        def raced(name, flags, **kwargs):
            if name == 'passwd': path.unlink(); os.mkfifo(path, 0o600)
            return original(name, flags, **kwargs)
        with mock.patch.object(ACCOUNTS.os, 'open', side_effect=raced), self.assertRaisesRegex(ValueError, 'before read'):
            ACCOUNTS.observe()
        self.assertTrue(stat.S_ISFIFO(path.lstat().st_mode))

    def test_namespace_leaf_replacement_during_classification_refuses(self):
        original = ACCOUNTS.classify; path = self.root / 'etc/passwd'; replacement = self.root / 'replacement'
        replacement.write_bytes(path.read_bytes()); replacement.chmod(0o644)
        def raced(content):
            result = original(content); os.replace(replacement, path); return result
        with mock.patch.object(ACCOUNTS, 'classify', side_effect=raced), self.assertRaisesRegex(ValueError, 'snapshot or namespace'):
            ACCOUNTS.observe()

    def test_same_inode_changed_content_is_caught_by_second_whole_read(self):
        original = ACCOUNTS.classify; path = self.root / 'etc/group'
        def raced(content):
            result = original(content); path.write_bytes(path.read_bytes() + b'other:x:2000:\n'); return result
        with mock.patch.object(ACCOUNTS, 'classify', side_effect=raced), self.assertRaisesRegex(ValueError, 'snapshot or namespace'):
            ACCOUNTS.observe()

    def test_etc_directory_swap_cannot_borrow_old_held_records(self):
        original = ACCOUNTS.classify; directory = self.root / 'etc'
        def raced(content):
            result = original(content); directory.rename(self.root / 'old'); directory.mkdir(mode=0o700)
            for name, data in tables().items(): (directory / name).write_bytes(data)
            return result
        with mock.patch.object(ACCOUNTS, 'classify', side_effect=raced), self.assertRaisesRegex(ValueError, 'ancestry'):
            ACCOUNTS.observe()

    def test_second_root_identity_change_refuses(self):
        other = self.root / 'other'; other.mkdir(mode=0o700)
        calls = 0; original = self.root_delivery
        def raced():
            nonlocal calls
            calls += 1
            return original() if calls == 1 else os.open(other, os.O_RDONLY | os.O_DIRECTORY)
        with mock.patch.object(ACCOUNTS, 'root_open', side_effect=raced), self.assertRaisesRegex(ValueError, 'ancestry'):
            ACCOUNTS.observe()

    def test_close_failure_withholds_observation(self):
        original = ACCOUNTS.os.close
        def failed(fd): original(fd); raise OSError('delivered close error')
        with mock.patch.object(ACCOUNTS.os, 'close', side_effect=failed), self.assertRaisesRegex(OSError, 'close error'):
            ACCOUNTS.observe()


class NativeSSHAccountTests(unittest.TestCase):
    def native(self, delivered=False):
        before = {name: hashlib.sha256(Path('/etc', name).read_bytes()).hexdigest() for name in ('passwd','group','shells')}
        if delivered:
            with tempfile.TemporaryDirectory(prefix='s4-account-delivery-', dir='/dev/shm') as directory:
                path = Path(directory) / 'setup.sh'; path.write_bytes((ROOT / 'azurelinux3s4.sh').read_bytes()); path.chmod(0o755)
                result = subprocess.run(['bash', str(path), '--inspect-ssh-account'], capture_output=True, cwd=directory, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode()); self.assertEqual(result.stderr, b'')
                proof = json.loads(result.stdout)
                self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ['setup.sh'])
            self.assertFalse(Path(directory).exists())
        else: proof = ACCOUNTS.observe()
        after = {name: hashlib.sha256(Path('/etc', name).read_bytes()).hexdigest() for name in ('passwd','group','shells')}
        self.assertEqual(before, after)
        self.assertEqual(proof['administrator_name'], 'azurelinux3s4-admin')
        self.assertIn(proof['local_status'], ('present', 'absent'))
        self.assertEqual(len(proof['authority']), 16); self.assertTrue(all(v is False for v in proof['authority'].values()))
        for name, digest in before.items():
            self.assertEqual(proof['sources'][name]['sha256'], digest)
            source = Path('/etc', name); self.assertEqual(source.stat().st_uid, 0)
            self.assertFalse(source.stat().st_mode & 0o022); self.assertFalse(source.is_symlink())
        self.record = {'proof': proof, 'public_source_sha256_before': before, 'public_source_sha256_after': after,
                       'actual_cli_wait_exit': result.returncode if delivered else None, 'delivered': delivered,
                       'ownership_or_root_fd_substitution': False, 'accounts_created': False, 'nss_or_pam_invoked': False,
                       'authentication_executed': False, 'raw_host_account_records_retained': False}

    def test_actual_root_owned_local_sources_observed_without_substitution(self): self.native()

    def test_standalone_actual_local_observation_without_checkout_or_preflight(self): self.native(delivered=True)


class SSHAccountCLITests(unittest.TestCase):
    def test_cli_and_python_override_refusal_precedes_any_observation(self):
        for command in ([str(ROOT / 'azurelinux3s4.sh'), '--inspect-ssh-account', 'override'],
                        [sys.executable, '-I', str(ROOT / 'SSH/accounts.py'), 'override']):
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 64); self.assertEqual(result.stdout, b'')

    def test_failed_observation_withholds_output_and_secret_diagnostics(self):
        code = "import importlib.util; s=importlib.util.spec_from_file_location('a'," + repr(str(ROOT / 'SSH/accounts.py')) + "); a=importlib.util.module_from_spec(s); s.loader.exec_module(a); a.observe=lambda: (_ for _ in ()).throw(ValueError('PRIVATE-DIAGNOSTIC')); raise SystemExit(a.main())"
        result = subprocess.run([sys.executable, '-I', '-c', code], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'SSH local account observation refused\n')


if __name__ == '__main__': unittest.main()

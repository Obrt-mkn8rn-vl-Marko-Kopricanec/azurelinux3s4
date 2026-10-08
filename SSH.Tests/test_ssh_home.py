import copy
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
SPEC = importlib.util.spec_from_file_location('s4_ssh_home', ROOT / 'SSH/home.py')
HOME = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(HOME)


def view(present=True):
    return {'administrator_name': HOME.HOME_ADMIN, 'local_status': 'present' if present else 'absent',
            'account': {'name': HOME.HOME_ADMIN, 'uid': 1003, 'gid': 1004, 'home': HOME.HOME_FIXED_PATH,
                        'shell': '/bin/bash'} if present else None,
            'authority': {str(index): False for index in range(16)},
            'sources': {'fixture': 'EXPLICIT qualified-local-view MODEL, not actual records/NSS/owner authority'}}


class SSHHomeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='s4-home-observer-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name); self.parent = self.root / 'home'
        self.parent.mkdir(mode=0o755); self.target = self.parent / HOME.HOME_ADMIN
        self.target.mkdir(mode=0o755); self.target.chmod(0o755); self.current_view = view()
        original = HOME.os.open
        self.root_delivery = lambda: original(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(HOME, 'home_root_open', side_effect=self.root_delivery).start()
        mock.patch.object(HOME, 'HOME_OWNER_UID', os.geteuid()).start()
        mock.patch.object(HOME, 'HOME_OWNER_GID', os.getegid()).start()

    def observe(self, callback=None):
        return HOME.home_observe(callback or (lambda: copy.deepcopy(self.current_view)))

    def startup(self, name='.bashrc', data=b'# PUBLIC-FIXTURE-NOT-EXECUTED\n', mode=0o644):
        path = self.target / name; path.write_bytes(data); path.chmod(mode); return path

    def test_present_empty_protected_home_is_not_adoption_or_readiness(self):
        proof = self.observe()
        self.assertEqual(proof['home_status'], 'present'); self.assertEqual(len(proof['authority']), 16)
        self.assertTrue(all(flag is False for flag in proof['authority'].values()))
        self.assertEqual({item['path'] for item in proof['objects']},
                         {'/home', HOME.HOME_FIXED_PATH, HOME.HOME_FIXED_PATH + '/.ssh',
                          *(HOME.HOME_FIXED_PATH + '/' + name for name in HOME.HOME_STARTUPS)})

    def test_absent_target_is_qualified_without_creation(self):
        self.target.rmdir(); self.current_view = view(False)
        proof = self.observe(); self.assertEqual(proof['home_status'], 'absent')
        self.assertFalse(self.target.exists()); self.assertTrue(all(value is False for value in proof['authority'].values()))

    def test_absent_parent_is_qualified_without_creation(self):
        self.target.rmdir(); self.parent.rmdir(); self.current_view = view(False)
        proof = self.observe(); self.assertEqual(proof['home_status'], 'absent')
        self.assertEqual(proof['objects'], [{'path': '/home', 'kind': 'directory', 'status': 'absent'}])
        self.assertFalse(self.parent.exists())

    def test_existing_home_without_local_account_is_a_collision(self):
        self.current_view = view(False)
        before = HOME.home_identity(self.target.stat())
        with self.assertRaisesRegex(ValueError, 'without matching'): self.observe()
        self.assertEqual(HOME.home_identity(self.target.stat()), before)

    def test_opaque_binary_or_unicode_startup_bytes_are_only_hashed(self):
        data = b'\x00\xff' + 'not executed\u2028\u0085👩‍💻'.encode()
        path = self.startup(data=data); before = HOME.home_identity(path.stat())
        proof = self.observe(); item = next(value for value in proof['objects'] if value['path'].endswith('/.bashrc'))
        self.assertEqual(item['bytes'], len(data)); self.assertEqual(item['sha256'], hashlib.sha256(data).hexdigest())
        self.assertNotIn('not executed', json.dumps(proof)); self.assertFalse(proof['authority']['startup_scripts_safe'])
        self.assertEqual(HOME.home_identity(path.stat()), before); self.assertEqual(path.read_bytes(), data)

    def test_empty_startup_is_a_bounded_regular_snapshot(self):
        self.startup(data=b''); item = next(value for value in self.observe()['objects'] if value['path'].endswith('/.bashrc'))
        self.assertEqual(item['bytes'], 0); self.assertEqual(item['sha256'], hashlib.sha256(b'').hexdigest())

    def test_exact_startup_size_limit_passes_and_excess_refuses(self):
        path = self.startup(data=b'x' * HOME.HOME_FILE_LIMIT)
        self.assertEqual(next(value for value in self.observe()['objects'] if value['path'].endswith('/.bashrc'))['bytes'], HOME.HOME_FILE_LIMIT)
        path.write_bytes(b'x' * (HOME.HOME_FILE_LIMIT + 1))
        with self.assertRaises(ValueError): self.observe()

    def test_root_and_parent_write_permissions_refuse(self):
        for path in (self.root, self.parent):
            path.chmod(0o777)
            with self.subTest(path=str(path)), self.assertRaises(ValueError): self.observe()
            path.chmod(0o755)

    def test_home_modes_do_not_implicitly_grant_user_access(self):
        for mode in (0o700, 0o750, 0o775, 0o777, 0o2755):
            self.target.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.observe()
        self.target.chmod(0o755)

    def test_home_foreign_owner_or_group_delivery_refuses(self):
        with mock.patch.object(HOME, 'HOME_OWNER_UID', os.geteuid() + 1), self.assertRaises(ValueError): self.observe()
        with mock.patch.object(HOME, 'HOME_OWNER_GID', os.getegid() + 1), self.assertRaises(ValueError): self.observe()

    def test_parent_and_home_symlinks_are_not_followed(self):
        self.target.rmdir(); held = self.root / 'elsewhere'; held.mkdir(mode=0o755); self.target.symlink_to(held)
        with self.assertRaises(ValueError): self.observe()
        self.assertTrue(self.target.is_symlink()); self.target.unlink(); self.parent.rmdir(); self.parent.symlink_to(held)
        with self.assertRaises(ValueError): self.observe()
        self.assertTrue(self.parent.is_symlink())

    def test_wrong_kind_startup_leaves_are_preserved_before_open(self):
        path = self.target / '.bashrc'
        with socket.socket(socket.AF_UNIX) as listener:
            for kind in ('fifo', 'symlink', 'directory', 'socket'):
                if kind == 'fifo': os.mkfifo(path, 0o600)
                elif kind == 'symlink': path.symlink_to(self.root / 'missing')
                elif kind == 'directory': path.mkdir(mode=0o700)
                else: listener.bind(str(path))
                before = HOME.home_identity(path.lstat())
                with self.subTest(kind=kind), self.assertRaises(ValueError): self.observe()
                self.assertEqual(HOME.home_identity(path.lstat()), before)
                path.rmdir() if kind == 'directory' else path.unlink()

    def test_startup_modes_refuse_writable_executable_or_private_delivery(self):
        path = self.startup()
        for mode in (0o666, 0o664, 0o755, 0o600, 0o640):
            path.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(ValueError): self.observe()
        path.chmod(0o444); self.assertEqual(self.observe()['home_status'], 'present')

    def test_hardlinked_startup_is_not_borrowed(self):
        path = self.startup(); os.link(path, self.target / 'alias')
        with self.assertRaises(ValueError): self.observe()
        self.assertEqual(path.stat().st_nlink, 2)

    def test_leaf_open_requires_nofollow_nonblock_and_cloexec(self):
        self.startup(); original = HOME.os.open; calls = []
        def checked(name, flags, **kwargs):
            if name == '.bashrc':
                self.assertEqual(flags, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
                self.assertIn('dir_fd', kwargs); calls.append(name)
            return original(name, flags, **kwargs)
        with mock.patch.object(HOME.os, 'open', side_effect=checked): self.observe()
        self.assertEqual(calls, ['.bashrc'])

    def test_regular_leaf_race_to_fifo_refuses_without_waiting_for_reader(self):
        path = self.startup(); original = HOME.os.open
        def raced(name, flags, **kwargs):
            if name == '.bashrc': path.unlink(); os.mkfifo(path, 0o600)
            return original(name, flags, **kwargs)
        with mock.patch.object(HOME.os, 'open', side_effect=raced), self.assertRaisesRegex(ValueError, 'before read'):
            self.observe()
        self.assertTrue(stat.S_ISFIFO(path.lstat().st_mode))

    def test_startup_second_read_rejects_same_inode_content_change(self):
        path = self.startup(); calls = 0
        def changed():
            nonlocal calls
            calls += 1
            if calls == 2: path.write_bytes(b'CHANGED\n')
            return copy.deepcopy(self.current_view)
        with self.assertRaisesRegex(ValueError, 'startup snapshot'): self.observe(changed)

    def test_startup_namespace_replacement_refuses(self):
        path = self.startup(); replacement = self.root / 'replacement'; replacement.write_bytes(path.read_bytes()); replacement.chmod(0o644)
        calls = 0
        def changed():
            nonlocal calls
            calls += 1
            if calls == 2: os.replace(replacement, path)
            return copy.deepcopy(self.current_view)
        with self.assertRaisesRegex(ValueError, 'startup snapshot'): self.observe(changed)

    def test_home_directory_replacement_cannot_borrow_held_namespace(self):
        calls = 0
        def changed():
            nonlocal calls
            calls += 1
            if calls == 2: self.target.rename(self.parent / 'old'); self.target.mkdir(mode=0o755)
            return copy.deepcopy(self.current_view)
        with self.assertRaisesRegex(ValueError, 'directory namespace'): self.observe(changed)

    def test_missing_startup_appearance_refuses(self):
        calls = 0
        def changed():
            nonlocal calls
            calls += 1
            if calls == 2: self.startup()
            return copy.deepcopy(self.current_view)
        with self.assertRaises(ValueError): self.observe(changed)

    def test_missing_parent_appearance_refuses(self):
        self.target.rmdir(); self.parent.rmdir(); self.current_view = view(False); calls = 0
        def changed():
            nonlocal calls
            calls += 1
            if calls == 2: self.parent.mkdir(mode=0o755)
            return copy.deepcopy(self.current_view)
        with self.assertRaises(ValueError): self.observe(changed)

    def test_fresh_root_identity_change_refuses(self):
        other = self.root / 'other'; other.mkdir(mode=0o755); calls = 0
        def changed():
            nonlocal calls
            calls += 1
            return self.root_delivery() if calls == 1 else os.open(other, os.O_RDONLY | os.O_DIRECTORY)
        with mock.patch.object(HOME, 'home_root_open', side_effect=changed), self.assertRaisesRegex(ValueError, 'root namespace'):
            self.observe()

    def test_changed_local_account_view_refuses_before_publication(self):
        values = iter((view(), {**view(), 'sources': {'changed': 'MODEL'}}))
        with self.assertRaisesRegex(ValueError, 'account view changed'): self.observe(lambda: next(values))

    def test_malformed_or_authoritative_record_deliveries_refuse(self):
        for value in (None, {}, {**view(), 'administrator_name': 'other'}, {**view(), 'local_status': 'unsupported'},
                      {**view(False), 'account': view()['account']}, {**view(), 'account': None},
                      {**view(), 'authority': {'bad': True}}, {**view(), 'authority': {str(i): 0 for i in range(16)}}):
            with self.subTest(value=value), self.assertRaises(ValueError): self.observe(lambda: value)

    def test_ssh_directory_and_rc_are_optional_named_observations(self):
        ssh = self.target / '.ssh'; ssh.mkdir(mode=0o700); path = ssh / 'rc'; path.write_bytes(b'# NOT RUN\n'); path.chmod(0o644)
        proof = self.observe(); self.assertEqual(len([value for value in proof['objects'] if value['status'] == 'present']), 4)
        item = next(value for value in proof['objects'] if value['path'].endswith('/.ssh/rc'))
        self.assertEqual(item['sha256'], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertFalse(proof['authority']['startup_selection_complete'])

    def test_ssh_directory_symlink_and_mode_conflicts_are_preserved(self):
        path = self.target / '.ssh'; path.symlink_to(self.root / 'missing')
        with self.assertRaises(ValueError): self.observe()
        self.assertTrue(path.is_symlink()); path.unlink(); path.mkdir(mode=0o750)
        with self.assertRaises(ValueError): self.observe()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o750)

    def test_unlisted_objects_are_not_claimed_as_full_inventory(self):
        self.startup('unlisted', b'not inventoried\n')
        proof = self.observe(); self.assertFalse(proof['authority']['complete_home_inventory'])
        self.assertFalse(any(value['path'].endswith('/unlisted') for value in proof['objects']))

    def test_close_failure_withholds_observation(self):
        original = HOME.os.close
        def failed(descriptor): original(descriptor); raise OSError('delivered close failure')
        with mock.patch.object(HOME.os, 'close', side_effect=failed), self.assertRaisesRegex(OSError, 'close failure'):
            self.observe()

    def test_accepted_account_snapshots_and_home_integrate_on_private_filesystem(self):
        spec = importlib.util.spec_from_file_location('s4_private_records', ROOT / 'SSH/accounts.py')
        records = importlib.util.module_from_spec(spec); spec.loader.exec_module(records)
        directory = self.root / 'etc'; directory.mkdir(mode=0o700)
        data = {'passwd': ('root:x:0:0::/root:/bin/bash\n' + HOME.HOME_ADMIN + ':x:1003:1004:PRIVATE-GECOS:' + HOME.HOME_FIXED_PATH + ':/bin/bash\n').encode(),
                'group': ('root:x:0:\n' + HOME.HOME_ADMIN + ':x:1004:\n').encode(), 'shells': b'/bin/bash\n'}
        for name, body in data.items():
            path = directory / name; path.write_bytes(body); path.chmod(0o644)
        path = self.startup(); before = HOME.home_identity(path.stat())
        with mock.patch.object(records, 'TRUSTED_UID', os.geteuid()), mock.patch.object(records, 'root_open', side_effect=self.root_delivery):
            proof = HOME.home_observe(records.observe)
            self.assertEqual(proof['local_account']['account']['uid'], 1003)
            self.assertEqual(proof['home_status'], 'present')
            self.assertTrue(all(value is False for value in proof['local_account']['authority'].values()))
            self.assertTrue(all(value is False for value in proof['authority'].values()))
            self.assertNotIn('PRIVATE-GECOS', json.dumps(proof))
            self.assertEqual(HOME.home_identity(path.stat()), before)
            (directory / 'shells').write_bytes(b'/bin/sh\xe2\x80\xa8/bin/bash\n')
            with mock.patch.object(HOME, 'home_root_open', side_effect=AssertionError('must refuse record before home walk')), self.assertRaises(ValueError):
                HOME.home_observe(records.observe)


class SSHHomeCLITests(unittest.TestCase):
    def test_argument_overrides_refuse_before_preflight_or_namespace(self):
        for command in ([str(ROOT / 'azurelinux3s4.sh'), '--inspect-ssh-home', 'override'],
                        ['bash', '-c', 'source "$1"; s4_inspect_ssh_administrator invalid', 'fixture', str(ROOT / 'azurelinux3s4.sh')]):
            result = subprocess.run(command, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 64); self.assertEqual(result.stdout, b'')

    def test_literal_library_composition_preserves_account_globals_and_r1(self):
        namespace = {'__name__': 's4_administrator_library'}
        exec(compile((ROOT / 'SSH/accounts.py').read_bytes(), 'accepted-accounts', 'exec'), namespace)
        before = dict(namespace)
        exec(compile((ROOT / 'SSH/home.py').read_bytes(), 'home-library', 'exec'), namespace)
        self.assertEqual({name for name, value in before.items() if namespace[name] is not value}, {'__doc__'})
        for data in (b'/bin/sh\xe2\x80\xa8/bin/bash\n', b'x' * 4097 + b'\n'):
            with self.assertRaises(ValueError): namespace['lines'](data)

    def test_home_main_refusal_has_fixed_diagnostic_and_no_json(self):
        code = "import importlib.util; s=importlib.util.spec_from_file_location('h'," + repr(str(ROOT / 'SSH/home.py')) + "); h=importlib.util.module_from_spec(s); s.loader.exec_module(h); raise SystemExit(h.home_main(lambda: (_ for _ in ()).throw(ValueError('PRIVATE-DIAGNOSTIC'))))"
        result = subprocess.run([sys.executable, '-I', '-c', code], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 75); self.assertEqual(result.stdout, b'')
        self.assertEqual(result.stderr, b'SSH administrator home observation refused\n')


class NativeSSHHomeTests(unittest.TestCase):
    def native(self, delivered=False):
        before = {name: hashlib.sha256(Path('/etc', name).read_bytes()).hexdigest() for name in ('passwd', 'group', 'shells')}
        if delivered:
            with tempfile.TemporaryDirectory(prefix='s4-home-delivery-', dir='/dev/shm') as directory:
                path = Path(directory) / 'setup.sh'; path.write_bytes((ROOT / 'azurelinux3s4.sh').read_bytes()); path.chmod(0o755)
                result = subprocess.run(['bash', str(path), '--inspect-ssh-home'], capture_output=True, cwd=directory, timeout=10)
                self.assertEqual(sorted(value.name for value in Path(directory).iterdir()), ['setup.sh'])
            self.assertFalse(Path(directory).exists())
        else:
            result = subprocess.run([str(ROOT / 'azurelinux3s4.sh'), '--inspect-ssh-home'], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr); self.assertEqual(result.stderr, b'')
        proof = json.loads(result.stdout); self.assertEqual(proof['home_status'], 'absent')
        self.assertEqual(proof['local_account']['local_status'], 'absent')
        self.assertEqual(len(proof['authority']), 16); self.assertTrue(all(value is False for value in proof['authority'].values()))
        self.assertTrue(all(value is False for value in proof['local_account']['authority'].values()))
        after = {name: hashlib.sha256(Path('/etc', name).read_bytes()).hexdigest() for name in before}
        self.assertEqual(before, after)
        for name in before: self.assertEqual(proof['local_account']['sources'][name]['sha256'], before[name])
        self.assertEqual(Path('/').stat().st_uid, 0); self.assertEqual(Path('/home').stat().st_uid, 0)
        self.assertFalse(Path(HOME.HOME_FIXED_PATH).exists())
        self.record = {'proof': proof, 'actual_cli_wait_exit': result.returncode, 'delivered': delivered,
                       'public_record_sha256_before': before, 'public_record_sha256_after': after,
                       'root_fd_owner_group_or_account_delivery': False, 'actual_host_raw_records_or_startup_bytes_retained': False,
                       'accounts_created_or_home_installed': False, 'nss_pam_login_or_script_execution': False}

    def test_actual_protected_root_parent_and_absent_home(self): self.native()

    def test_standalone_home_inspection_without_checkout_or_preflight(self): self.native(delivered=True)


if __name__ == '__main__': unittest.main()

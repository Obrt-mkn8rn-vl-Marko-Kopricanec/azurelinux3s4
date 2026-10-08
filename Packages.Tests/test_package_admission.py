import base64
import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import stat
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / 'azurelinux3s4.sh'
KEY = SCRIPT.parent / 'Trust/vendor-key.asc'


def protected_model_parent():
    # Optional existing RAM directory, never a mount/account/permission change.
    candidate = Path('/run/user') / str(os.geteuid())
    try:
        value = candidate.lstat()
        if (stat.S_ISDIR(value.st_mode) and value.st_uid == os.geteuid() and not value.st_mode & 0o022
                and not os.statvfs(candidate).f_flag & os.ST_NOEXEC):
            return candidate
    except OSError:
        pass
    return Path.home() / '.cache'


class PackageAdmissionTests(unittest.TestCase):
    def setUp(self):
        previous = os.umask(0o077)
        self.addCleanup(os.umask, previous)
        cache = getattr(self, 'temporary_parent', Path.home() / '.cache')
        self.temporary = tempfile.TemporaryDirectory(prefix='azurelinux3s4-admission-', dir=cache)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ('bin', 'run'):
            (self.root / name).mkdir(mode=0o700)
        (self.root / 'vendor.asc').write_bytes(KEY.read_bytes())
        self.artifact = self.root / 'input.rpm'
        self.artifact.write_bytes(b'signed fixture\n')
        self.configuration = {}
        self.configure()
        self.command('rpm', r'''
import base64
import json
import os
from pathlib import Path
import sys
import time
root = Path(__file__).resolve().parent.parent
configuration = json.loads((root / 'configuration.json').read_text())
args = sys.argv[1:]
database = Path(args[args.index('--dbpath') + 1])
assert database.parent.parent == root / 'run'
assert args[:1] == ['--noplugins']
for value in ('_keyring rpmdb', '_pkgverify_level all', '_pkgverify_flags 0'):
    assert value in args
assert Path(os.environ['HOME']) == database.parent / 'home'
assert 'RPM_POPTEXEC_PATH' not in os.environ
assert 'RPM_CONFIGDIR' not in os.environ
with (root / 'calls').open('a') as log:
    log.write(json.dumps({'tool': 'rpm', 'args': args}) + '\n')
if configuration.get('hang'): time.sleep(100)
if '--initdb' in args:
    if configuration.get('init_error'): sys.exit(42)
    (database / 'key.json').write_text('[]')
elif '--import' in args:
    if configuration.get('import_error'): sys.exit(42)
    if not configuration.get('import_noop'):
        material = Path(args[-1]).read_bytes()
        assert material == (root / 'vendor.asc').read_bytes()
        body = ''.join(line for line in material.decode().splitlines() if line and not line.startswith(('-----', 'Version:', '=')))
        (database / 'key.json').write_text(json.dumps([body]))
elif '-qa' in args:
    if configuration.get('query_error'): sys.exit(42)
    admitted = json.loads((database / 'key.json').read_text())
    if admitted:
        print('gpg-pubkey-3135ce90-5e6fda74')
        if configuration.get('extra_key'): print('gpg-pubkey-12345678-12345678')
elif '-q' in args:
    if configuration.get('packet_error'): sys.exit(42)
    packets = json.loads((database / 'key.json').read_text())
    if configuration.get('wrong_packets'): packets = [base64.b64encode(b'wrong packets').decode()]
    print('\n'.join(packets))
else: sys.exit(99)
''')
        self.command('rpmkeys', r'''
import json
import os
from pathlib import Path
import sys
root = Path(__file__).resolve().parent.parent
configuration = json.loads((root / 'configuration.json').read_text())
args = sys.argv[1:]
database = Path(args[args.index('--dbpath') + 1])
assert database.parent.parent == root / 'run'
assert args[:1] == ['--noplugins']
for value in ('_keyring rpmdb', '_pkgverify_level all', '_pkgverify_flags 0'):
    assert value in args
assert Path(os.environ['HOME']) == database.parent / 'home'
assert '--checksig' in args and '--verbose' in args
with (root / 'calls').open('a') as log:
    log.write(json.dumps({'tool': 'rpmkeys', 'args': args}) + '\n')
if configuration.get('check_error'): sys.exit(42)
if configuration.get('oversize_output'):
    print('x' * 65537)
    sys.exit(0)
artifact = Path(args[-1])
assert artifact.parent == database.parent and artifact.stat().st_mode & 0o777 == 0o600
print(str(artifact) + ':')
kind = artifact.read_bytes().decode().strip()
records = ['Header V4 RSA/SHA256 Signature, key ID 3135ce90: OK',
           'Header SHA256 digest: OK', 'Header SHA1 digest: OK',
           'Payload SHA256 digest: OK', 'V4 RSA/SHA256 Signature, key ID 3135ce90: OK',
           'MD5 digest: OK']
if kind == 'unsigned fixture': records = records[1:]
if kind == 'foreign fixture': records[0] = records[0].replace('3135ce90', '12345678')
if kind == 'foreign additional signature fixture': records[4] = records[4].replace('3135ce90', '12345678')
if kind == 'corrupt fixture': records[3] = 'Payload SHA256 digest: BAD'
if kind == 'weak signature fixture': records[0] = records[0].replace('SHA256', 'SHA1')
if kind == 'weak payload fixture': records[3] = 'Payload SHA1 digest: OK'
if kind == 'header only fixture': records = records[:3]
if kind == 'unknown diagnostic fixture': records.append('verification outcome unknown')
if configuration.get('mutate_original'): (root / 'input.rpm').write_bytes(b'changed after snapshot\n')
for line in records: print('    ' + line)
''')

    def configure(self, **values):
        self.configuration = values
        (self.root / 'configuration.json').write_text(json.dumps(values))

    def command(self, name, body):
        path = self.root / 'bin' / name
        path.write_text('#!/usr/bin/python3\n' + body.lstrip())
        path.chmod(0o700)

    def shell(self, arguments=None, prefix='', expected=0, timeout=30):
        if arguments is None: arguments = [str(self.artifact)]
        header = f'''source {shlex.quote(str(SCRIPT))}
S4_RUN={shlex.quote(str(self.root / 'run'))}
S4_GPG_KEY={shlex.quote(str(self.root / 'vendor.asc'))}
export PATH={shlex.quote(str(self.root / 'bin'))}:$PATH
export RPM_CONFIGDIR=foreign RPM_POPTEXEC_PATH=foreign
'''
        result = subprocess.run(['bash', '-c', header + prefix + '\ns4_verify_rpm_artifacts ' + shlex.join(arguments)],
                                text=True, capture_output=True, timeout=timeout)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertEqual(list((self.root / 'run').iterdir()), [], 'private workspace leaked')
        if expected: self.assertEqual(result.stdout, '', 'failed batch published admission')
        return result

    def calls(self):
        path = self.root / 'calls'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_signed_snapshot_has_only_pinned_private_key_and_exact_digest(self):
        prior = self.artifact.read_bytes()
        proof = json.loads(self.shell().stdout)
        self.assertEqual(proof['artifacts'], [{'path': str(self.artifact), 'sha256': hashlib.sha256(prior).hexdigest(), 'bytes': len(prior)}])
        self.assertEqual(proof['vendor_fingerprint'], '2BC94FFF7015A5F28F1537AD0CD9FED33135CE90')
        self.assertFalse(proof['installs_performed'])
        self.assertFalse(proof['snapshots_retained'])
        self.assertFalse(proof['freshness_proven'])
        self.assertEqual(self.artifact.read_bytes(), prior)
        self.assertEqual([call['tool'] for call in self.calls()], ['rpm'] * 4 + ['rpmkeys'])

    def test_global_foreign_key_material_is_never_borrowed(self):
        foreign = self.root / 'system-rpmdb'
        foreign.mkdir()
        (foreign / 'key').write_text('unrelated operator key')
        before = (foreign / 'key').read_bytes()
        self.shell()
        self.assertEqual((foreign / 'key').read_bytes(), before)
        self.assertTrue(all(str(foreign) not in call['args'] for call in self.calls()))

    def test_zero_exit_unsigned_foreign_corrupt_and_weak_packages_are_rejected(self):
        for kind in ('unsigned', 'foreign', 'foreign additional signature', 'corrupt', 'weak signature', 'weak payload', 'header only', 'unknown diagnostic'):
            with self.subTest(kind=kind):
                self.artifact.write_text(kind + ' fixture\n')
                self.shell(expected=75)

    def test_batch_publishes_no_partial_success(self):
        second = self.root / 'second.rpm'
        second.write_bytes(b'foreign fixture\n')
        self.shell([str(self.artifact), str(second)], expected=75)
        self.assertEqual(len([call for call in self.calls() if call['tool'] == 'rpmkeys']), 2)

    def test_multiple_signed_artifacts_are_admitted_together(self):
        second = self.root / 'second.rpm'
        second.write_bytes(b'signed fixture\n')
        proof = json.loads(self.shell([str(self.artifact), str(second)]).stdout)
        self.assertEqual(len(proof['artifacts']), 2)
        databases = {call['args'][call['args'].index('--dbpath') + 1] for call in self.calls()}
        self.assertEqual(len(databases), 1)

    def test_private_database_failures_and_noop_import_cannot_certify(self):
        for setting in ('init_error', 'import_error', 'import_noop', 'query_error', 'packet_error', 'wrong_packets', 'extra_key'):
            with self.subTest(setting=setting):
                self.configure(**{setting: True})
                count = len([call for call in self.calls() if call['tool'] == 'rpmkeys'])
                self.shell(expected=75)
                self.assertEqual(len([call for call in self.calls() if call['tool'] == 'rpmkeys']), count)

    def test_damaged_key_refuses_before_any_rpm_invocation(self):
        (self.root / 'vendor.asc').write_bytes(b'changed material')
        self.shell(expected=75)
        self.assertEqual(self.calls(), [])

    def test_rpmkeys_failure_and_oversized_diagnostics_do_not_admit(self):
        for setting in ('check_error', 'oversize_output'):
            with self.subTest(setting=setting):
                self.configure(**{setting: True})
                self.shell(expected=75)

    def test_actual_fifo_socket_directory_and_symlink_inputs_refuse(self):
        # Observe actual opens by the unchanged embedded Python. A wrong-kind
        # object must be rejected before an open, not merely after fstat.
        self.command('python3', r'''
from pathlib import Path
import stat
import sys
root = Path(__file__).resolve().parent.parent
def observe(event, arguments):
    if event == 'open' and arguments[0] == str(root / 'input.rpm'):
        if not stat.S_ISREG((root / 'input.rpm').lstat().st_mode):
            (root / 'wrong-kind-open').write_text(str(arguments))
sys.addaudithook(observe)
sys.argv = sys.argv[2:]
exec(compile(sys.stdin.read(), '<stdin>', 'exec'), {'__name__': '__main__'})
''')
        path = self.artifact
        path.unlink()
        os.mkfifo(path, 0o600)
        inode = path.stat().st_ino
        # This wall budget also covers interpreter/private-keyring startup and
        # four RPM fixture commands. The audit below independently forbids any
        # wrong-kind open, so extra scheduling margin cannot hide FIFO IO.
        self.shell(expected=75, timeout=15)
        self.assertEqual(path.stat().st_ino, inode)
        path.unlink()
        path.mkdir()
        inode = path.stat().st_ino
        self.shell(expected=75)
        self.assertEqual(path.stat().st_ino, inode)
        path.rmdir()
        path.symlink_to(self.root / 'vendor.asc')
        self.shell(expected=75)
        self.assertTrue(path.is_symlink())
        path.unlink()
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(path))
            inode = path.stat().st_ino
            self.shell(expected=75)
            self.assertEqual(path.stat().st_ino, inode)
        self.assertFalse((self.root / 'wrong-kind-open').exists())

    def test_untrusted_writable_input_and_ancestry_refuse(self):
        self.artifact.chmod(0o666)
        self.shell(expected=75)
        self.artifact.chmod(0o600)
        self.root.chmod(0o777)
        self.shell(expected=75)
        self.root.chmod(0o700)

    def test_empty_oversized_and_relative_inputs_refuse(self):
        self.artifact.write_bytes(b'')
        self.shell(expected=75)
        with self.artifact.open('wb') as stream: stream.truncate(512 * 1024 * 1024 + 1)
        self.shell(expected=75)
        self.shell(['relative.rpm'], expected=75)

    def test_mutation_after_copy_cannot_change_the_verified_snapshot(self):
        before = self.artifact.read_bytes()
        self.configure(mutate_original=True)
        proof = json.loads(self.shell().stdout)
        self.assertNotEqual(self.artifact.read_bytes(), before)
        self.assertEqual(proof['artifacts'][0]['sha256'], hashlib.sha256(before).hexdigest())

    def test_bounded_timeout_reclaims_private_workspace(self):
        self.configure(hang=True)
        self.shell(prefix='timeout() { shift 3; command timeout --kill-after=1s 1s "$@"; };', expected=75, timeout=4)

    def test_unfinished_online_mutations_are_refused_before_verifier_or_tdnf(self):
        for arguments in ('upgrade', 'install nginx', 'erase bash', 'makecache --nosignature', ''):
            with self.subTest(arguments=arguments):
                result = subprocess.run(['bash', '-c', 'source ' + shlex.quote(str(SCRIPT)) +
                    '; s4_verify_metadata() { exit 99; }; s4_tdnf ' + arguments], capture_output=True, text=True)
                self.assertEqual(result.returncode, 78, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()

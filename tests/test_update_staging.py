import hashlib
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import unittest

import test_package_admission as admission_fixture


class UpdateStagingTests(unittest.TestCase):
    command = admission_fixture.PackageAdmissionTests.command
    configure = admission_fixture.PackageAdmissionTests.configure
    calls = admission_fixture.PackageAdmissionTests.calls

    def setUp(self):
        admission_fixture.PackageAdmissionTests.setUp(self)
        for name in ('state', 'state/updates', 'state/components', 'units', 'runner'):
            (self.root / name).mkdir(mode=0o700)
        (self.root / 'state/tdnf.conf').write_text('[main]\ncachedir=/var/cache/tdnf/azurelinux3s4\n')
        # The existing admission fixture asserts volatile snapshots. Only this
        # disposable test fixture additionally permits the retained private slot.
        verifier = self.root / 'bin/rpmkeys'
        verifier.write_text(verifier.read_text().replace(
            'assert artifact.parent == database.parent and artifact.stat().st_mode & 0o777 == 0o600',
            "assert artifact.parent.parent.parent == root / 'state/updates' and artifact.stat().st_mode & 0o777 == 0o600"))
        self.command('gpg2', r'''
import os
import shutil
import sys
os.execv(shutil.which('gpg'), ['gpg', *sys.argv[1:]])
''')
        self.command('systemd-run', r'''
import json
import os
from pathlib import Path
import subprocess
import sys
root = Path(__file__).resolve().parent.parent
args = sys.argv[1:]
required = ['--wait', '--pipe', '--collect', '--service-type=exec',
    '--property=ProtectSystem=strict', '--property=NoNewPrivileges=yes',
    '--property=CapabilityBoundingSet=', '--property=PrivateDevices=yes',
    '--property=ProtectHome=yes', '--property=RuntimeMaxSec=14min',
    '--property=InaccessiblePaths=/run/systemd/private /run/dbus/system_bus_socket']
assert all(value in args for value in required)
environment = dict(os.environ)
for value in args:
    if value.startswith('--setenv='):
        name, data = value.removeprefix('--setenv=').split('=', 1)
        environment[name] = data
with (root / 'sandbox-calls').open('a') as log: log.write(json.dumps(args) + '\n')
command = args[args.index('--') + 1:]
assert command[:3] == ['python3', '-I', '-c']
assert 'CapBnd' in command[3] and 'os.ST_RDONLY' in command[3]
configuration = json.loads((root / 'configuration.json').read_text())
if not configuration.get('no_sandbox_proof'): print('S4_DOWNLOAD_SANDBOX_VERIFIED', flush=True)
command = command[4:]
command[0] = str(root / 'bin/tdnf')
sys.exit(subprocess.run(command, env=environment).returncode)
''')
        self.command('tdnf', r'''
import json
import os
from pathlib import Path
import sys
root = Path(__file__).resolve().parent.parent
configuration = json.loads((root / 'configuration.json').read_text())
args = sys.argv[1:]
assert args[-3:-1] == ['upgrade', '--downloadonly']
incoming = Path(args[-1].removeprefix('--downloaddir='))
assert incoming.parent.parent == root / 'run'
assert Path(os.environ['GNUPGHOME']).is_dir()
assert '--noplugins' not in args
config = Path(args[args.index('-c') + 1]).read_text()
assert 'cachedir=' + str(Path(os.environ['GNUPGHOME']).parent / 'cache') in config
if not configuration.get('no_loader'): print('Loaded plugin: tdnfrepogpgcheck')
if configuration.get('loader_error'): print('Error loading plugin')
if configuration.get('download_failure'): sys.exit(42)
if configuration.get('empty'):
    if not configuration.get('silent'): print('Nothing to do.')
else:
    (incoming / 'first.rpm').write_bytes((root / 'input.rpm').read_bytes())
    (incoming / 'first.rpm').chmod(configuration.get('incoming_mode', 0o644))
    if configuration.get('second'):
        (incoming / 'second.rpm').write_text(configuration['second'] + ' fixture\n')
    if configuration.get('fifo'): os.mkfifo(incoming / 'fifo.rpm', 0o600)
    if configuration.get('link'): (incoming / 'link.rpm').symlink_to(root / 'input.rpm')
    if configuration.get('noise'): print('x' * (1024 * 1024 + 1))
''')
        self.command('systemctl', r'''
from pathlib import Path
import sys
root = Path(__file__).resolve().parent.parent
with (root / 'manager-calls').open('a') as log: log.write(' '.join(sys.argv[1:]) + '\n')
''')
        self.command('sync', r'''
import json
import os
from pathlib import Path
import sys
root = Path(__file__).resolve().parent.parent
configuration = json.loads((root / 'configuration.json').read_text())
with (root / 'barriers').open('a') as log: log.write(' '.join(sys.argv[1:]) + '\n')
if configuration.get('sync_failure'):
    current = (root / 'state/updates/current.json').exists()
    manifest = any((root / 'state/updates').glob('slot*/manifest.json'))
    if ((not configuration.get('after_current') and not configuration.get('after_manifest'))
            or configuration.get('after_current') and current
            or configuration.get('after_manifest') and manifest): sys.exit(42)
for name in sys.argv[1:]:
    if name in ('-f', '--'): continue
    path = Path(name)
    path.relative_to(root)
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
    try: os.fsync(descriptor)
    finally: os.close(descriptor)
''')

    def shell(self, body='s4_prepare_updates', expected=0, timeout=45):
        header = f'''source {shlex.quote(str(admission_fixture.SCRIPT))}
S4_STATE={shlex.quote(str(self.root / 'state'))}
S4_RUN={shlex.quote(str(self.root / 'run'))}
S4_GPG_KEY={shlex.quote(str(self.root / 'vendor.asc'))}
S4_SYSTEMD_DIR={shlex.quote(str(self.root / 'units'))}
S4_INSTALL_DIR={shlex.quote(str(self.root / 'runner'))}
export PATH={shlex.quote(str(self.root / 'bin'))}:$PATH
S4_NOW=1000000
s4_verify_metadata() {{ return 0; }}
'''
        result = subprocess.run(['bash', '-c', header + body], text=True,
                                capture_output=True, timeout=timeout)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        self.assertEqual(list((self.root / 'run').iterdir()), [], 'volatile workspace leaked')
        if expected:
            self.assertEqual(result.stdout, '', 'failed preparation published success')
        return result

    def current(self):
        pointer = json.loads((self.root / 'state/updates/current.json').read_text())
        slot = self.root / 'state/updates' / ('slot' + pointer['slot'])
        return pointer, slot, json.loads((slot / 'manifest.json').read_text())

    def test_prepared_bytes_are_the_native_verified_snapshots(self):
        before = self.artifact.read_bytes()
        self.shell()
        pointer, slot, proof = self.current()
        retained = slot / 'packages/0.rpm'
        self.assertEqual(retained.read_bytes(), before)
        self.assertEqual(retained.stat().st_mode & 0o777, 0o400)
        self.assertEqual(proof['packages'], [{'file': 'packages/0.rpm', 'bytes': len(before),
            'sha256': hashlib.sha256(before).hexdigest()}])
        self.assertFalse(proof['installs_performed'])
        self.assertFalse(proof['freshness_proven'])
        verified = [call['args'][-1] for call in self.calls() if call['tool'] == 'rpmkeys']
        self.assertEqual(verified, [str(retained)])
        self.assertEqual(pointer['manifest_sha256'], hashlib.sha256((slot / 'manifest.json').read_bytes()).hexdigest())
        self.shell('s4_update_store verify')

    def test_two_slots_bound_repeated_success_without_losing_current(self):
        for index in range(4):
            self.shell()
            pointer, _, _ = self.current()
            self.assertEqual(pointer['slot'], str(index % 2))
        self.assertEqual({path.name for path in (self.root / 'state/updates').iterdir()},
                         {'slot0', 'slot1', 'current.json'})

    def test_failed_download_preserves_the_previous_batch(self):
        self.shell()
        before = (self.root / 'state/updates/current.json').read_bytes()
        self.configure(download_failure=True)
        self.shell(expected=75)
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), before)

    def test_unsigned_foreign_and_damaged_batches_publish_nothing(self):
        for kind in ('unsigned', 'foreign', 'corrupt', 'header only'):
            with self.subTest(kind=kind):
                self.configure(second=kind)
                self.shell(expected=75)
                self.assertFalse((self.root / 'state/updates/current.json').exists())

    def test_native_zero_without_loader_or_with_loader_error_is_pending(self):
        for setting in ('no_loader', 'loader_error'):
            with self.subTest(setting=setting):
                self.configure(**{setting: True})
                self.shell(expected=75)
                self.assertFalse((self.root / 'state/updates/current.json').exists())

    def test_empty_batch_requires_explicit_native_no_action(self):
        self.configure(empty=True, silent=True)
        self.shell(expected=75)
        self.configure(empty=True)
        self.shell()
        self.assertEqual(self.current()[2]['packages'], [])

    def test_actual_download_fifo_and_symlink_are_rejected(self):
        for setting in ('fifo', 'link'):
            with self.subTest(setting=setting):
                self.configure(**{setting: True})
                self.shell(expected=75)
                self.assertFalse((self.root / 'state/updates/current.json').exists())

    def test_bounded_streaming_diagnostics_stop_the_download_service(self):
        self.configure(noise=True)
        self.shell(expected=75)
        self.assertIn('stop azurelinux3s4-download-', (self.root / 'manager-calls').read_text())

    def test_failed_initial_barrier_publishes_no_current(self):
        self.configure(sync_failure=True)
        self.shell(expected=75)
        self.assertFalse((self.root / 'state/updates/current.json').exists())
        self.configure()
        self.shell()

    def test_failed_publication_barrier_cannot_be_certified_by_visibility(self):
        self.configure(sync_failure=True, after_current=True)
        self.shell(expected=75)
        self.assertTrue((self.root / 'state/updates/current.json').exists())
        pointer = (self.root / 'state/updates/current.json').read_bytes()
        count = len((self.root / 'barriers').read_text().splitlines())
        self.shell('s4_update_store verify', expected=75)
        self.shell(expected=75)
        self.assertGreater(len((self.root / 'barriers').read_text().splitlines()), count)
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), pointer)
        self.assertFalse((self.root / 'state/updates/slot1').exists())
        self.configure()
        self.shell()

    def test_current_bytes_are_checked_before_reusing_the_other_slot(self):
        self.shell()
        _, slot, _ = self.current()
        retained = slot / 'packages/0.rpm'
        retained.chmod(0o600)
        retained.write_bytes(b'changed retained bytes\n')
        retained.chmod(0o400)
        self.shell(expected=75)
        self.assertFalse((self.root / 'state/updates/slot1').exists())

    def test_foreign_slot_files_and_wrong_kind_objects_are_preserved(self):
        self.shell('s4_directory "$S4_STATE/updates/slot0" 0700; printf operator > "$S4_STATE/updates/slot0/foreign"')
        foreign = self.root / 'state/updates/slot0/foreign'
        inode = foreign.stat().st_ino
        self.shell(expected=75)
        self.assertEqual(foreign.stat().st_ino, inode)
        self.assertEqual(foreign.read_text(), 'operator')

    def test_current_fifo_socket_directory_and_symlink_refuse_without_opening(self):
        current = self.root / 'state/updates/current.json'
        os.mkfifo(current, 0o600)
        inode = current.stat().st_ino
        self.shell(expected=75, timeout=5)
        self.assertEqual(current.stat().st_ino, inode)
        current.unlink()
        current.mkdir(mode=0o700)
        self.shell(expected=75)
        current.rmdir()
        current.symlink_to(self.artifact)
        self.shell(expected=75)
        current.unlink()
        with socket.socket(socket.AF_UNIX) as channel:
            channel.bind(str(current))
            self.shell(expected=75)

    def test_package_changing_and_arbitrary_download_arguments_remain_closed(self):
        self.shell('s4_tdnf upgrade', expected=78)
        self.shell('s4_tdnf install nginx', expected=78)
        self.shell('s4_tdnf upgrade --downloadonly --downloaddir=/etc', expected=78)
        self.assertFalse((self.root / 'sandbox-calls').exists())

    def test_automatic_preparation_honors_backoff_without_download(self):
        self.shell('s4_write_state update-preparation pending 1 1000030 75; s4_reconcile_component update-preparation no', expected=75)
        self.assertFalse((self.root / 'sandbox-calls').exists())

    def test_finalization_is_forbidden_from_retiring_periodic_preparation(self):
        self.shell('s4_stop_timer "$S4_UPDATE_TIMER"', expected=78)
        self.assertFalse((self.root / 'manager-calls').exists())

    def test_interrupted_candidate_does_not_replace_current_and_is_reusable(self):
        self.shell()
        before = (self.root / 'state/updates/current.json').read_bytes()
        self.shell('''saved=$(declare -f s4_update_store); eval "${saved/s4_update_store/original_update_store}"
s4_update_store() { if [[ $1 == commit ]]; then return 99; fi; original_update_store "$@"; }
s4_prepare_updates''', expected=75)
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), before)
        self.assertTrue((self.root / 'state/updates/slot1/packages/0.rpm').is_file())
        self.shell()
        self.assertEqual(self.current()[0]['slot'], '1')

    def test_adverse_loss_of_unflushed_pointer_preserves_old_durable_batch(self):
        self.shell()
        current = self.root / 'state/updates/current.json'
        durable = current.read_bytes()
        self.configure(sync_failure=True, after_current=True)
        # The failure on the prior pointer's repeated barrier prevents ANY reuse.
        self.shell(expected=75)
        self.assertFalse((self.root / 'state/updates/slot1').exists())
        self.configure()
        # Permit pre-existing-current persistence, then fail the first barrier
        # after publishing slot1. Model a crash that loses that unflushed rename.
        sync = self.root / 'bin/sync'
        sync.write_text(sync.read_text().replace("if configuration.get('sync_failure'):",
            "if (root / 'state/updates/current.json').exists() and json.loads((root / 'state/updates/current.json').read_text())['slot'] == '1': sys.exit(42)\nif configuration.get('sync_failure'):"))
        self.shell(expected=75)
        self.assertEqual(self.current()[0]['slot'], '1')
        current.write_bytes(durable)
        self.shell('s4_update_store verify')
        self.assertEqual(self.current()[0]['slot'], '0')

    def test_no_preparation_completion_when_periodic_activation_fails(self):
        self.shell('s4_start_timer() { return 42; }; s4_reconcile_component update-preparation yes', expected=75)
        self.assertFalse((self.root / 'sandbox-calls').exists())
        self.assertIn('status=pending', (self.root / 'state/components/update-preparation').read_text())

    def test_automatic_success_records_only_preparation(self):
        self.shell('s4_start_timer() { return 0; }; s4_reconcile_component update-preparation yes')
        self.assertIn('status=complete', (self.root / 'state/components/update-preparation').read_text())
        self.assertFalse(self.current()[2]['installs_performed'])

    def test_damaged_verifier_defers_before_starting_downloader(self):
        self.shell('s4_verify_metadata() { return 42; }; s4_prepare_updates', expected=75)
        self.assertFalse((self.root / 'sandbox-calls').exists())

    def test_group_or_world_writable_download_is_refused(self):
        self.configure(incoming_mode=0o666)
        self.shell(expected=75)
        self.assertFalse((self.root / 'state/updates/current.json').exists())

    def test_sandbox_without_positive_enforcement_observation_is_pending(self):
        self.configure(no_sandbox_proof=True)
        self.shell(expected=75)
        self.assertFalse((self.root / 'state/updates/current.json').exists())

    def test_safe_empty_slot_from_interrupted_creation_recovers(self):
        (self.root / 'state/updates/slot0').mkdir(mode=0o700)
        self.shell()
        self.assertEqual(self.current()[0]['slot'], '0')

    def test_interrupted_initial_marker_recovers_only_its_empty_slot_prefix(self):
        slot = self.root / 'state/updates/slot0'
        slot.mkdir(mode=0o700)
        for material in (b'', b'azurelinux3s4-update-'):
            with self.subTest(material=material):
                (slot / 'owner').write_bytes(material)
                self.shell('s4_update_store begin')
                self.assertEqual((slot / 'owner').read_bytes(), b'azurelinux3s4-update-slot-v1\n')
                (slot / 'packages').rmdir()
        (slot / 'owner').write_bytes(b'operator')
        self.shell('s4_update_store begin', expected=75)
        self.assertEqual((slot / 'owner').read_bytes(), b'operator')

    def test_interruption_during_slot_recycling_keeps_recognizable_ownership(self):
        for _ in range(3):
            self.shell()
        current = (self.root / 'state/updates/current.json').read_bytes()
        self.command('python3', r'''
import os
import sys
program = sys.stdin.read()
original = os.unlink
def remove(path, *args, **options):
    original(path, *args, **options)
    if str(path).endswith('slot1/manifest.json'): os._exit(99)
os.unlink = remove
sys.argv = ['-'] + sys.argv[3:]
exec(compile(program, '<unchanged-source>', 'exec'))
''')
        self.shell(expected=75)
        slot = self.root / 'state/updates/slot1'
        self.assertEqual((slot / 'owner').read_bytes(), b'azurelinux3s4-update-slot-v1\n')
        self.assertTrue((slot / 'packages').is_dir())
        self.assertEqual((self.root / 'state/updates/current.json').read_bytes(), current)
        (self.root / 'bin/python3').unlink()
        self.shell()
        self.assertEqual(self.current()[0]['slot'], '1')


if __name__ == '__main__':
    unittest.main()

"""Private file IO for disconnected configuration installation; no host actions."""

import collections
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock

from test_deployment_policy import encoded, emitted_program, library, manifest
from test_deployment_publication import PublicationOS


ROOT = Path(__file__).resolve().parents[1]


class ConfigurationInstallationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=Path.home() / '.cache')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.n = library()
        for name in ('publication', 'application_installation', 'configuration_installation'):
            path = ROOT / 'Deployment' / (name + '.py')
            exec(compile(path.read_bytes(), str(path), 'exec'), self.n)
        self.delivery = PublicationOS(self.root)
        self.n['dep_os'] = self.delivery
        self.n['DEP_TRUSTED_UID'] = os.geteuid()
        self.value = manifest()
        self.data = encoded(self.value)
        self.digest, self.record, self.rows = self.n['configuration_installation_plan'](self.data, self.n['bundle'])
        for name in self.n['CONFIG_INSTALL_DIRECTORIES']:
            p = self.root / name[1:]; p.mkdir(parents=True, mode=0o700)
            for parent in (p, *p.parents):
                if parent == self.root.parent:
                    break
                parent.chmod(0o700)
        self.state = self.root / self.n['CONFIG_INSTALL_STATE'][1:]

    def install(self):
        return self.n['configuration_installation'](encoded(self.value), self.n['bundle'])

    def leaf(self, index):
        row = self.rows[index]
        return self.root / row['parent'][1:] / row['leaf']

    def snapshot(self):
        return {str(p.relative_to(self.root)): (p.read_bytes(), stat.S_IMODE(p.stat().st_mode))
                for p in self.root.rglob('*') if p.is_file() and not p.is_symlink()}

    def owner(self):
        p = self.state / 'installation.json'; p.write_bytes(self.record); p.chmod(0o400)

    def closed(self):
        self.assertEqual(collections.Counter(self.delivery.acquired), collections.Counter(self.delivery.closed))

    def test_complete_five_file_installation_and_idempotent_retry_preserve_exact_bytes_modes(self):
        result = self.install()
        self.assertEqual((result['files'], result['changed_files']), (5, 5))
        self.assertEqual(result['publication_sha256'], self.digest)
        self.assertEqual(result['installation_record_sha256'], hashlib.sha256(self.record).hexdigest())
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual(len(result['authority']), 16)
        for index, row in enumerate(self.rows):
            self.assertEqual((self.leaf(index).read_bytes(), stat.S_IMODE(self.leaf(index).stat().st_mode)),
                             (row['raw'], row['mode']))
        before = self.snapshot()
        identities = {str(p): self.n['deployment_identity'](p.stat()) for p in self.root.rglob('*') if p.is_file()}
        again = self.install()
        self.assertEqual(again['changed_files'], 0)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual({str(p): self.n['deployment_identity'](p.stat()) for p in self.root.rglob('*') if p.is_file()}, identities)
        self.assertFalse((self.root / 'etc/systemd').exists())
        self.assertFalse((self.root / 'usr').exists())
        self.closed()

    def test_late_unowned_or_foreign_payload_refuses_before_early_file_and_lock_writes(self):
        self.leaf(4).write_bytes(self.rows[4]['raw']); self.leaf(4).chmod(0o600)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'ownership'):
            self.install()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(list(self.state.iterdir()), [])
        self.closed()

    def test_zero_private_configuration_write_retains_owner_and_resumes_same600_inode(self):
        original = self.delivery.write
        self.delivery.write = lambda fd, raw: 0 if raw == self.rows[2]['raw'] else original(fd, raw)
        with self.assertRaisesRegex(ValueError, 'incomplete installation write'):
            self.install()
        self.assertEqual(self.leaf(2).read_bytes(), b'')
        self.assertEqual(stat.S_IMODE(self.leaf(2).stat().st_mode), 0o600)
        inode = self.leaf(2).stat().st_ino
        self.assertEqual((self.state / 'installation.json').read_bytes(), self.record)
        self.delivery.write = original
        result = self.install()
        self.assertEqual(result['changed_files'], 3)
        self.assertEqual(self.leaf(2).stat().st_ino, inode)
        self.assertEqual(self.leaf(2).read_bytes(), self.rows[2]['raw'])
        self.closed()

    def test_late_owned_mismatch_or_plan_change_cannot_complete_earlier_private_prefix(self):
        self.owner()
        self.leaf(0).write_bytes(self.rows[0]['raw'][:8]); self.leaf(0).chmod(0o600)
        self.leaf(4).write_bytes(b'foreign'); self.leaf(4).chmod(0o600)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'mismatch'):
            self.install()
        self.assertEqual(self.snapshot(), before)
        self.leaf(4).unlink()
        self.value['mail']['pop3s'] = True
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(self.snapshot(), before)
        self.closed()

    def test_partial_owner_linked_destination_and_missing_ancestry_are_never_adopted(self):
        p = self.state / 'installation.json'; p.write_bytes(self.record[:10]); p.chmod(0o400)
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(self.snapshot(), before)
        p.unlink(); self.owner()
        self.leaf(3).write_bytes(self.rows[3]['raw']); self.leaf(3).chmod(0o600)
        alias = self.root / 'alias'; os.link(self.leaf(3), alias)
        before = self.snapshot()
        with self.assertRaisesRegex(ValueError, 'leaf'):
            self.install()
        self.assertEqual(self.snapshot(), before)
        alias.unlink(); self.leaf(3).unlink(); self.leaf(3).parent.rmdir()
        with self.assertRaises(FileNotFoundError):
            self.install()
        self.assertFalse(self.leaf(3).parent.exists())
        self.closed()

    def test_corrupt_last_compiled_commitment_refuses_before_any_destination_io(self):
        original = self.n['publication_plan']
        def corrupt(*args):
            digest, contents = original(*args)
            intent = json.loads(contents['publication.json'])
            intent['files'][-1]['sha256'] = '0' * 64
            contents['publication.json'] = encoded(intent)
            return hashlib.sha256(contents['publication.json']).hexdigest(), contents
        self.n['publication_plan'] = corrupt
        self.n['installation_directories'] = Mock(side_effect=AssertionError('target IO forbidden'))
        with self.assertRaisesRegex(ValueError, 'commitment'):
            self.install()
        self.n['installation_directories'].assert_not_called()
        self.assertEqual(self.snapshot(), {})

    def test_whole_delivered_library_private_model_and_production_dispatch_remain_separate(self):
        full = emitted_program()
        body, dispatch = full.split('action = sys.argv[1]\n', 1)
        self.assertNotIn('configuration_installation(', dispatch)
        self.assertNotIn('configuration_installation', (ROOT / 'Bootstrap/main.sh').read_text())
        source = body + ('\nDEP_TRUSTED_UID = dep_os.geteuid()\n'
            '_original_os = dep_os\n'
            'class PrivateRoot:\n'
            '    def __getattr__(self, name): return getattr(_original_os, name)\n'
            '    def open(self, path, flags, *args, **kwargs):\n'
            '        return _original_os.open(' + repr(str(self.root)) + ' if path == "/" else path, flags, *args, **kwargs)\n'
            'dep_os = PrivateRoot()\n'
            'result = configuration_installation(' + repr(self.data) + ', bundle)\n'
            'print(publication_encoded(result).decode("ascii"), end="")\n')
        child = subprocess.run([sys.executable, '-I', '-B', '-'], input=source.encode('ascii'),
                               capture_output=True, timeout=30)
        self.assertEqual(child.returncode, 0, child.stderr)
        result = json.loads(child.stdout)
        self.assertEqual(result['files'], 5)
        self.assertTrue(all(value is False for value in result['authority'].values()))
        for index, row in enumerate(self.rows):
            self.assertEqual(self.leaf(index).read_bytes(), row['raw'])

"""Offline release staging with synthetic publishes and actual private file IO."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from unittest.mock import patch

import test_deployment_releases as fixture


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('development_release', ROOT / 'Bootstrap/release.py')
RELEASE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RELEASE)


class ReleaseStagingTests(fixture.ReleaseFixture):
    def inputs(self, app='mk8.sava'):
        roles = {role: self.folder(app) / role for role in self.n['REL_PROGRAMS'][app]}
        config = {name: self.root / 'etc' / app / name for name in self.n['REL_CONFIGS'][app]}
        return app, '1' * 40, '2' * 40, roles, config, self.root / ('staged-' + app)

    def test_all_four_staged_manifests_match_original_bytes_and_modes_without_copying_secrets(self):
        for app in self.n['DEP_APPS']:
            with self.subTest(app=app):
                args = self.inputs(app)
                originals = {str(p): p.read_bytes() for p in self.folder(app).rglob('*') if p.is_file()}
                originals.update({str(p): p.read_bytes() for p in args[4].values()})
                result = RELEASE.stage(*args)
                raw = (args[-1] / 'release.json').read_bytes()
                self.assertEqual(json.loads(raw), self.documents[app])
                self.assertEqual(result['declaration']['manifest_sha256'], hashlib.sha256(raw).hexdigest())
                self.assertEqual(result['files'], 16)
                self.assertEqual(len(result['runtime']), 2)
                for name in ('configuration_copied', 'source_or_build_authenticated',
                             'installed_ownership_admitted', 'application_executed', 'server_ready'):
                    self.assertIs(result[name], False)
                self.assertEqual(stat.S_IMODE(args[-1].stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE((args[-1] / 'release.json').stat().st_mode), 0o400)
                self.assertEqual(sorted(str(p.relative_to(args[-1])) for p in args[-1].rglob('*') if p.is_file()),
                                 sorted(['release.json'] + [row['path'] for row in self.documents[app]['files']]))
                for row in self.documents[app]['files']:
                    p = args[-1] / row['path']
                    self.assertEqual(p.read_bytes(), originals[str(self.folder(app) / row['path'])])
                    self.assertEqual(stat.S_IMODE(p.stat().st_mode), int(row['mode'], 8))
                    self.assertEqual(p.stat().st_nlink, 1)
                self.assertEqual({name: Path(name).read_bytes() for name in originals}, originals)

    def test_original_sdk_json_without_lf_and_complete_cli_receipt(self):
        args = self.inputs()
        for role, program in self.n['REL_PROGRAMS'][args[0]].items():
            for suffix in ('.runtimeconfig.json', '.deps.json'):
                path = args[3][role] / (program + suffix)
                path.write_bytes(path.read_bytes().rstrip(b'\n'))
        command = [sys.executable, '-B', str(ROOT / 'Bootstrap/release.py'), '--app', args[0],
                   '--commit', args[1], '--tree', args[2], '--output', str(args[-1])]
        for flag, values in (('--role', args[3]), ('--config', args[4])):
            for name, path in values.items():
                command.extend((flag, name + '=' + str(path)))
        child = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(child.stderr, b'')
        self.assertEqual(json.loads(child.stdout)['files'], 16)
        for role, program in self.n['REL_PROGRAMS'][args[0]].items():
            self.assertFalse((args[-1] / role / (program + '.deps.json')).read_bytes().endswith(b'\n'))
        again = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual((again.returncode, again.stdout, again.stderr),
                         (75, b'', b'Development release staging refused\n'))

    def test_incomplete_roles_configuration_and_unsafe_output_are_refused_before_writes(self):
        args = list(self.inputs())
        variants = [(3, {'application': args[3]['application']}),
                    (4, {key: value for key, value in args[4].items() if key != 'rpc.key'}),
                    (1, 'A' * 40), (2, '../foreign'), (5, args[3]['application'] / 'output')]
        for index, value in variants:
            with self.subTest(index=index, value=str(value)):
                changed = args.copy(); changed[index] = value
                with self.assertRaises(ValueError):
                    RELEASE.stage(*changed)
                self.assertFalse(args[-1].exists())
        with self.assertRaises(ValueError):
            RELEASE.bindings(['application=/one', 'application=/two'])
        public = self.root / 'public-parent'; public.mkdir(mode=0o755); public.chmod(0o755)
        args[-1] = public / 'output'
        with self.assertRaisesRegex(ValueError, '0700'):
            RELEASE.stage(*args)
        self.assertFalse(args[-1].exists())

    def test_symlink_hardlink_and_fifo_publish_entries_refuse_without_changing_originals(self):
        args = self.inputs()
        extra = args[3]['gateway'] / 'late-input'
        source = args[3]['gateway'] / 'System.Private.CoreLib.dll'
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    extra.symlink_to(source)
                elif kind == 'hardlink':
                    os.link(source, extra)
                else:
                    os.mkfifo(extra, 0o600)
                try:
                    with self.assertRaises((OSError, ValueError)):
                        RELEASE.stage(*args)
                    self.assertFalse(args[-1].exists())
                    self.assertEqual(source.read_bytes(), b'MZ synthetic core fixture\n')
                finally:
                    extra.unlink()

    def test_invalid_late_runtime_and_missing_native_dependency_refuse_before_output(self):
        args = self.inputs()
        native = args[3]['gateway'] / 'libcoreclr.so'
        original = native.read_bytes()
        native.write_bytes(b'not a native image')
        with self.assertRaisesRegex(ValueError, 'ELF'):
            RELEASE.stage(*args)
        self.assertFalse(args[-1].exists())
        native.write_bytes(original)
        native.unlink()
        with self.assertRaisesRegex(ValueError, 'runtime files'):
            RELEASE.stage(*args)
        self.assertFalse(args[-1].exists())

    def test_source_change_between_admission_and_copy_refuses_without_manifest(self):
        args = self.inputs()
        source = args[3]['application'] / self.n['REL_PROGRAMS'][args[0]]['application']
        original = RELEASE.create_file
        changed = False
        def create(parent, leaf):
            nonlocal changed
            if not changed:
                changed = True
                source.write_bytes(source.read_bytes() + b'changed')
            return original(parent, leaf)
        with patch.object(RELEASE, 'create_file', side_effect=create):
            with self.assertRaisesRegex(ValueError, 'changed since admission'):
                RELEASE.stage(*args)
        self.assertFalse((args[-1] / 'release.json').exists())
        self.assertTrue(args[-1].exists())

    def test_zero_write_and_checked_close_failure_never_return_success_or_allow_retry_adoption(self):
        args = self.inputs()
        before = self.snapshot()
        with patch.object(RELEASE.os, 'write', return_value=0):
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                RELEASE.stage(*args)
        self.assertFalse((args[-1] / 'release.json').exists())
        for name, (digest, mode) in before.items():
            p = self.root / name
            self.assertEqual((hashlib.sha256(p.read_bytes()).hexdigest(), stat.S_IMODE(p.stat().st_mode)), (digest, mode))
        with self.assertRaisesRegex(ValueError, 'already exists'):
            RELEASE.stage(*args)
        args = (*args[:-1], self.root / 'close-failure')
        original_create, original_close, target = RELEASE.create_file, RELEASE.os.close, [None]
        def create(parent, leaf):
            fd = original_create(parent, leaf)
            target[0] = fd
            return fd
        def close(fd):
            original_close(fd)
            if fd == target[0]:
                target[0] = None
                raise OSError('controlled output close failure')
        with patch.object(RELEASE, 'create_file', side_effect=create), patch.object(RELEASE.os, 'close', side_effect=close):
            with self.assertRaisesRegex(OSError, 'controlled output close'):
                RELEASE.stage(*args)
        self.assertFalse((args[-1] / 'release.json').exists())

    def test_configuration_change_during_staging_refuses_and_never_exports_secret_bytes(self):
        args = self.inputs()
        secret = args[4]['rpc.key']
        original = RELEASE.create_file
        changed = False
        def create(parent, leaf):
            nonlocal changed
            if not changed:
                changed = True
                secret.write_bytes(b'private-synthetic-changed-secret\n')
            return original(parent, leaf)
        with patch.object(RELEASE, 'create_file', side_effect=create):
            with self.assertRaisesRegex(ValueError, 'changed since admission'):
                RELEASE.stage(*args)
        self.assertFalse((args[-1] / 'release.json').exists())
        for path in args[-1].rglob('*'):
            if path.is_file():
                self.assertNotIn(b'private-synthetic-changed-secret', path.read_bytes())

    def test_verify_requires_pinned_hash_complete_membership_modes_and_payload_bytes(self):
        args = self.inputs()
        staged = RELEASE.stage(*args)
        digest = staged['declaration']['manifest_sha256']
        before = self.snapshot()
        result = RELEASE.verify(*args[:3], digest, args[-1])
        self.assertEqual(result['files'], 16)
        self.assertFalse(result['installed_ownership_admitted'])
        self.assertEqual(self.snapshot(), before)
        with self.assertRaisesRegex(ValueError, 'digest'):
            RELEASE.verify(*args[:3], '0' * 64, args[-1])
        extra = args[-1] / 'extra'; extra.write_bytes(b'unlisted')
        with self.assertRaisesRegex(ValueError, 'membership'):
            RELEASE.verify(*args[:3], digest, args[-1])
        extra.unlink()
        target = args[-1] / 'gateway' / 'System.Private.CoreLib.dll'
        target.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'mode'):
            RELEASE.verify(*args[:3], digest, args[-1])
        target.chmod(0o644); target.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'commitment'):
            RELEASE.verify(*args[:3], digest, args[-1])

    def test_verify_cli_and_late_output_membership_change_refuse_without_success(self):
        args = self.inputs()
        staged = RELEASE.stage(*args)
        command = [sys.executable, '-B', str(ROOT / 'Bootstrap/release.py'), '--app', args[0],
                   '--commit', args[1], '--tree', args[2], '--verify', str(args[-1]),
                   '--manifest-sha256', staged['declaration']['manifest_sha256']]
        before = self.snapshot()
        child = subprocess.run(command, capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout)['files'], 16)
        self.assertEqual(self.snapshot(), before)
        args = (*args[:-1], self.root / 'late-membership')
        original = RELEASE.inspect_release
        def inspect(root, *rest):
            fd = RELEASE.create_file(root, 'unlisted')
            os.close(fd)
            return original(root, *rest)
        with patch.object(RELEASE, 'inspect_release', side_effect=inspect):
            with self.assertRaisesRegex(ValueError, 'membership'):
                RELEASE.stage(*args)

"""Run only the maintained metadata helper; compiler outputs stay inert inputs."""

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile
from unittest.mock import patch

import test_deployment_releases as fixture


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_managed_imports', ROOT / 'Bootstrap/managed_imports.py')
IMPORTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(IMPORTS)
CAPTURES = []


class ManagedImportTests(fixture.ReleaseFixture):
    @classmethod
    def setUpClass(cls):
        cls.material = tempfile.TemporaryDirectory(dir=Path.home() / '.cache')
        cls.addClassCleanup(cls.material.cleanup)
        folder = Path(cls.material.name); folder.chmod(0o700)
        environment = {**IMPORTS.ENVIRONMENT, 'DOTNET_CLI_HOME': str(folder),
                       'DOTNET_SKIP_FIRST_TIME_EXPERIENCE': '1', 'DOTNET_NOLOGO': '1',
                       'MSBUILDDISABLENODEREUSE': '1', 'DOTNET_CLI_WORKLOAD_UPDATE_NOTIFY_DISABLE': 'true',
                       'NUGET_PACKAGES': os.environ.get('NUGET_PACKAGES', str(folder / 'packages'))}
        cls.build_environment = environment
        records = []

        def run(command):
            child = subprocess.run(command, capture_output=True, timeout=120, env=environment, cwd=folder)
            records.append({'command': command, 'actual_returncode': child.returncode,
                            'stdout': child.stdout.decode('utf-8'), 'stderr': child.stderr.decode('utf-8')})
            if child.returncode:
                raise AssertionError('Owned managed helper/fixture compilation failed: ' + child.stdout.decode() + child.stderr.decode())

        selected = os.environ.get('S4_MANAGED_IMPORTS_TEST_BUILD')
        if selected is None:
            run([IMPORTS.DOTNET, 'build', str(ROOT / 'ManagedImports/ManagedImports.csproj'),
                 '--configuration', 'Release', '--artifacts-path', str(folder / 'build'), '--disable-build-servers',
                 '--nologo', '-p:RestoreConfigFile=' + str(ROOT / 'ManagedImports/NuGet.Config'), '-p:NuGetAudit=false'])
            build = folder / 'build/bin/ManagedImports/release'
        else:
            build = Path(selected)
        cls.helper_bytes = {leaf: (build / leaf).read_bytes() for leaf in IMPORTS.HELPER_FILES}
        source = '''using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
public static class InertImports
{
    [DllImport("model-native-first", EntryPoint="model_first", ExactSpelling=true, CallingConvention=CallingConvention.Cdecl)]
    public static extern int First();
    [DllImport("model-native-last", EntryPoint="model_last", CharSet=CharSet.Unicode, SetLastError=true)]
    public static extern int Last(int value);
    [ModuleInitializer]
    internal static void NeverExecute() => throw new InvalidOperationException("This fixture must remain metadata only.");
}
'''
        (folder / 'InertImports.cs').write_text(source)
        sdk = sorted(Path('/usr/share/dotnet/sdk').glob('10.*/Roslyn/bincore/csc.dll'))
        references = sorted(Path('/usr/share/dotnet/packs/Microsoft.NETCore.App.Ref').glob('10.*/ref/net10.0'))
        if not sdk or not references:
            raise AssertionError('Installed .NET10 compiler/reference DATA required')
        command = [IMPORTS.DOTNET, str(sdk[-1]), '-noconfig', '-nostdlib+', '-target:library',
                   '-nullable:enable', '-warnaserror+', '-nologo', '-out:' + str(folder / 'InertImports.dll')]
        command += ['-reference:' + str(path) for path in sorted(references[-1].glob('*.dll'))]
        run([*command, str(folder / 'InertImports.cs')])
        cls.assembly = (folder / 'InertImports.dll').read_bytes()
        cls.dotnet_pin = hashlib.sha256(Path(IMPORTS.DOTNET).read_bytes()).hexdigest()
        CAPTURES.append({'scope': 'OWNED HELPER/INERT FIXTURE COMPILER INPUTS; INPUT MODULE INITIALIZER NEVER EXECUTED',
                         'source': source, 'records': records, 'helper_reused_from': selected,
                         'assembly_hex': cls.assembly.hex(),
                         'helper_files': {name: {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                                          for name, raw in cls.helper_bytes.items()}})

    def setUp(self):
        super().setUp(); self.app = 'mk8.sava'
        for row in tuple(self.documents[self.app]['files']):
            if row['path'].endswith('.dll'):
                raw = self.helper_bytes['S4.ManagedImports.dll'] if row['path'].endswith('System.Private.CoreLib.dll') else self.assembly
                self.replace_file(row['path'], raw, self.app)
        self.helper = self.root / 'helper'; self.helper.mkdir(mode=0o700)
        for name, raw in self.helper_bytes.items():
            path = self.helper / name; path.write_bytes(raw); path.chmod(0o400)
        manifest = {'schema': 1, 'files': [{'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
                                          for name, raw in self.helper_bytes.items()]}
        raw = fixture.encoded(manifest); path = self.helper / 'helper.json'; path.write_bytes(raw); path.chmod(0o400)
        self.helper_pin = hashlib.sha256(raw).hexdigest()

    def arguments(self):
        return dict(app=self.app, **self.value['releases'][self.app], release=self.folder(self.app),
                    helper=self.helper, helper_sha256=self.helper_pin, dotnet_sha256=self.dotnet_pin,
                    trusted_build_outputs=True)

    def helper_call(self, raw):
        return subprocess.run([IMPORTS.DOTNET, 'exec', str(self.helper / 'S4.ManagedImports.dll')],
                              input=raw, capture_output=True, timeout=10, env=IMPORTS.ENVIRONMENT)

    def test_complete_cli_binds_all_paths_deduplicates_exact_images_and_never_calls_imports(self):
        before = self.snapshot(); arguments = self.arguments(); arguments.pop('trusted_build_outputs')
        command = [sys.executable, '-I', '-B', str(ROOT / 'Bootstrap/managed_imports.py'), '--trusted-build-outputs']
        for key, value in arguments.items(): command.extend(('--' + key.replace('_', '-'), str(value)))
        child = subprocess.run(command, capture_output=True, timeout=45)
        self.assertEqual((child.returncode, child.stderr), (0, b''), child.stderr)
        result = json.loads(child.stdout)
        self.assertEqual(len(result['files']), 4); self.assertEqual(len(result['metadata']['images']), 2)
        found = next(row for row in result['metadata']['images'] if row['assembly_name'] == 'InertImports')
        self.assertEqual(found['implmap_rows'], 2)
        self.assertEqual([(row['module'], row['entry_point']) for row in found['imports']],
                         [('model-native-first', 'model_first'), ('model-native-last', 'model_last')])
        self.assertTrue(all(row['signature_bytes'] > 0 for row in found['imports']))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertTrue(all(value is False for value in result['metadata']['authority'].values()))
        self.assertEqual(self.snapshot(), before)
        CAPTURES.append({'method': self._testMethodName, 'actual_returncode': child.returncode,
                         'stdout_hex': child.stdout.hex(), 'stderr_hex': child.stderr.hex()})

    def test_complete_batch_refuses_late_digest_ordinal_trailing_truncated_and_nonmetadata_bytes(self):
        good = IMPORTS.frame([self.assembly, self.assembly]); second = 12 + 44 + len(self.assembly)
        bad_hash = bytearray(good); bad_hash[second + 12] ^= 1
        bad_ordinal = bytearray(good); struct.pack_into('<I', bad_ordinal, second, 0)
        bad_size = bytearray(good); struct.pack_into('<Q', bad_size, second + 4, IMPORTS.IMAGE_LIMIT + 1)
        records = []
        for raw in (b'X' + good[1:], good + b'\0', good[:-1], bytes(bad_hash), bytes(bad_ordinal),
                    bytes(bad_size), IMPORTS.frame([self.assembly, b'MZ' + b'\0' * 62])):
            with self.subTest(digest=hashlib.sha256(raw).hexdigest()):
                child = self.helper_call(raw)
                self.assertEqual((child.returncode, child.stdout, child.stderr),
                                 (75, b'', b'Managed import inspection refused\n'))
                records.append({'input_sha256': hashlib.sha256(raw).hexdigest(), 'input_hex': raw.hex(),
                                'actual_returncode': child.returncode, 'stdout_hex': child.stdout.hex(),
                                'stderr_hex': child.stderr.hex()})
        CAPTURES.append({'method': self._testMethodName, 'refusals': records})

    def test_missing_trust_bad_pins_late_release_and_helper_membership_refuse_before_runtime(self):
        before = self.snapshot()
        for change in ({'trusted_build_outputs': False}, {'trusted_build_outputs': 1},
                       {'helper_sha256': '0' * 64}, {'manifest_sha256': '0' * 64}):
            with self.subTest(change=change), patch.object(IMPORTS.NATIVE, 'PinnedExecutable') as runtime:
                with self.assertRaises(ValueError): IMPORTS.audit(**(self.arguments() | change))
                runtime.assert_not_called()
        extra = self.helper / 'unexpected.dll'; extra.write_bytes(b'foreign'); extra.chmod(0o400)
        with patch.object(IMPORTS.NATIVE, 'PinnedExecutable') as runtime:
            with self.assertRaises(ValueError): IMPORTS.audit(**self.arguments())
            runtime.assert_not_called()
        extra.unlink(); self.assertEqual(self.snapshot(), before)
        last = self.folder(self.app) / 'gateway/System.Private.CoreLib.dll'; last.write_bytes(b'changed')
        with patch.object(IMPORTS.NATIVE, 'PinnedExecutable') as runtime:
            with self.assertRaises(ValueError): IMPORTS.audit(**self.arguments())
            runtime.assert_not_called()

    def test_helper_and_release_changes_after_child_success_withhold_the_receipt(self):
        original_run = IMPORTS.NATIVE.PinnedExecutable.run
        for target in (self.helper / 'S4.ManagedImports.dll', self.folder(self.app) / 'gateway/System.Private.CoreLib.dll'):
            original = target.read_bytes(); mode = target.stat().st_mode & 0o777
            def changed(tool, *args, **kwargs):
                result = original_run(tool, *args, **kwargs)
                target.chmod(0o600); target.write_bytes(original + b'changed'); target.chmod(mode)
                return result
            with self.subTest(target=target.name), patch.object(IMPORTS.NATIVE.PinnedExecutable, 'run', changed):
                with self.assertRaises(ValueError): IMPORTS.audit(**self.arguments())
            target.chmod(0o600); target.write_bytes(original); target.chmod(mode)

    def test_faulty_helper_response_cannot_hide_late_rows_or_gain_runtime_authority(self):
        child = self.helper_call(IMPORTS.frame([self.assembly])); self.assertEqual(child.returncode, 0, child.stderr)
        original = json.loads(child.stdout); contract = IMPORTS.RELEASE.contracts()
        self.assertEqual(IMPORTS.admit_result(child.stdout, [self.assembly], contract), original)
        for fault in ('missing-image', 'pin', 'boolean-ordinal', 'authority', 'late-module', 'late-token', 'late-flags', 'count'):
            bad = copy.deepcopy(original); row = bad['images'][0]
            if fault == 'missing-image': bad['images'].clear()
            elif fault == 'pin': row['sha256'] = '0' * 64
            elif fault == 'boolean-ordinal': row['ordinal'] = False
            elif fault == 'authority': bad['authority']['native_imports_called'] = True
            elif fault == 'late-module': row['imports'][-1]['module'] = 'unlisted'
            elif fault == 'late-token': row['imports'][-1]['method_token'] = row['imports'][0]['method_token']
            elif fault == 'late-flags': row['imports'][-1]['mapping_flags'] |= 0x8000
            else: row['implmap_rows'] += 1
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                IMPORTS.admit_result(fixture.encoded(bad), [self.assembly], contract)

    def test_actual_analyzer_rejects_loading_process_and_filesystem_apis_without_running_them(self):
        project = self.root / 'analyzer-model'; project.mkdir(mode=0o700)
        for name in ('.editorconfig', 'ManagedImports.csproj', 'NuGet.Config', 'Program.cs', 'BannedSymbols.txt', 'packages.lock.json'):
            (project / name).write_bytes((ROOT / 'ManagedImports' / name).read_bytes())
        types = ('System.Reflection.Assembly', 'System.Runtime.Loader.AssemblyLoadContext',
                 'System.Reflection.Emit.AssemblyBuilder', 'System.Runtime.InteropServices.NativeLibrary',
                 'System.Diagnostics.Process', 'System.IO.File', 'System.IO.Directory', 'System.IO.FileStream')
        source = 'namespace S4.ManagedImports;\ninternal static class ForbiddenProbe\n{\n    internal static System.Type[] Types() => [\n'
        source += ',\n'.join('        typeof(' + name + ')' for name in types) + '\n    ];\n}\n'
        (project / 'ForbiddenProbe.cs').write_text(source)
        command = [IMPORTS.DOTNET, 'build', str(project / 'ManagedImports.csproj'), '--configuration', 'Release',
                   '--artifacts-path', str(project / 'build'), '--disable-build-servers', '--nologo',
                   '-p:RestoreConfigFile=' + str(project / 'NuGet.Config'), '-p:NuGetAudit=false']
        child = subprocess.run(command, capture_output=True, timeout=120, env=self.build_environment)
        self.assertEqual(child.returncode, 1, child.stdout + child.stderr)
        self.assertIn(b'Build FAILED.', child.stdout); self.assertNotIn(b'Build succeeded.', child.stdout)
        diagnostics = {line for line in child.stdout.decode().splitlines() if 'error RS0030:' in line}
        self.assertEqual(len(diagnostics), 8, child.stdout.decode())
        self.assertEqual({int(re.search(r'ForbiddenProbe.cs\((\d+),', line)[1]) for line in diagnostics}, set(range(5, 13)))
        self.assertNotIn(b'AD0001', child.stdout + child.stderr)
        CAPTURES.append({'method': self._testMethodName, 'scope': 'EXPECTED FAILED COMPILATION OF INERT OWNED BANNED-API SOURCE',
                         'source': source, 'command': command, 'actual_returncode': child.returncode,
                         'stdout_hex': child.stdout.hex(), 'stderr_hex': child.stderr.hex(), 'unique_banned_api_errors': 8})

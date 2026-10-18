"""Actual local unit parsing in a private fixture; never a running manager."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

import test_deployment_releases as fixture


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('private_unit_preflight', ROOT/'Bootstrap/unit_preflight.py')
UNIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UNIT)


class UnitPreflightTests(fixture.ReleaseFixture):
    def setUp(self):
        super().setUp()
        self.work = tempfile.TemporaryDirectory(dir=Path.home()/'.cache')
        self.addCleanup(self.work.cleanup)
        self.work_parent = Path(self.work.name); self.work_parent.chmod(0o700)
        self.pin = hashlib.sha256(Path(UNIT.PARSER).read_bytes()).hexdigest()

    def audit(self):
        return UNIT.audit(self.root, '/manifest.json', self.work_parent, self.pin)

    def test_complete_exact_units_parse_without_app_execution_or_original_writes(self):
        before = self.snapshot(); result = self.audit()
        self.assertEqual(len(result['units']), 9)
        self.assertTrue(all(result['checks'].values()))
        self.assertTrue(all(value is False for value in result['authority'].values()))
        self.assertEqual([row['actual_returncode'] for row in result['parser']['commands']], [0, 0])
        command = result['parser']['commands'][-1]
        self.assertEqual((command['stdout_bytes'], command['stderr_bytes']), (0, 0))
        self.assertIn('--recursive-errors=no', command['arguments'])
        self.assertIn('--generators=no', command['arguments'])
        self.assertIn('--man=no', command['arguments'])
        for row in result['units']:
            parsed = result['fixture']['files']['etc/systemd/system/' + row['file'].split('/')[-1]]
            self.assertEqual((parsed['bytes'], parsed['sha256']), (row['bytes'], row['sha256']))
        for name in result['placeholder_executables']:
            self.assertEqual(result['fixture']['files'][name[1:]]['sha256'], hashlib.sha256(UNIT.PLACEHOLDER).hexdigest())
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(list(self.work_parent.iterdir()), [])
        self.assertFalse((self.root/'var').exists())

    def test_faulty_producer_unknown_directive_is_rejected_by_actual_native_parser(self):
        original = UNIT.PREFLIGHT.preflight(self.root, '/manifest.json', include_candidate=True)
        broken = copy.deepcopy(original); row = broken['candidate']['files'][-1]
        row['content'] = row['content'].replace('[Service]\n', '[Service]\nDefinitelyUnknownDirective=yes\n')
        raw = row['content'].encode('ascii'); row['bytes']=len(raw); row['sha256']=hashlib.sha256(raw).hexdigest()
        before = self.snapshot()
        with patch.object(UNIT.PREFLIGHT, 'preflight', return_value=broken):
            with self.assertRaises(UNIT.ParserRefusal) as caught: self.audit()
        self.assertNotEqual(caught.exception.commands[-1]['actual_returncode'], 0)
        self.assertIn(b'DefinitelyUnknownDirective', caught.exception.stderr)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(list(self.work_parent.iterdir()), [])

    def test_unbound_bytes_arbitrary_commands_pin_or_work_root_refuse_before_verification(self):
        original = UNIT.PREFLIGHT.preflight(self.root, '/manifest.json', include_candidate=True)
        for problem in ('bytes', 'executable', 'filename'):
            broken=copy.deepcopy(original); row=broken['candidate']['files'][-1]
            if problem == 'bytes': row['sha256']='0'*64
            elif problem == 'filename': row['file']='systemd/../../outside.service'
            else:
                lines=row['content'].splitlines(True)
                row['content']=''.join('ExecStart=/bin/foreign\n' if line.startswith('ExecStart=') else line for line in lines)
                raw=row['content'].encode('ascii'); row['bytes']=len(raw); row['sha256']=hashlib.sha256(raw).hexdigest()
            with self.subTest(problem=problem), patch.object(UNIT.PREFLIGHT,'preflight',return_value=broken), \
                    patch.object(UNIT.NATIVE,'PinnedExecutable',side_effect=AssertionError('early native call')) as native:
                with self.assertRaises(ValueError): self.audit()
                native.assert_not_called()
            self.assertEqual(list(self.work_parent.iterdir()), [])
        self.pin='0'*64
        with self.assertRaisesRegex(ValueError,'pin mismatch'): self.audit()
        self.assertEqual(list(self.work_parent.iterdir()), [])
        with self.assertRaisesRegex(ValueError,'outside'): UNIT.audit(self.root,'/manifest.json',self.root,self.pin)
        self.work_parent.chmod(0o755)
        with self.assertRaisesRegex(ValueError,'0700'): self.audit()
        self.work_parent.chmod(0o700)

    def test_fixed_generator_paths_and_changed_original_plan_are_not_adopted(self):
        original=UNIT.NATIVE.PinnedExecutable.run; calls=[]
        def observed(native,arguments,*args,**kwargs):
            env=native.environment
            self.assertEqual(env['SYSTEMD_GENERATOR_PATH'],env['SYSTEMD_ENVIRONMENT_GENERATOR_PATH'])
            empty=Path(env['SYSTEMD_GENERATOR_PATH']); self.assertEqual(list(empty.iterdir()),[])
            self.assertTrue(empty.is_relative_to(self.work_parent))
            self.assertEqual(env['SYSTEMD_UNIT_PATH'],'/etc/systemd/system')
            self.assertEqual(env['SYSTEMD_LOG_TARGET'],'console')
            self.assertNotIn('LD_PRELOAD',env); self.assertNotIn('DBUS_SYSTEM_BUS_ADDRESS',env)
            result=original(native,arguments,*args,**kwargs); calls.append(arguments)
            if 'verify' in arguments:
                path=self.root/'etc/mk8.email/worker/messaging-key.txt'
                path.write_bytes(path.read_bytes()+b'\n')
            return result
        with patch.object(UNIT.NATIVE.PinnedExecutable,'run',observed):
            with self.assertRaisesRegex(ValueError,'plan changed'): self.audit()
        self.assertEqual(len(calls),2)
        self.assertEqual(list(self.work_parent.iterdir()),[])

    def test_cli_private_check_returns_receipt_and_early_refusal_has_empty_stdout(self):
        before=self.snapshot()
        args=[sys.executable,'-I','-B',str(ROOT/'Bootstrap/unit_preflight.py'), '--root',str(self.root),
              '--manifest','/manifest.json','--work-parent',str(self.work_parent),'--parser-sha256',self.pin]
        child=subprocess.run(args,capture_output=True,timeout=30)
        self.assertEqual(child.returncode,0,child.stderr)
        self.assertEqual(len(json.loads(child.stdout)['units']),9)
        self.assertEqual(self.snapshot(),before)
        self.assertEqual(list(self.work_parent.iterdir()),[])
        child=subprocess.run([*args[:-1],'0'*64],capture_output=True,timeout=30)
        self.assertEqual((child.returncode,child.stdout,child.stderr),(75,b'',b'Private unit syntax check refused\n'))
        self.assertEqual(self.snapshot(),before)
        self.assertEqual(list(self.work_parent.iterdir()),[])

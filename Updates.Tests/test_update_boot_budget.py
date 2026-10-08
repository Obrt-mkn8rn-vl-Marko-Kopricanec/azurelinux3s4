import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

import test_update_capacity as capacity
import test_update_compatibility as compatibility


ROOT=Path(__file__).resolve().parents[1]

# Existing capacity observer model plus an independently tight boot volume.
# Traversal/directory/link objects are real; proc/mount/device/statvfs delivery
# remains a MODEL, not a mount operation or installed-root storage proof.
BOOT_FIXTURE=capacity.OBSERVATION_FIXTURE
BOOT_FIXTURE=BOOT_FIXTURE.replace("    if _configuration.get('separate_mount') or _configuration.get('bind_alias'):\n",
    "    if _configuration.get('separate_boot') and str(path).startswith(str(_filesystem / 'boot')):\n        return 3\n    if _configuration.get('separate_mount') or _configuration.get('bind_alias'):\n",1)
BOOT_FIXTURE=BOOT_FIXTURE.replace("    if number == 2 and not _configuration.get('bind_alias') or owner:","    if number == 3 or number == 2 and not _configuration.get('bind_alias') or owner:")
BOOT_FIXTURE=BOOT_FIXTURE.replace("        if number == 2 and not _configuration.get('bind_alias'):\n            fields['st_dev'] = _device + 1",
    "        if number == 3 or number == 2 and not _configuration.get('bind_alias'):\n            fields['st_dev'] = _device + (2 if number == 3 else 1)")
BOOT_FIXTURE=BOOT_FIXTURE.replace("    if _configuration.get('changed_mount') and _mount_reads > 1:",
    "    if _configuration.get('separate_boot'):\n        device = _device + 2\n        lines += [f'3 1 {os.major(device)}:{os.minor(device)} / /boot rw - ext4 /dev/fixture3 rw']\n    if _configuration.get('changed_mount') and _mount_reads > 1:")
BOOT_FIXTURE=BOOT_FIXTURE.replace("    if _configuration.get('usr_low_space') and _which(_physical(fd)) == 2:",
    "    if _configuration.get('boot_low_space') and _which(_physical(fd)) == 3:\n        free = 0\n    if _configuration.get('boot_available_bytes') is not None and _which(_physical(fd)) == 3:\n        free = _configuration['boot_available_bytes']\n    if _configuration.get('usr_low_space') and _which(_physical(fd)) == 2:")


class BootWorkBudgetTests(unittest.TestCase):
    configure=capacity.PayloadCapacityTests.configure
    inventory=capacity.PayloadCapacityTests.inventory
    entry=staticmethod(capacity.PayloadCapacityTests.entry)
    run_guard=capacity.PayloadCapacityTests.run_guard

    def setUp(self):
        capacity.PayloadCapacityTests.setUp(self)
        source=self.program.read_text()
        assert source.count(capacity.OBSERVATION_FIXTURE)==1
        self.program.write_text(source.replace(capacity.OBSERVATION_FIXTURE,BOOT_FIXTURE))
        self.boot=self.root/'filesystem/boot';self.boot.mkdir(mode=0o700)
        self.inventory([self.entry('/boot/vmlinuz-3-1',1024**2,stat.S_IFREG|0o600)])

    def budget(self):
        return self.run_guard()['capacity_observation']['boot_work_budget']

    def test_supplemental_bytes_inodes_and_policy_bind_declared_image_and_observed_directory(self):
        result=self.run_guard();budget=result['capacity_observation']['boot_work_budget']
        self.assertEqual(budget['minimum_work_bytes'],132*1024**2)
        self.assertEqual(budget['minimum_work_inodes'],8)
        self.assertTrue(budget['boot_directory_observed'])
        self.assertGreater(budget['charged_bytes'],budget['minimum_work_bytes'])
        self.assertEqual(budget['filesystem_device'],result['capacity_observation']['filesystems'][0]['device'])
        self.assertFalse(budget['generated_image_size_bounded']);self.assertFalse(result['storage_capacity_checked'])

    def test_separate_boot_volume_gets_work_charge_without_root_credit(self):
        self.configure(separate_boot=True);result=self.run_guard()
        budget=result['capacity_observation']['boot_work_budget']
        volumes=result['capacity_observation']['filesystems']
        self.assertEqual(len(volumes),2)
        boot=next(v for v in volumes if v['device']==budget['filesystem_device'])
        root=next(v for v in volumes if v['device']!=budget['filesystem_device'])
        self.assertEqual(boot['mount_ids'],[3]);self.assertGreater(boot['required_bytes'],budget['charged_bytes'])
        self.assertLess(root['required_bytes'],budget['charged_bytes'])

    def test_roomy_root_cannot_hide_independently_full_boot_volume(self):
        self.configure(separate_boot=True,boot_low_space=True)
        result=self.run_guard(expected=75);self.assertIn('free blocks/inodes',result.stderr)

    def test_room_for_payload_alone_does_not_pass_work_allowance(self):
        self.configure(separate_boot=True,boot_available_bytes=450*1024**2)
        result=self.run_guard(expected=75);self.assertIn('free blocks/inodes',result.stderr)
        self.configure(separate_boot=True,boot_available_bytes=1024**3);self.run_guard()

    def test_rounding_uses_observed_allocation_units(self):
        self.inventory([self.entry('/boot/vmlinuz-3-1',123,stat.S_IFREG|0o600)])
        self.configure(block_size=65536,fragment_size=4096)
        budget=self.budget();minimum=128*1024**2+4*123
        self.assertEqual(budget['charged_bytes'],((minimum+65535)//65536)*65536+2*65536*8)

    def test_multiple_named_images_add_work_without_credit_for_existing_or_removed_objects(self):
        self.inventory([self.entry('/boot/vmlinuz-3-1',1024),self.entry('/boot/vmlinuz-4-1',2048)],removals=['old-kernel'])
        budget=self.budget();self.assertEqual(budget['minimum_work_bytes'],256*1024**2+4*3072)
        self.assertEqual(budget['minimum_work_inodes'],16)

    def test_duplicate_shared_image_is_once_at_largest_size_but_payload_remains_gross(self):
        self.inventory([self.entry('/boot/vmlinuz-3-1',4096)],packages=2)
        budget=self.budget();self.assertEqual(len(budget['images']),1)
        self.assertEqual(budget['minimum_work_bytes'],128*1024**2+4*4096)

    def test_ghost_unrelated_and_empty_batches_have_no_boot_observation_or_work_claim(self):
        for entries in ([self.entry('/boot/vmlinuz-3-1',0,flags=64)],[self.entry('/usr/bin/vmlinuz-3-1')],[]):
            with self.subTest(entries=entries):
                self.inventory(entries,packages=bool(entries));budget=self.budget()
                self.assertEqual(budget['images'],[]);self.assertEqual(budget['charged_bytes'],0)
                self.assertFalse(budget['boot_directory_observed'])

    def test_named_empty_link_and_directory_images_refuse_instead_of_getting_allowance(self):
        for item in (self.entry('/boot/vmlinuz-3-1',0),
                     self.entry('/boot/vmlinuz-3-1',1,stat.S_IFLNK|0o777,link='other'),
                     self.entry('/boot/vmlinuz-3-1',1,stat.S_IFDIR|0o700)):
            self.inventory([item]);result=self.run_guard(expected=75)
            self.assertIn('boot-work image declaration',result.stderr)

    def test_missing_boot_directory_is_not_certified_as_a_future_root_allocation(self):
        self.boot.rmdir();result=self.run_guard(expected=75)
        self.assertIn('boot-work destination directory is missing',result.stderr)
        self.assertFalse(self.boot.exists())

    def test_boot_fifo_socket_and_operator_file_are_preserved_and_refused(self):
        self.boot.rmdir()
        for kind in ('fifo','socket','regular'):
            sock=None
            if kind=='fifo':os.mkfifo(self.boot,0o600)
            elif kind=='socket':sock=__import__('socket').socket(__import__('socket').AF_UNIX);sock.bind(str(self.boot))
            else:self.boot.write_bytes(b'operator');self.boot.chmod(0o600)
            before=self.boot.lstat();self.run_guard(expected=75);self.assertEqual(self.boot.lstat(),before)
            if kind=='regular':self.assertEqual(self.boot.read_bytes(),b'operator')
            if sock:sock.close()
            self.boot.unlink()

    def test_protected_boot_alias_is_observed_and_runtime_alias_refuses(self):
        self.boot.rename(self.root/'filesystem/boot-target');self.boot.symlink_to('boot-target')
        identity=lambda value:tuple(getattr(value,key) for key in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_mtime_ns','st_ctime_ns'))
        before=identity(self.boot.lstat());self.run_guard();self.assertEqual(identity(self.boot.lstat()),before)
        self.boot.unlink();self.boot.symlink_to('/tmp');before=identity(self.boot.lstat())
        self.run_guard(expected=75);self.assertEqual(identity(self.boot.lstat()),before)

    def test_writable_boot_parent_readonly_mount_changed_mount_and_falling_space_refuse(self):
        self.boot.chmod(0o777);self.run_guard(expected=75);self.boot.chmod(0o700)
        for values in ({'readonly':True},{'changed_mount':True},{'falling_space':True}):
            with self.subTest(values=values):self.configure(**values);self.run_guard(expected=75)

    def test_complete_source_declarations_digest_is_preserved(self):
        entries=[self.entry('/boot/vmlinuz-3-1',1024**2,stat.S_IFREG|0o600)]
        data=json.dumps(entries,sort_keys=True,separators=(',',':')).encode()
        self.assertEqual(self.budget()['source_sha256'],hashlib.sha256(data).hexdigest())

    def test_image_bound_refuses_without_partial_forecast(self):
        self.inventory([self.entry(f'/boot/vmlinuz-{i}-1',1) for i in range(129)])
        result=self.run_guard(expected=75);self.assertIn('image count exceeds',result.stderr)

    def test_all_nine_new_authority_flags_remain_false(self):
        budget=self.budget()
        for key in ('kernel_owner_authenticated','all_regeneration_triggers_accounted','generated_image_size_bounded',
                    'space_reserved','complete_boot_capacity_checked','rollback_capacity_checked',
                    'installation_authorized','reboot_authorized','server_ready'):
            self.assertIs(budget[key],False)


BOOT_LIBRARY=capacity.CAPACITY_LIBRARY.replace('const char *rpmfiFN(', 'const char *oldBootFilename(')
BOOT_LIBRARY+=r'''
const char *rpmfiFN(FI *fi) { return fi->index?"/usr/share/fixture-link":"/boot/vmlinuz-3-1"; }
'''


class BootWorkPipelineTests(unittest.TestCase):
    temporary_parent=compatibility.admission.protected_model_parent()
    command=capacity.UpdateCapacityIntegrationTests.command
    configure=capacity.UpdateCapacityIntegrationTests.configure
    calls=capacity.UpdateCapacityIntegrationTests.calls
    header=capacity.UpdateCapacityIntegrationTests.header
    prepare=capacity.UpdateCapacityIntegrationTests.prepare
    native_calls=capacity.UpdateCapacityIntegrationTests.native_calls
    def shell(self,body='s4_check_update_capacity',expected=0,timeout=90):
        return capacity.UpdateCapacityIntegrationTests.shell(self,body,expected,timeout)

    @classmethod
    def setUpClass(cls):
        temporary=tempfile.TemporaryDirectory(prefix='s4-boot-budget-abi-',dir=Path.home()/'.cache')
        cls.addClassCleanup(temporary.cleanup);cls.library=Path(temporary.name)/'librpm-boot-budget-model.so'
        subprocess.run(['cc','-shared','-fPIC','-x','c','-','-o',str(cls.library)],input=BOOT_LIBRARY,
                       text=True,capture_output=True,check=True)

    def setUp(self):
        capacity.UpdateCapacityIntegrationTests.setUp(self)
        (self.root/'filesystem/boot').mkdir(mode=0o700)
        self.configuration_fixture.write_text(BOOT_FIXTURE)

    def test_current_capacity_forecast_binds_same_snapshots_and_separate_boot_volume(self):
        self.prepare(separate_boot=True);pointer=(self.root/'state/updates/current.json').read_bytes()
        proof=json.loads(self.shell().stdout);budget=proof['capacity_observation']['boot_work_budget']
        self.assertTrue(budget['boot_directory_observed']);self.assertEqual(len(budget['images']),1)
        self.assertFalse(proof['storage_capacity_checked']);self.assertFalse(budget['space_reserved'])
        self.assertEqual((self.root/'state/updates/current.json').read_bytes(),pointer)
        self.record={'proof':proof,'pointer_sha256_before':hashlib.sha256(pointer).hexdigest(),
                     'pointer_sha256_after':hashlib.sha256((self.root/'state/updates/current.json').read_bytes()).hexdigest(),
                     'ordinary_cleanup_verified':True,'real_install_mount_or_boot':False}

    def test_boot_shortage_withholds_all_json_preserves_pointer_and_stays_pending(self):
        self.prepare(separate_boot=True,boot_low_space=True);pointer=(self.root/'state/updates/current.json').read_bytes()
        result=self.shell(expected=75);self.assertEqual(result.stdout,'')
        self.assertIn('free blocks/inodes',result.stderr)
        self.assertEqual((self.root/'state/updates/current.json').read_bytes(),pointer)
        self.shell('s4_reconcile_component update-capacity yes',expected=75)
        self.assertIn('status=pending',(self.root/'state/components/update-capacity').read_text())
        self.record={'exit':75,'stdout':result.stdout,'stderr':result.stderr,
                     'pointer_sha256_before':hashlib.sha256(pointer).hexdigest(),
                     'pointer_sha256_after':hashlib.sha256((self.root/'state/updates/current.json').read_bytes()).hexdigest(),
                     'ordinary_cleanup_verified':True,'real_install_mount_or_boot':False}

    def test_new_space_observation_can_recover_without_reusing_stale_success(self):
        self.prepare(separate_boot=True);self.shell('s4_reconcile_component update-capacity yes')
        self.configure(separate_boot=True,boot_low_space=True)
        self.shell('s4_reconcile_component update-capacity yes',expected=75)
        self.assertIn('status=pending',(self.root/'state/components/update-capacity').read_text())
        self.configure(separate_boot=True);self.shell('s4_reconcile_component update-capacity yes')
        self.assertIn('status=complete',(self.root/'state/components/update-capacity').read_text())


if __name__=='__main__':unittest.main()

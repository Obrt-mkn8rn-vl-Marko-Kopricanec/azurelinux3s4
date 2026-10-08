import hashlib
import json
import os
from pathlib import Path
import socket
import stat
import unittest

import test_update_boot_budget as boot


class ExistingInitramfsTests(unittest.TestCase):
    configure = boot.BootWorkBudgetTests.configure
    inventory = boot.BootWorkBudgetTests.inventory
    entry = staticmethod(boot.BootWorkBudgetTests.entry)
    run_guard = boot.BootWorkBudgetTests.run_guard

    def setUp(self):
        boot.BootWorkBudgetTests.setUp(self)
        self.image = self.boot / 'initramfs-existing-1.img'
        self.image.write_bytes(b'opaque fixture, never decoded or read by the observer')
        self.image.chmod(0o600)

    def forecast(self):
        return self.run_guard()['capacity_observation']['existing_initramfs_work']

    def inject(self, source):
        text = self.program.read_text()
        self.assertEqual(text.count('held = []\ntry:\n'), 1)
        self.program.write_text(text.replace('held = []\ntry:\n', source + '\nheld = []\ntry:\n'))

    def change_between_scans(self, action):
        self.inject("_scan_original = initramfs_scan\n_scan_calls = 0\n"
            "def initramfs_scan(fd):\n    global _scan_calls\n    _scan_calls += 1\n"
            "    result = _scan_original(fd)\n    if _scan_calls == 1:\n" +
            ''.join('        ' + line + '\n' for line in action.splitlines()) + '    return result\n')

    def test_real_regular_metadata_is_bound_and_never_promoted_to_authentication(self):
        before = self.image.lstat(); receipt = self.forecast(); row = receipt['images'][0]
        self.assertEqual(row['path'], '/boot/initramfs-existing-1.img')
        self.assertEqual(row['logical_bytes'], before.st_size)
        self.assertEqual(row['allocated_bytes'], before.st_blocks * 512)
        self.assertEqual(row['metadata'][1], before.st_ino)
        self.assertEqual(receipt['minimum_work_bytes'], 128 * 1024**2 + 2 * max(before.st_size, before.st_blocks * 512))
        self.assertEqual(receipt['minimum_work_inodes'], 8)
        self.assertTrue(receipt['observation_performed'])
        self.assertEqual(len(receipt['observation_sha256']), 64)
        self.assertIn('no content read or trigger selection', receipt['scope'])
        for key in ('image_contents_read', 'images_authenticated', 'all_installed_kernels_accounted',
                    'regeneration_selection_complete', 'generated_image_size_bounded', 'space_reserved',
                    'complete_boot_capacity_checked', 'rollback_capacity_checked',
                    'installation_authorized', 'reboot_authorized', 'server_ready'):
            self.assertIs(receipt[key], False)
        after = self.image.lstat()
        self.assertEqual((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns),
                         (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))

    def test_sparse_logical_length_is_not_credited_as_free_work(self):
        with self.image.open('r+b') as stream: stream.truncate(16 * 1024**2)
        receipt = self.forecast(); row = receipt['images'][0]
        self.assertEqual(row['forecast_basis_bytes'], 16 * 1024**2)
        self.assertEqual(receipt['minimum_work_bytes'], 160 * 1024**2)

    def test_all_direct_supported_existing_images_are_sorted_not_just_incoming_versions(self):
        older = self.boot / 'initramfs-0.1-1.img'; older.write_bytes(b'older'); older.chmod(0o600)
        receipt = self.forecast()
        self.assertEqual([row['path'] for row in receipt['images']],
                         ['/boot/initramfs-0.1-1.img', '/boot/initramfs-existing-1.img'])
        self.assertEqual(receipt['minimum_work_inodes'], 16)

    def test_unrelated_names_and_subdirectories_are_not_claimed_as_images(self):
        (self.boot / 'unrelated').symlink_to('/does/not/exist')
        (self.boot / 'nested').mkdir(mode=0o700)
        (self.boot / 'nested/initramfs-hidden.img').write_bytes(b'unselected')
        self.assertEqual(len(self.forecast()['images']), 1)

    def test_conditional_absence_of_incoming_image_does_not_walk_boot(self):
        self.inventory([self.entry('/usr/share/file')]); self.image.unlink(); self.boot.rmdir()
        receipt = self.forecast()
        self.assertFalse(receipt['observation_performed']); self.assertIsNone(receipt['observation_sha256'])
        self.assertEqual(receipt['images'], []); self.assertEqual(receipt['charged_bytes'], 0)

    def test_checked_empty_directory_is_distinct_from_an_unperformed_scan(self):
        self.image.unlink(); receipt = self.forecast()
        self.assertTrue(receipt['observation_performed']); self.assertEqual(receipt['images'], [])
        self.assertEqual(receipt['minimum_work_bytes'], 0); self.assertEqual(receipt['charged_bytes'], 0)

    def test_symlink_dangling_link_fifo_directory_and_socket_are_preserved_and_refused(self):
        for kind in ('symlink', 'dangling', 'fifo', 'directory', 'socket'):
            with self.subTest(kind=kind):
                self.image.unlink()
                handle = None
                if kind == 'symlink': self.image.symlink_to('/bin/sh')
                elif kind == 'dangling': self.image.symlink_to('absent-referent')
                elif kind == 'fifo': os.mkfifo(self.image, 0o600)
                elif kind == 'directory': self.image.mkdir(mode=0o700)
                else:
                    handle = socket.socket(socket.AF_UNIX); handle.bind(str(self.image))
                before = self.image.lstat(); self.run_guard(expected=75); after = self.image.lstat()
                self.assertEqual((before.st_dev, before.st_ino, before.st_mode), (after.st_dev, after.st_ino, after.st_mode))
                if handle is not None: handle.close()
                if kind == 'directory': self.image.rmdir()
                else: self.image.unlink()
                self.image.write_bytes(b'fixture'); self.image.chmod(0o600)

    def test_regular_group_write_or_setid_permission_refuses_without_repair(self):
        for mode in (0o620, 0o606, 0o4600, 0o2600, 0o1600):
            with self.subTest(mode=mode):
                self.image.chmod(mode); self.run_guard(expected=75)
                self.assertEqual(stat.S_IMODE(self.image.lstat().st_mode), mode)

    def test_hardlinked_image_refuses_without_unlinking_either_name(self):
        alias = self.boot / 'operator-alias'; os.link(self.image, alias)
        self.run_guard(expected=75); self.assertEqual(self.image.lstat().st_ino, alias.lstat().st_ino)

    def test_empty_image_refuses(self):
        self.image.write_bytes(b''); self.run_guard(expected=75)

    def test_untrusted_leaf_owner_delivery_refuses(self):
        self.inject("_init_adjust = _adjust\ndef _adjust(value, path):\n"
            "    value = _init_adjust(value, path)\n    if str(path).endswith('/initramfs-existing-1.img'):\n"
            "        fields = {n:getattr(value,n) for n in dir(value) if n.startswith('st_')}\n"
            "        fields['st_uid'] = os.geteuid() + 1\n        return _fixture_types.SimpleNamespace(**fields)\n    return value\n")
        self.run_guard(expected=75)

    def test_no_follow_path_descriptor_is_the_only_selected_leaf_open(self):
        self.inject("_init_open = os.open\ndef _init_open_audit(path, flags, mode=0o777, *, dir_fd=None):\n"
            "    if str(path).startswith('initramfs-'):\n"
            "        with (_fixture/'initramfs-open.jsonl').open('a') as audit:\n"
            "            audit.write(json.dumps({'flags':flags,'path':str(path)})+'\\n')\n"
            "    return _init_open(path, flags, mode, dir_fd=dir_fd)\nos.open = _init_open_audit\n")
        self.forecast(); rows = [json.loads(line) for line in (self.root/'initramfs-open.jsonl').read_text().splitlines()]
        self.assertEqual(len(rows), 2)
        for row in rows:
            self.assertEqual(row['flags'], os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)

    def test_leaf_mount_mismatch_delivery_refuses(self):
        self.inject("_init_text = Path.read_text\ndef _init_text_read(path,*args,**kwargs):\n"
            "    if str(path).startswith('/proc/self/fdinfo/') and _physical(int(path.name)).endswith('/initramfs-existing-1.img'):\n"
            "        return 'mnt_id: 99\\n'\n    return _init_text(path,*args,**kwargs)\nPath.read_text = _init_text_read\n")
        self.assertIn('crosses a mount', self.run_guard(expected=75).stderr)

    def test_actual_leaf_replacement_before_open_refuses(self):
        self.inject("_init_open = os.open\ndef _init_open_swap(path, flags, mode=0o777, *, dir_fd=None):\n"
            "    if str(path) == 'initramfs-existing-1.img' and dir_fd is not None:\n"
            "        leaf = Path(_physical(dir_fd))/path\n        leaf.rename(leaf.with_name('saved-original'))\n"
            "        leaf.write_bytes(b'replacement');leaf.chmod(0o600)\n"
            "    return _init_open(path, flags, mode, dir_fd=dir_fd)\nos.open = _init_open_swap\n")
        self.assertIn('changed or crosses a mount', self.run_guard(expected=75).stderr)
        self.assertTrue((self.boot/'saved-original').is_file())

    def test_changed_image_length_between_complete_scans_refuses(self):
        self.change_between_scans("with (_filesystem/'boot/initramfs-existing-1.img').open('ab') as out: out.write(b'change')")
        self.assertIn('namespace changed', self.run_guard(expected=75).stderr)

    def test_new_image_between_scans_refuses(self):
        self.change_between_scans("leaf = _filesystem/'boot/initramfs-added.img'\nleaf.write_bytes(b'added');leaf.chmod(0o600)")
        self.assertIn('namespace changed', self.run_guard(expected=75).stderr)

    def test_deleted_image_between_scans_refuses(self):
        self.change_between_scans("(_filesystem/'boot/initramfs-existing-1.img').unlink()")
        self.assertIn('namespace changed', self.run_guard(expected=75).stderr)

    def test_same_size_new_inode_between_scans_refuses(self):
        self.change_between_scans("leaf = _filesystem/'boot/initramfs-existing-1.img'\nsize = leaf.stat().st_size\n"
            "leaf.rename(leaf.with_name('saved-original'))\nleaf.write_bytes(b'x'*size);leaf.chmod(0o600)")
        self.assertIn('namespace changed', self.run_guard(expected=75).stderr)

    def test_normal_leaf_close_failure_cannot_publish_json(self):
        self.inject("_init_close = os.close\ndef _init_close_fail(fd):\n"
            "    selected = _physical(fd).endswith('/initramfs-existing-1.img')\n    _init_close(fd)\n"
            "    if selected: raise OSError('initramfs ordinary close delivery failure')\nos.close = _init_close_fail\n")
        self.assertIn('ordinary close delivery failure', self.run_guard(expected=75).stderr)

    def test_non_ascii_control_and_overlong_selected_names_refuse(self):
        self.image.unlink()
        for name in ('initramfs-\u2028.img', 'initramfs-v\n1.img', 'initramfs-'+ 'x'*201 +'.img'):
            with self.subTest(name=name):
                leaf = self.boot/name; leaf.write_bytes(b'fixture'); leaf.chmod(0o600)
                self.assertIn('ASCII profile', self.run_guard(expected=75).stderr); leaf.unlink()

    def test_directory_entry_cap_applies_before_name_selection(self):
        for number in range(4096): (self.boot / f'unselected-{number}').touch(mode=0o600)
        self.assertIn('entry count exceeds', self.run_guard(expected=75).stderr)

    def test_selected_image_count_cap_refuses_partial_observation(self):
        for number in range(128):
            leaf = self.boot / f'initramfs-extra-{number}.img'; leaf.write_bytes(b'x'); leaf.chmod(0o600)
        self.assertIn('count or allocation', self.run_guard(expected=75).stderr)

    def test_per_file_logical_size_cap_refuses_sparse_overflow(self):
        with self.image.open('r+b') as out: out.truncate(2 * 1024**3 + 1)
        self.assertIn('bounded ordinary', self.run_guard(expected=75).stderr)

    def test_aggregate_logical_size_cap_refuses_sparse_overflow(self):
        self.image.unlink()
        for number in range(9):
            leaf = self.boot / f'initramfs-large-{number}.img'
            with leaf.open('wb') as out: out.truncate(2 * 1024**3)
            leaf.chmod(0o600)
        self.assertIn('count or allocation', self.run_guard(expected=75).stderr)

    def test_extra_work_is_charged_to_separate_boot_device(self):
        self.configure(separate_boot=True); result = self.run_guard(); receipt = result['capacity_observation']['existing_initramfs_work']
        volume = next(item for item in result['capacity_observation']['filesystems'] if item['mount_ids'] == [3])
        self.assertEqual(receipt['filesystem_device'], volume['device'])
        self.assertGreaterEqual(volume['required_bytes'], receipt['charged_bytes'] + result['capacity_observation']['boot_work_budget']['charged_bytes'])

    def test_roomy_root_cannot_hide_existing_image_regeneration_shortage(self):
        with self.image.open('r+b') as out: out.truncate(64 * 1024**2)
        self.configure(separate_boot=True, boot_available_bytes=600 * 1024**2)
        self.assertIn('free blocks/inodes', self.run_guard(expected=75).stderr)


class InitramfsPipelineTests(unittest.TestCase):
    temporary_parent = boot.BootWorkPipelineTests.temporary_parent
    command = boot.BootWorkPipelineTests.command
    configure = boot.BootWorkPipelineTests.configure
    calls = boot.BootWorkPipelineTests.calls
    header = boot.BootWorkPipelineTests.header
    prepare = boot.BootWorkPipelineTests.prepare
    native_calls = boot.BootWorkPipelineTests.native_calls
    shell = boot.BootWorkPipelineTests.shell
    setUpClass = classmethod(boot.BootWorkPipelineTests.setUpClass.__func__)

    def setUp(self):
        boot.BootWorkPipelineTests.setUp(self)
        self.image = self.root/'filesystem/boot/initramfs-existing-1.img'
        with self.image.open('wb') as out: out.truncate(64 * 1024**2)
        self.image.chmod(0o600)

    def test_current_same_byte_diagnostic_observes_existing_image_without_install_authority(self):
        self.prepare(separate_boot=True); pointer = (self.root/'state/updates/current.json').read_bytes()
        before = self.image.lstat(); proof = json.loads(self.shell().stdout)
        receipt = proof['capacity_observation']['existing_initramfs_work']
        self.assertTrue(receipt['observation_performed']); self.assertEqual(len(receipt['images']), 1)
        self.assertEqual(receipt['minimum_work_bytes'], 256 * 1024**2)
        self.assertFalse(proof['storage_capacity_checked']); self.assertFalse(receipt['generated_image_size_bounded'])
        self.assertFalse(proof['installation_authorized']); self.assertFalse(receipt['space_reserved'])
        self.assertEqual((self.root/'state/updates/current.json').read_bytes(), pointer)
        self.assertEqual(self.image.lstat(), before)
        self.record = {'proof':proof, 'pointer_sha256_before':hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after':hashlib.sha256((self.root/'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified':True, 'real_install_mount_or_boot':False}

    def test_existing_image_work_shortage_stays_pending_and_preserves_same_batch(self):
        self.prepare(separate_boot=True, boot_available_bytes=600 * 1024**2)
        pointer = (self.root/'state/updates/current.json').read_bytes(); result = self.shell(expected=75)
        self.assertIn('free blocks/inodes', result.stderr); self.assertEqual(result.stdout, '')
        self.assertEqual((self.root/'state/updates/current.json').read_bytes(), pointer)
        self.shell('s4_reconcile_component update-capacity yes', expected=75)
        self.assertIn('status=pending', (self.root/'state/components/update-capacity').read_text())
        self.record = {'exit':75, 'stdout':result.stdout, 'stderr':result.stderr,
            'pointer_sha256_before':hashlib.sha256(pointer).hexdigest(),
            'pointer_sha256_after':hashlib.sha256((self.root/'state/updates/current.json').read_bytes()).hexdigest(),
            'ordinary_cleanup_verified':True, 'real_install_mount_or_boot':False}


if __name__ == '__main__': unittest.main()

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

import test_update_compatibility as compatibility


SOURCE = Path(__file__).resolve().parents[1] / 'azurelinux3s4.sh'

# Mount/statvfs/proc delivery and the explicit leaf-owner/mount failure controls
# are modeled. Directory traversal and real link/regular/FIFO/socket objects,
# copy/hash/parse/budgets and the deliberate inode-swap control are actual.
OBSERVATION_FIXTURE = r'''
import types as _fixture_types
_fixture = Path(os.environ['S4_CAPACITY_FIXTURE'])
_configuration = json.loads((_fixture / 'configuration.json').read_text())
_filesystem = _fixture / 'filesystem'
_real_open, _real_stat, _real_fstat = os.open, os.stat, os.fstat
_real_readlink = os.readlink
_real_read_bytes, _real_read_text = Path.read_bytes, Path.read_text
_device = _real_stat(_filesystem).st_dev
_mount_reads, _capacity_reads = 0, 0
sys.argv[2] = '/var/lib/rpm'
def _physical(fd):
    return _real_readlink('/proc/self/fd/' + str(fd))
def _which(path):
    if not str(path).startswith(str(_filesystem) + '/') and str(path) != str(_filesystem):
        return 0
    if _configuration.get('separate_mount') or _configuration.get('bind_alias'):
        if str(path).startswith(str(_filesystem / 'usr')):
            return 2
    return 1
def _adjust(value, path):
    number = _which(path)
    owner = _configuration.get('untrusted_leaf_owner') and str(path).endswith('/payload-link')
    if number == 2 and not _configuration.get('bind_alias') or owner:
        fields = {name:getattr(value,name) for name in dir(value) if name.startswith('st_')}
        if number == 2 and not _configuration.get('bind_alias'):
            fields['st_dev'] = _device + 1
        if owner:
            fields['st_uid'] = os.geteuid() + 1
        return _fixture_types.SimpleNamespace(**fields)
    return value
def _open(path, flags, mode=0o777, *, dir_fd=None):
    if path == '/' and dir_fd is None:
        path = _filesystem
    if dir_fd is not None and path == 'payload-link':
        if _configuration.get('audit_leaf_open'):
            with (_fixture / 'leaf-open-flags.json').open('a') as audit:
                audit.write(json.dumps({'flags':flags,'name':path})+'\n')
        if _configuration.get('swap_leaf_before_open'):
            leaf = Path(_physical(dir_fd)) / path
            leaf.rename(leaf.with_name('prior-payload-link'))
            leaf.symlink_to('changed-target')
    return _real_open(path, flags, mode, dir_fd=dir_fd)
def _stat(path, *, dir_fd=None, follow_symlinks=True):
    value = _real_stat(path, dir_fd=dir_fd, follow_symlinks=follow_symlinks)
    physical = Path(_physical(dir_fd)) / path if dir_fd is not None else Path(path)
    return _adjust(value, physical)
def _fstat(fd):
    return _adjust(_real_fstat(fd), _physical(fd))
def _mount_data():
    global _mount_reads
    _mount_reads += 1
    filesystem = _configuration.get('filesystem_type','ext4')
    options = _configuration.get('mount_options','rw')
    lines = [f'1 0 {os.major(_device)}:{os.minor(_device)} / / {options} - {filesystem} /dev/fixture {options}']
    if _configuration.get('separate_mount') or _configuration.get('bind_alias'):
        device = _device if _configuration.get('bind_alias') else _device + 1
        lines += [f'2 1 {os.major(device)}:{os.minor(device)} / /usr rw - ext4 /dev/fixture2 rw']
    if _configuration.get('changed_mount') and _mount_reads > 1:
        lines[0] = lines[0].replace(' / / ', ' / /changed ')
    return ('\n'.join(lines)+'\n').encode()
def _read_bytes(path):
    if str(path) == '/proc/self/mountinfo': return _mount_data()
    return _real_read_bytes(path)
def _read_text(path,*args,**kwargs):
    if str(path).startswith('/proc/self/fdinfo/'):
        fd = int(path.name)
        if _configuration.get('leaf_mount_mismatch') and _physical(fd).endswith('/payload-link'):
            return 'mnt_id: 2\n'
        return 'mnt_id: '+str(_which(_physical(fd)))+'\n'
    return _real_read_text(path,*args,**kwargs)
def _capacity(fd):
    global _capacity_reads
    _capacity_reads += 1
    unit = _configuration.get('fragment_size',4096)
    block = _configuration.get('block_size',4096)
    total = _configuration.get('total_bytes',8*1024**3)
    free = _configuration.get('available_bytes',7*1024**3)
    if _configuration.get('usr_low_space') and _which(_physical(fd)) == 2:
        free = 0
    if _configuration.get('falling_space') and _capacity_reads > 2:
        free = 0
    if _configuration.get('change_parent') and _capacity_reads == 1:
        (_filesystem/'usr/share').rename(_filesystem/'usr/share-old')
        (_filesystem/'usr/share').mkdir(mode=0o700)
    return _fixture_types.SimpleNamespace(f_flag=os.ST_RDONLY if _configuration.get('readonly') else 0,
        f_frsize=unit,f_bsize=block,f_blocks=total//unit,f_bfree=total//unit,
        f_bavail=free//unit,f_files=_configuration.get('total_inodes',100000),
        f_ffree=100000,f_favail=_configuration.get('available_inodes',90000))
os.open, os.stat, os.fstat, os.fstatvfs = _open, _stat, _fstat, _capacity
Path.read_bytes, Path.read_text = _read_bytes, _read_text
'''


def filesystem_fixture(root):
    for name in ('filesystem','filesystem/usr','filesystem/usr/share','filesystem/usr/bin',
                 'filesystem/var','filesystem/var/lib','filesystem/var/lib/rpm'):
        path=root/name
        path.mkdir(mode=0o700,exist_ok=True)
        path.chmod(0o700)
    (root / 'filesystem/var/lib/rpm/Packages.db').write_bytes(b'installed database fixture')
    (root / 'filesystem/var/lib/rpm/Packages.db').chmod(0o600)


class PayloadCapacityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='azurelinux3s4-capacity-', dir=Path.home() / '.cache')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.workspace = self.root / 'workspace'
        self.workspace.mkdir(mode=0o700)
        filesystem_fixture(self.root)
        self.configure()
        program = subprocess.check_output(['bash','-c','source "$1"; s4_update_capacity_program','fixture',str(SOURCE)], text=True)
        self.program = self.root / 'capacity.py'
        self.program.write_text(program.replace('held = []\ntry:\n', OBSERVATION_FIXTURE + '\nheld = []\ntry:\n', 1))
        self.inventory([self.entry()])

    def configure(self, **values):
        (self.root / 'configuration.json').write_text(json.dumps(values))

    @staticmethod
    def entry(path='/usr/share/new/file', size=1234, mode=stat.S_IFREG | 0o644, flags=0, link=''):
        return {'path':path,'bytes':size,'mode':mode,'flags':flags,'link':link}

    def inventory(self, entries, packages=1, removals=None):
        artifacts = [{'file':f'packages/{index}.rpm','sha256':'a'*64,'bytes':15,
                      'header_bytes':4096,'files':entries} for index in range(packages)]
        data = json.dumps({'schema':1,'manifest_sha256':'b'*64,'artifacts':artifacts}).encode()
        proof = {'schema':1,'manifest_sha256':'b'*64,'test_passed':True,'rpm_test_performed':bool(packages),
                 'installs_performed':False,'scripts_executed':False,'installation_authorized':False,
                 'storage_capacity_checked':False,'freshness_proven':False,
                 'additions':[{k:v for k,v in item.items() if k in ('file','sha256','bytes')} for item in artifacts],
                 'removals':removals or [],'payload_inventory':{'sha256':hashlib.sha256(data).hexdigest(),
                     'bytes':len(data),'files':len(entries)*packages}}
        for name,value in (('inventory.json',data),('result.json',json.dumps(proof).encode())):
            path=self.workspace/name;path.write_bytes(value);path.chmod(0o600)

    def run_guard(self, expected=0):
        environment = dict(os.environ, S4_CAPACITY_FIXTURE=str(self.root))
        result = subprocess.run(['python3','-I',str(self.program),str(self.workspace),'/var/lib/rpm'],
                                env=environment, capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,expected,result.stderr)
        if expected: self.assertEqual(result.stdout,'')
        return json.loads(result.stdout) if not expected else result

    def test_gross_payload_and_database_budget_is_observed_without_install_permission(self):
        result=self.run_guard()
        self.assertTrue(result['payload_capacity_checked'])
        for field in ('installation_authorized','storage_capacity_checked','installs_performed','scripts_executed','freshness_proven'):
            self.assertFalse(result[field])
        scope=result['capacity_observation']
        self.assertFalse(scope['space_reserved'])
        self.assertFalse(scope['scripts_capacity_checked'])
        self.assertFalse(scope['rollback_capacity_checked'])
        self.assertFalse(scope['atomic_filesystem_snapshot'])
        volume=scope['filesystems'][0]
        self.assertGreater(volume['required_bytes'],64*1024*1024)
        self.assertGreater(volume['required_inodes'],64)
        self.assertGreaterEqual(volume['headroom_bytes'],64*1024*1024)

    def test_reserved_root_blocks_cannot_mask_low_bavail(self):
        self.configure(available_bytes=80*1024*1024)
        self.run_guard(expected=75)

    def test_inode_shortage_fails_even_with_plentiful_blocks(self):
        self.configure(available_inodes=100)
        self.run_guard(expected=75)

    def test_fragment_units_are_not_confused_with_preferred_block_size(self):
        self.configure(fragment_size=512,block_size=4096)
        result=self.run_guard()
        self.assertEqual(result['capacity_observation']['filesystems'][0]['available_bytes'],7*1024**3)

    def test_independent_destination_volume_shortage_is_not_hidden_by_root_space(self):
        self.configure(separate_mount=True,usr_low_space=True)
        self.run_guard(expected=75)

    def test_multiple_local_volumes_receive_separate_payload_and_database_budgets(self):
        self.configure(separate_mount=True)
        result=self.run_guard()['capacity_observation']['filesystems']
        self.assertEqual(len(result),2)
        self.assertTrue(all(item['required_bytes']>0 and item['required_inodes']>0 for item in result))

    def test_bind_aliases_share_one_gross_budget_and_use_lowest_availability(self):
        self.configure(bind_alias=True)
        result=self.run_guard()['capacity_observation']['filesystems']
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]['mount_ids'],[1,2])
        self.configure(bind_alias=True,usr_low_space=True)
        self.run_guard(expected=75)

    def test_removed_old_packages_and_identical_payloads_do_not_receive_space_credit(self):
        self.inventory([self.entry(size=75*1024*1024)],removals=['old-giant-package-1.x86_64'])
        self.configure(total_bytes=1024**3,available_bytes=150*1024*1024)
        self.run_guard(expected=75)
        self.inventory([self.entry(size=35*1024*1024)],packages=2)
        self.run_guard(expected=75)

    def test_readonly_unknown_cow_network_and_quota_mounts_are_not_certified(self):
        for options in ({'readonly':True},{'filesystem_type':'btrfs'},{'filesystem_type':'nfs'},
                        {'filesystem_type':'overlay'},{'mount_options':'rw,prjquota'},
                        {'mount_options':'rw,pquota'},{'mount_options':'rw,usrjquota=a,jqfmt=vfsv1'},
                        {'mount_options':'ro'}):
            with self.subTest(options=options):
                self.configure(**options);self.run_guard(expected=75)

    def test_missing_or_inconsistent_block_and_inode_geometry_remains_pending(self):
        for options in ({'total_inodes':0},{'total_bytes':0},{'block_size':0},
                        {'fragment_size':768},{'available_inodes':200000}):
            with self.subTest(options=options):
                self.configure(**options);self.run_guard(expected=75)

    def test_final_observation_uses_decreasing_availability(self):
        self.configure(falling_space=True)
        self.run_guard(expected=75)

    def test_mount_or_directory_change_during_observation_is_refused(self):
        self.configure(changed_mount=True);self.run_guard(expected=75)
        self.configure(change_parent=True);self.run_guard(expected=75)

    def test_actual_fifo_socket_file_and_untrusted_parent_are_bounded_refusals(self):
        path=self.root/'filesystem/usr/share/new'
        os.mkfifo(path,0o600);self.run_guard(expected=75);path.unlink()
        sock=socket.socket(socket.AF_UNIX);self.addCleanup(sock.close)
        sock.bind(str(path));self.run_guard(expected=75);path.unlink();sock.close()
        path.write_bytes(b'operator file');self.run_guard(expected=75);path.unlink()
        path.mkdir(mode=0o777);path.chmod(0o777);self.run_guard(expected=75)

    def test_actual_private_inventory_wrong_kind_and_link_are_never_opened(self):
        path=self.workspace/'inventory.json';data=path.read_bytes();path.unlink()
        os.mkfifo(path,0o600);self.run_guard(expected=75);path.unlink()
        target=self.workspace/'target';target.write_bytes(data);target.chmod(0o600)
        path.symlink_to(target);self.run_guard(expected=75);path.unlink()
        os.link(target,path);self.run_guard(expected=75)

    def test_checked_existing_usr_alias_is_resolved_without_following_operator_objects(self):
        (self.root/'filesystem/bin').symlink_to('usr/bin')
        self.inventory([self.entry('/bin/app')])
        self.run_guard()
        (self.root/'filesystem/bin').unlink()
        (self.root/'filesystem/bin').symlink_to('/tmp')
        self.run_guard(expected=75)

    def test_new_or_changed_batch_symlink_ancestors_are_not_assumed_safe(self):
        self.inventory([self.entry('/usr/share/new',0,stat.S_IFLNK|0o777,link='/usr/bin'),self.entry()])
        self.run_guard(expected=75)
        (self.root/'filesystem/bin').symlink_to('usr/bin')
        self.inventory([self.entry('/bin',0,stat.S_IFLNK|0o777,link='/usr/share'),self.entry('/bin/app')])
        self.run_guard(expected=75)

    def test_noncanonical_runtime_special_and_changed_kind_targets_are_refused(self):
        for entry in (self.entry('/usr/../tmp/file'),self.entry('/usr//file'),self.entry('/run/file'),
                      self.entry(mode=stat.S_IFIFO|0o600),self.entry('/usr/share/new\nfile')):
            with self.subTest(entry=entry):
                self.inventory([entry]);self.run_guard(expected=75)
        (self.root/'filesystem/usr/share/new').mkdir(mode=0o700)
        target=self.root/'filesystem/usr/share/new/file';os.mkfifo(target,0o600)
        self.inventory([self.entry()]);self.run_guard(expected=75)

    def test_ghost_entries_are_disclosed_without_claiming_script_storage(self):
        self.inventory([self.entry('/run/application.pid',0,stat.S_IFREG|0o600,flags=64)])
        result=self.run_guard()
        self.assertEqual(result['capacity_observation']['skipped_ghost_entries'],1)
        self.assertFalse(result['capacity_observation']['scripts_capacity_checked'])

    def test_empty_batch_does_not_claim_package_transaction(self):
        self.inventory([],packages=0)
        result=self.run_guard()
        self.assertFalse(result['rpm_test_performed'])
        self.assertTrue(result['payload_capacity_checked'])

    def test_database_wrong_kind_and_mutated_admitted_inventory_are_refused(self):
        path=self.root/'filesystem/var/lib/rpm/Packages.db';path.unlink();os.mkfifo(path,0o600)
        self.run_guard(expected=75)
        path.unlink();path.write_bytes(b'installed database fixture')
        inventory=self.workspace/'inventory.json';inventory.write_bytes(inventory.read_bytes()+b' ')
        self.run_guard(expected=75)

    def test_existing_matching_symlink_leaf_passes_without_changing_link_or_referent(self):
        parent=self.root/'filesystem/usr/share'
        target=parent/'operator-target';target.write_bytes(b'operator bytes');target.chmod(0o600)
        leaf=parent/'payload-link';leaf.symlink_to('operator-target')
        content=target.read_bytes()
        before=leaf.lstat(),target.stat(),content
        self.assertEqual(stat.S_IMODE(before[0].st_mode),0o777)
        self.inventory([self.entry('/usr/share/payload-link',14,stat.S_IFLNK|0o777,link='operator-target')])
        self.run_guard()
        self.assertEqual(leaf.lstat(),before[0])
        self.assertEqual(target.stat(),before[1])
        self.assertEqual(target.read_bytes(),before[2])
        self.assertEqual(os.readlink(leaf),'operator-target')

    def test_existing_dangling_matching_symlink_leaf_passes_without_creating_target(self):
        parent=self.root/'filesystem/usr/share'
        leaf=parent/'payload-link';leaf.symlink_to('missing-target')
        before=leaf.lstat()
        self.inventory([self.entry('/usr/share/payload-link',14,stat.S_IFLNK|0o777,link='missing-target')])
        self.run_guard()
        self.assertEqual(leaf.lstat(),before)
        self.assertEqual(os.readlink(leaf),'missing-target')
        self.assertFalse((parent/'missing-target').exists())

    def test_existing_leaf_fifo_referent_is_not_opened_or_mutated(self):
        parent=self.root/'filesystem/usr/share'
        target=parent/'operator-fifo';os.mkfifo(target,0o600)
        leaf=parent/'payload-link';leaf.symlink_to('operator-fifo')
        before=leaf.lstat(),target.lstat()
        self.inventory([self.entry('/usr/share/payload-link',13,stat.S_IFLNK|0o777,link='operator-fifo')])
        self.configure(audit_leaf_open=True)
        self.run_guard()
        opens=[json.loads(line) for line in (self.root/'leaf-open-flags.json').read_text().splitlines()]
        self.assertTrue(opens)
        self.assertTrue(all(item['flags'] & os.O_PATH and item['flags'] & os.O_NOFOLLOW for item in opens))
        self.assertEqual((leaf.lstat(),target.lstat()),before)

    def test_existing_symlink_leaf_untrusted_owner_is_refused_without_operator_changes(self):
        leaf=self.root/'filesystem/usr/share/payload-link';leaf.symlink_to('missing-target')
        before=leaf.lstat()
        self.inventory([self.entry('/usr/share/payload-link',14,stat.S_IFLNK|0o777,link='missing-target')])
        self.configure(untrusted_leaf_owner=True)
        result=self.run_guard(expected=75)
        self.assertIn('untrusted',result.stderr)
        self.assertEqual(leaf.lstat(),before)
        self.assertEqual(os.readlink(leaf),'missing-target')

    def test_signed_symlink_leaf_wrong_existing_kinds_are_preserved_and_refused(self):
        leaf=self.root/'filesystem/usr/share/payload-link'
        self.inventory([self.entry('/usr/share/payload-link',6,stat.S_IFLNK|0o777,link='target')])
        for kind in ('regular','directory','fifo','socket'):
            with self.subTest(kind=kind):
                sock=None
                if kind=='regular':leaf.write_bytes(b'operator');leaf.chmod(0o600)
                elif kind=='directory':leaf.mkdir(mode=0o700)
                elif kind=='fifo':os.mkfifo(leaf,0o600)
                else:
                    sock=socket.socket(socket.AF_UNIX);sock.bind(str(leaf));leaf.chmod(0o600)
                before=leaf.lstat()
                self.run_guard(expected=75)
                self.assertEqual(leaf.lstat(),before)
                if kind=='regular':self.assertEqual(leaf.read_bytes(),b'operator')
                if sock:sock.close()
                if kind=='directory':leaf.rmdir()
                else:leaf.unlink()

    def test_existing_regular_and_directory_write_bits_remain_strict(self):
        leaf=self.root/'filesystem/usr/share/payload-file'
        leaf.write_bytes(b'operator');leaf.chmod(0o666)
        self.inventory([self.entry('/usr/share/payload-file')])
        before=leaf.lstat();self.run_guard(expected=75)
        self.assertEqual(leaf.lstat(),before)
        self.assertEqual(leaf.read_bytes(),b'operator')
        leaf.chmod(0o600);self.run_guard()
        directory=self.root/'filesystem/usr/share/payload-directory';directory.mkdir(mode=0o777);directory.chmod(0o777)
        self.inventory([self.entry('/usr/share/payload-directory',0,stat.S_IFDIR|0o755)])
        before=directory.lstat();self.run_guard(expected=75)
        self.assertEqual(directory.lstat(),before)
        directory.chmod(0o700);self.run_guard()

    def test_existing_symlink_inode_swap_before_open_is_a_real_refusal(self):
        parent=self.root/'filesystem/usr/share';leaf=parent/'payload-link';leaf.symlink_to('original-target')
        before=leaf.lstat()
        self.inventory([self.entry('/usr/share/payload-link',15,stat.S_IFLNK|0o777,link='original-target')])
        self.configure(swap_leaf_before_open=True)
        result=self.run_guard(expected=75)
        self.assertIn('changed or a file mount',result.stderr)
        prior=parent/'prior-payload-link'
        self.assertEqual(prior.lstat().st_ino,before.st_ino)
        self.assertEqual(os.readlink(prior),'original-target')
        self.assertEqual(os.readlink(leaf),'changed-target')

    def test_existing_symlink_leaf_mount_mismatch_still_refuses(self):
        leaf=self.root/'filesystem/usr/share/payload-link';leaf.symlink_to('missing-target')
        before=leaf.lstat()
        self.inventory([self.entry('/usr/share/payload-link',14,stat.S_IFLNK|0o777,link='missing-target')])
        self.configure(leaf_mount_mismatch=True)
        result=self.run_guard(expected=75)
        self.assertIn('changed or a file mount',result.stderr)
        self.assertEqual(leaf.lstat(),before)


CAPACITY_LIBRARY = compatibility.LIBRARY + r'''
typedef struct { int index, count; } FI;
void *rpmfiNew(void *ts, void *header, int tag, unsigned flags) {
    if(tag || flags!=916798) abort(); record("inventory",1);
    if(setting("fi_failure")) return NULL;
    FI *fi=calloc(1,sizeof(FI));fi->index=-1;fi->count=setting("fi_empty")?0:2;return fi;
}
void *rpmfiFree(FI *fi) { record("inventory-free",1);free(fi);return NULL; }
void *rpmfiInit(FI *fi,int start) { if(start) abort();fi->index=-1;return fi; }
unsigned rpmfiFC(FI *fi) { return setting("fi_excessive")?131073:fi->count; }
int rpmfiNext(FI *fi) { return ++fi->index<fi->count && !(setting("fi_short") && fi->index==1)?fi->index:-1; }
const char *rpmfiFN(FI *fi) { return setting("fi_duplicate")?"/usr/share/fixture":fi->index?"/usr/share/fixture-link":"/usr/share/fixture"; }
uint64_t rpmfiFSize(FI *fi) { return setting("fi_large64")?((uint64_t)1<<32):1234; }
uint16_t rpmfiFMode(FI *fi) { return fi->index?0120777:0100644; }
unsigned rpmfiFFlags(FI *fi) { return 0; }
const char *rpmfiFLink(FI *fi) { return fi->index?"fixture":""; }
typedef struct { int tag; } TD;
void *rpmtdNew(void) { return setting("td_failure")?NULL:calloc(1,sizeof(TD)); }
void *rpmtdFree(TD *td) { free(td);return NULL; }
void rpmtdFreeData(TD *td) { }
int headerGet(void *header,int tag,TD *td,unsigned flags) {
    if(flags) abort();td->tag=tag;
    if(tag==1027 || tag==5008 || setting("fi_absent_size") && tag==1028) return 0;
    return 1;
}
unsigned rpmtdCount(TD *td) { return setting("fi_excessive")?131073:setting("fi_badcount") && td->tag==1028?1:setting("fi_empty")?0:2; }
int rpmtdType(TD *td) { return setting("fi_badtype")?7:td->tag==1117 || td->tag==1036?8:td->tag==1030?3:4; }
'''


class UpdateCapacityIntegrationTests(unittest.TestCase):
    command = compatibility.UpdateCompatibilityTests.command
    configure = compatibility.UpdateCompatibilityTests.configure
    calls = compatibility.UpdateCompatibilityTests.calls
    shell = compatibility.UpdateCompatibilityTests.shell
    prepare = compatibility.UpdateCompatibilityTests.prepare
    native_calls = compatibility.UpdateCompatibilityTests.native_calls

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='azurelinux3s4-capacity-rpm-',dir=Path.home()/'.cache')
        cls.addClassCleanup(temporary.cleanup)
        cls.library=Path(temporary.name)/'librpm-fixture.so'
        subprocess.run(['cc','-shared','-fPIC','-x','c','-','-o',str(cls.library)],input=CAPACITY_LIBRARY,
                       text=True,capture_output=True,check=True)

    def setUp(self):
        compatibility.UpdateCompatibilityTests.setUp(self)
        filesystem_fixture(self.root)
        fixture=self.root/'capacity-fixture-injection.py';fixture.write_text(OBSERVATION_FIXTURE)
        self.configuration_fixture=fixture

    def header(self):
        return compatibility.UpdateCompatibilityTests.header(self) + f'''
export S4_CAPACITY_FIXTURE={shlex.quote(str(self.root))}
eval "$(declare -f s4_update_capacity_program | sed '1s/s4_update_capacity_program/s4_original_capacity_program/')"
s4_update_capacity_program() {{
    s4_original_capacity_program | python3 -c 'import pathlib,sys; text=sys.stdin.read(); injection=pathlib.Path(sys.argv[1]).read_text(); print(text.replace("held = []\\ntry:\\n",injection+"\\nheld = []\\ntry:\\n",1),end="")' {shlex.quote(str(self.configuration_fixture))}
}}
'''

    def test_fresh_native_inventory_is_bound_to_capacity_observation_and_original_pointer(self):
        self.prepare()
        pointer=(self.root/'state/updates/current.json').read_bytes()
        result=json.loads(self.shell('s4_check_update_capacity').stdout)
        self.assertTrue(result['payload_capacity_checked'])
        self.assertFalse(result['storage_capacity_checked'])
        self.assertEqual(result['payload_inventory']['files'],2)
        self.assertIn('inventory 1',self.native_calls())
        self.assertIn('inventory-free 1',self.native_calls())
        self.assertEqual(pointer,(self.root/'state/updates/current.json').read_bytes())
        self.assertFalse(result['installation_authorized'])

    def test_native_inventory_allocation_count_order_and_duplicate_failures_remain_pending(self):
        self.prepare()
        for flag in ('fi_failure','fi_excessive','fi_short','fi_duplicate'):
            with self.subTest(flag=flag):
                self.configure(**{flag:True});self.shell('s4_check_update_capacity',expected=75)

    def test_missing_short_or_wrong_typed_file_arrays_are_not_zero_size_success(self):
        self.prepare()
        for flag in ('td_failure','fi_absent_size','fi_badcount','fi_badtype'):
            with self.subTest(flag=flag):
                self.configure(**{flag:True});self.shell('s4_check_update_capacity',expected=75)

    def test_public_64bit_file_size_is_not_truncated_in_capacity_budget(self):
        self.prepare(fi_large64=True,total_bytes=128*1024**3,available_bytes=120*1024**3)
        result=json.loads(self.shell('s4_check_update_capacity').stdout)
        self.assertGreater(result['capacity_observation']['filesystems'][0]['required_bytes'],16*1024**3)

    def test_native_dependency_or_signature_failure_precedes_capacity_success(self):
        self.prepare()
        for flag in ('dependencies','check_error'):
            with self.subTest(flag=flag):
                self.configure(**{flag:True});self.shell('s4_check_update_capacity',expected=75)

    def test_capacity_failure_does_not_reuse_prior_success_or_remove_batch(self):
        self.prepare();self.shell('s4_reconcile_component update-capacity yes')
        self.assertIn('status=complete',(self.root/'state/components/update-capacity').read_text())
        pointer=(self.root/'state/updates/current.json').read_bytes()
        self.configure(available_inodes=0)
        self.shell('s4_reconcile_component update-capacity yes',expected=75)
        self.assertIn('status=pending',(self.root/'state/components/update-capacity').read_text())
        self.assertEqual(pointer,(self.root/'state/updates/current.json').read_bytes())

    def test_capacity_backoff_precedes_readmission_or_native_inventory(self):
        self.shell('s4_write_state update-capacity pending 1 1000030 75; s4_reconcile_component update-capacity no',expected=75)
        self.assertEqual(self.native_calls(),[])

    def test_default_six_component_dispatch_requires_capacity_before_finalization(self):
        self.prepare(available_inodes=0)
        body=f'''
s4_verify_trust_anchor() {{ return 0; }}
s4_verify_bootstrap() {{ return 0; }}
s4_repositories() {{ return 0; }}
s4_verify_repository_trust() {{ return 0; }}
s4_prepare_updates() {{ return 0; }}
s4_start_timer() {{ return 0; }}
s4_start_repair_timer() {{ touch {shlex.quote(str(self.root/'retry'))}; }}
s4_finish_repair() {{ touch {shlex.quote(str(self.root/'finished'))}; }}
# Earlier component diagnostics are progress; this case asserts worker state.
s4_repair yes >/dev/null
'''
        self.shell(body,expected=75)
        self.assertTrue((self.root/'retry').exists())
        self.assertFalse((self.root/'finished').exists())
        self.configure();self.shell(body)
        self.assertTrue((self.root/'finished').exists())
        self.assertIn('status=complete',(self.root/'state/components/update-capacity').read_text())

    def test_empty_native_batch_is_not_mislabeled_as_package_test(self):
        self.prepare(empty=True)
        result=json.loads(self.shell('s4_check_update_capacity').stdout)
        self.assertFalse(result['rpm_test_performed'])
        self.assertEqual(result['payload_inventory']['files'],0)

    def test_whole_attempt_budget_includes_repeated_admission_test_capacity_and_controls(self):
        deadline=int(self.shell('s4_repair_timeout_seconds').stdout)
        self.assertEqual(deadline,11800+2295+305+4*35)
        self.assertLess(deadline,5*60*60)

    def test_existing_matching_fixture_link_passes_fresh_native_inventory_check(self):
        self.prepare()
        parent=self.root/'filesystem/usr/share'
        target=parent/'fixture';target.write_bytes(b'operator target');target.chmod(0o600)
        leaf=parent/'fixture-link';leaf.symlink_to('fixture')
        before=leaf.lstat(),target.stat(),(self.root/'state/updates/current.json').read_bytes()
        result=json.loads(self.shell('s4_check_update_capacity').stdout)
        self.assertTrue(result['payload_capacity_checked'])
        self.assertFalse(result['installation_authorized'])
        self.assertEqual(result['payload_inventory']['files'],2)
        self.assertEqual((leaf.lstat(),target.stat(),(self.root/'state/updates/current.json').read_bytes()),before)
        self.assertEqual(target.read_bytes(),b'operator target')

    def test_existing_dangling_fixture_link_completes_capacity_reconciliation(self):
        self.prepare()
        parent=self.root/'filesystem/usr/share';leaf=parent/'fixture-link';leaf.symlink_to('fixture')
        before=leaf.lstat(),(self.root/'state/updates/current.json').read_bytes()
        self.shell('s4_reconcile_component update-capacity yes')
        self.assertIn('status=complete',(self.root/'state/components/update-capacity').read_text())
        self.assertEqual((leaf.lstat(),(self.root/'state/updates/current.json').read_bytes()),before)
        self.assertFalse((parent/'fixture').exists())

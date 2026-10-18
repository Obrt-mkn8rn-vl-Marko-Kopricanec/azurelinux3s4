"""Inspect local account-file declarations; never query NSS or provision accounts."""


ACCOUNT_INPUT_LIMIT = 2 * 1024 * 1024
ACCOUNT_ROW_LIMIT = 10000
ACCOUNT_FILES = {'passwd': 0o644, 'group': 0o644, 'shadow': 0o600,
                 'gshadow': 0o600, 'nsswitch.conf': 0o644}
ACCOUNT_INVENTORY_AUTHORITY = ('native_nss_queried', 'effective_nss_resolution_proven',
                               'password_authentication_disabled', 'shell_executable_authenticated',
                               'accounts_created_or_modified', 'group_membership_enforced',
                               'service_credentials_accessible', 'account_intent_authenticated', 'server_ready')


def account_text(raw):
    if (type(raw) is not bytes or not 0 < len(raw) <= ACCOUNT_INPUT_LIMIT or not raw.endswith(b'\n')
            or any(byte < 32 and byte not in (9, 10) or byte > 126 for byte in raw)):
        raise ValueError('bounded ASCII account input with final LF required')
    lines = raw.decode('ascii').splitlines()
    if len(lines) > ACCOUNT_ROW_LIMIT:
        raise ValueError('account input row bound')
    return lines


def account_name(value):
    if not dep_re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,31}\$?', value) or len(value) > 32:
        raise ValueError('unsupported local account name')
    return value


def account_number(value, optional=False):
    if optional and value == '':
        return None
    if not dep_re.fullmatch(r'0|[1-9][0-9]{0,9}', value) or int(value) > 4294967294:
        raise ValueError('bounded canonical account number required')
    return int(value)


def account_members(value):
    names = [] if value == '' else value.split(',')
    if len(names) > 1024 or len(set(names)) != len(names):
        raise ValueError('unique bounded group member list required')
    for name in names:
        account_name(name)
    return names


def account_rows(raw, kind):
    widths = {'passwd': 7, 'group': 4, 'shadow': 9, 'gshadow': 4}
    result = {}
    for line in account_text(raw):
        if '\t' in line:
            raise ValueError('tabs are unsupported in local account records')
        if not line or line.startswith('#'):
            continue
        fields = line.split(':')
        if len(fields) != widths[kind] or fields[0] in result:
            raise ValueError('exact unique local account record required')
        name = account_name(fields[0])
        if kind == 'passwd':
            account_number(fields[2]); account_number(fields[3])
        elif kind == 'group':
            account_number(fields[2]); account_members(fields[3])
        elif kind == 'shadow':
            for value in fields[2:8]:
                account_number(value, optional=True)
            if fields[8]:
                raise ValueError('unsupported reserved shadow field')
        else:
            account_members(fields[2]); account_members(fields[3])
        result[name] = fields
    return result


def account_nss(raw):
    selected = {}
    watched = ('passwd', 'group', 'shadow', 'gshadow', 'initgroups')
    for line in account_text(raw):
        line = line.partition('#')[0].strip()
        if not line:
            continue
        name, separator, providers = line.partition(':')
        if not separator or not dep_re.fullmatch(r'[a-z_]+', name.strip()) or line.endswith('\\'):
            raise ValueError('unsupported NSS declaration syntax')
        name = name.strip()
        if name in watched:
            if name in selected:
                raise ValueError('duplicate NSS account database declaration')
            selected[name] = providers.split()
    local_only = all(selected.get(name) == ['files'] for name in watched[:4])
    if 'initgroups' in selected and selected['initgroups'] != ['files']:
        local_only = False
    return selected, local_only


def account_inventory(units, inputs):
    # Recompile the complete ordered unit/account correspondence, not an adopted
    # account receipt or a caller-selected list of users to skip.
    policy = application_account_policy(units)
    deployment_fields(inputs, ACCOUNT_FILES)
    databases = {name: account_rows(inputs[name], name) for name in ('passwd', 'group', 'shadow', 'gshadow')}
    passwd, groups, shadow, gshadow = (databases[name] for name in ('passwd', 'group', 'shadow', 'gshadow'))
    providers, local_only = account_nss(inputs['nsswitch.conf'])
    rows = []
    for declared in policy['accounts']:
        name = declared['name']
        present = [name in database for database in databases.values()]
        memberships = [group for group, fields in groups.items() if name in account_members(fields[3])]
        shadow_memberships = [group for group, fields in gshadow.items() if name in account_members(fields[3])]
        administrators = [group for group, fields in gshadow.items() if name in account_members(fields[2])]
        issues, uid, gid = [], None, None
        if not any(present) and not memberships and not shadow_memberships and not administrators:
            status = 'absent'
        elif not all(present):
            status, issues = 'conflict', ['partial_account_records']
        else:
            user, group, secret, group_secret = (database[name] for database in databases.values())
            uid, gid = int(user[2]), int(group[2])
            checks = {
                'root_numeric_identity': uid == 0 or gid == 0,
                'primary_group_mismatch': int(user[3]) != gid,
                'uid_alias': sum(int(row[2]) == uid for row in passwd.values()) != 1,
                'gid_alias': sum(int(row[2]) == gid for row in groups.values()) != 1,
                'foreign_primary_group_user': any(other != name and int(row[3]) == gid for other, row in passwd.items()),
                'password_source_not_shadow': user[1] != 'x',
                'password_not_locked': not secret[1].startswith(('!', '*')),
                'unexpected_home_or_shell': user[5:] != ['/', '/usr/sbin/nologin'],
                'group_password_not_locked': group[1] not in ('x', '!', '*') or not group_secret[1].startswith(('!', '*')),
                'unexpected_group_member': bool((set(account_members(group[3])) | set(account_members(group_secret[3]))) - {name}),
                'group_shadow_members_mismatch': set(account_members(group[3])) != set(account_members(group_secret[3])),
                'supplementary_group_membership': bool((set(memberships) | set(shadow_memberships)) - {name}),
                'group_administrator_membership': bool(administrators) or bool(account_members(group_secret[2])),
            }
            issues = [key for key, failed in checks.items() if failed]
            status = 'conflict' if issues else 'compatible-local-declarations'
        rows.append({'name': name, 'status': status, 'uid': uid, 'gid': gid, 'issues': issues,
                     'units': declared['units']})
    return {'scope': 'LOCAL ACCOUNT FILE DECLARATIONS ONLY', 'units': policy['units'], 'accounts': rows,
            'sources': {name: {'bytes': len(raw), 'sha256': dep_hash.sha256(raw).hexdigest()} for name, raw in inputs.items()},
            'nss_declarations': providers, 'selected_nss_files_only': local_only,
            'all_present_and_locally_compatible': local_only and all(row['status'] == 'compatible-local-declarations' for row in rows),
            'authority': {name: False for name in ACCOUNT_INVENTORY_AUTHORITY},
            'limits': ['Bounded conservative ASCII record syntax and files-only NSS declarations, not the complete native parser or effective NSS resolution.',
                       'Password lock markers and nologin path spelling do not disable all authentication, authenticate the shell, or prove PAM/SSH/process/credential behavior.',
                       'Missing users remain absent; conflicts are reported without changing IDs, memberships, passwords, files or accounts. No numeric allocation is selected.',
                       'Drava and DNS deliberately share their respective account names; local uniqueness does not establish per-role or hostile same-UID isolation.']}


def account_inventory_observe(units):
    if dep_os.geteuid() != DEP_TRUSTED_UID:
        raise ValueError('protected local account observation requires root')
    captured = {}
    with dep_context.ExitStack() as stack:
        root = dep_os.open('/', DEP_OPEN | dep_os.O_DIRECTORY); stack.callback(dep_os.close, root)
        root_before = dep_os.fstat(root); deployment_directory(root_before)
        before = dep_os.stat('etc', dir_fd=root, follow_symlinks=False); deployment_directory(before)
        parent = dep_os.open('etc', DEP_OPEN | dep_os.O_DIRECTORY, dir_fd=root); stack.callback(dep_os.close, parent)
        if deployment_identity(dep_os.fstat(parent)) != deployment_identity(before):
            raise ValueError('account database directory changed on open')
        leaves = []
        for name, mode in ACCOUNT_FILES.items():
            value, info = release_file(parent, name, ACCOUNT_INPUT_LIMIT, mode, capture=True)
            captured[name] = value[2]; leaves.append((name, info))
        result = account_inventory(units, captured)
        for name, original in leaves:
            if deployment_identity(dep_os.stat(name, dir_fd=parent, follow_symlinks=False)) != deployment_identity(original):
                raise ValueError('account database changed during observation')
        if (deployment_identity(dep_os.fstat(parent)) != deployment_identity(before)
                or deployment_identity(dep_os.stat('etc', dir_fd=root, follow_symlinks=False)) != deployment_identity(before)
                or deployment_identity(dep_os.fstat(root)) != deployment_identity(root_before)):
            raise ValueError('account database ancestry changed')
        fresh = dep_os.open('/', DEP_OPEN | dep_os.O_DIRECTORY); stack.callback(dep_os.close, fresh)
        if deployment_identity(dep_os.fstat(fresh)) != deployment_identity(root_before):
            raise ValueError('account observation root changed')
    return result

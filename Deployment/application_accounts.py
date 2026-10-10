"""Fixed sysusers declarations bound to complete freshly produced service units.

No NSS lookup, account creation, native parser or manager invocation is supplied.
"""


APP_ACCOUNT_FILE = 'usr/lib/sysusers.d/azurelinux3s4-applications.conf'
APP_ACCOUNT_UNIT_LIMIT = 64 * 1024
APP_ACCOUNT_UNITS = {
    'mk8-sava-application': 'mk8sava-application',
    'mk8-sava-gateway': 'mk8sava-gateway',
    'mk8-drava-application': 'mk8drava', 'mk8-drava-gateway': 'mk8drava',
    'mk8-dns-controller': 'mk8dns', 'mk8-dns-authoritative-replica': 'mk8dns',
    'mk8-dns-gateway4': 'mk8dns', 'mk8-dns-gateway6': 'mk8dns',
    'mk8-email-worker': 'mk8email-worker', 'mk8-email-gateway': 'mk8email-gateway',
}
APP_ACCOUNT_AUTHORITY = ('owner_account_intent_authenticated', 'native_sysusers_parser_passed',
                         'sysusers_executed', 'current_nss_users_groups_admitted',
                         'uids_gids_allocated', 'passwords_locked_and_shells_admitted',
                         'supplementary_groups_admitted', 'service_credential_access_proven',
                         'accounts_rollback_proven', 'server_ready')


def application_account_policy(units):
    # Internal pure compiler. The mandatory publisher calls this only with its
    # freshly reconstructed full candidate, never a CLI-supplied retained receipt.
    if type(units) is not list or len(units) not in (9, 10):
        raise ValueError('complete application account unit set required')
    rows, seen, accounts = [], set(), {}
    for entry in units:
        deployment_fields(entry, ('file', 'mode', 'bytes', 'sha256', 'content'))
        if (type(entry['file']) is not str or not entry['file'].startswith('systemd/')
                or not entry['file'].endswith('.service') or type(entry['mode']) is not str or entry['mode'] != '0644'
                or type(entry['sha256']) is not str
                or type(entry['bytes']) is not int or type(entry['content']) is not str
                or not 0 < len(entry['content']) <= APP_ACCOUNT_UNIT_LIMIT):
            raise ValueError('fixed account unit identity/mode required')
        name = entry['file'][len('systemd/'):-len('.service')]
        if name not in APP_ACCOUNT_UNITS or name in seen:
            raise ValueError('unique supported account unit required')
        raw = entry['content'].encode('ascii')
        if (not raw.endswith(b'\n') or any(byte < 32 and byte != 10 or byte > 126 for byte in raw)
                or entry['bytes'] != len(raw) or entry['sha256'] != dep_hash.sha256(raw).hexdigest()):
            raise ValueError('account unit byte commitment mismatch')
        section, service_sections, identities = '', 0, {}
        for line in entry['content'].splitlines():
            if not line or line.startswith('#'):
                continue
            if line.startswith('['):
                if line not in ('[Unit]', '[Service]', '[Install]'):
                    raise ValueError('unsupported account unit section')
                section = line
                service_sections += line == '[Service]'
            key, separator, value = line.partition('=')
            if separator and not dep_re.fullmatch(r'[A-Za-z][A-Za-z0-9]*', key):
                raise ValueError('canonical account unit directive required')
            if separator and key in ('DynamicUser', 'SupplementaryGroups', 'PAMName',
                                     'RootDirectory', 'RootImage', 'PrivateUsers'):
                raise ValueError('unsupported account identity modifier')
            if separator and key in ('User', 'Group'):
                if section != '[Service]' or key in identities:
                    raise ValueError('single service User/Group declarations required')
                identities[key] = value
        account = APP_ACCOUNT_UNITS[name]
        if service_sections != 1 or identities != {'User': account, 'Group': account}:
            raise ValueError('exact service account correspondence required')
        seen.add(name)
        rows.append({'file': entry['file'], 'bytes': len(raw), 'sha256': entry['sha256'],
                     'user': account, 'group': account})
        accounts.setdefault(account, []).append(entry['file'])
    base = tuple(name for name in APP_ACCOUNT_UNITS if not name.startswith('mk8-dns-gateway')
                 and not name.startswith('mk8-email-'))
    gateways = tuple(name for name in ('mk8-dns-gateway4', 'mk8-dns-gateway6') if name in seen)
    expected = (*base, *gateways, 'mk8-email-worker', 'mk8-email-gateway')
    if not gateways or tuple(row['file'] for row in rows) != tuple('systemd/' + name + '.service' for name in expected):
        raise ValueError('complete ordered account unit membership required')
    lines = ['# Candidate declarations; account provisioning and consumer context unproven.']
    for account in accounts:
        # '-' delegates numeric allocation to a future admitted native consumer.
        # No ID/range, membership, password, credential or admin account is invented.
        lines.append('u ' + account + ' - "Application service account" / /usr/sbin/nologin')
    file = deployment_file(APP_ACCOUNT_FILE, '0644', '\n'.join(lines) + '\n')
    return {'file': file, 'units': rows,
            'accounts': [{'name': name, 'primary_group': name, 'uid': None, 'gid': None,
                          'units': owners} for name, owners in accounts.items()],
            'source_profile': 'Pinned systemd v255 u syntax; missing users/groups only; automatic numeric allocation UNSELECTED.',
            'authority': {name: False for name in APP_ACCOUNT_AUTHORITY},
            'limits': ['Pure declaration compiler; no NSS/native sysusers/account creation or UID/GID/current-password/shell/access proof.',
                       'Existing users/groups are not repaired by this fragment. Fresh complete NSS/local databases, supplementary groups, non-root uniqueness and credential access remain required.',
                       'Full /etc,/run,/usr/lib sysusers precedence and every conflicting fragment/native consumer must be admitted. An installed fragment could be consumed at boot or by independent tools.',
                       'The explicit nologin path is a declaration, not authenticated installed executable proof. No home directory is created; native state/cache/runtime provisioning remains separate.',
                       'Drava and DNS retain shared per-application names; this does not establish same-UID isolation or actual numeric equality/distinctness.']}

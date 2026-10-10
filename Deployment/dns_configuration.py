"""Observe a conservative complete DNS control-record declaration profile."""

import base64 as dns_base64
import datetime as dns_datetime


DNS_CONFIGURATION_AUTHORITY = (
    'original_application_deserializer_executed', 'complete_runtime_schema_compatibility_proven',
    'publisher_epoch_authenticated', 'target_node_identity_authenticated', 'zone_ownership_authenticated',
    'grant_intent_authenticated', 'grant_credentials_authenticated', 'grant_expiry_current',
    'request_actions_authorized', 'record_scope_authorized', 'signing_key_curve_and_scope_validated',
    'dnssec_runtime_sufficiency_proven', 'database_and_publication_usable',
    'configuration_installed', 'application_started', 'server_ready',
)


def dns_fields(value, required, optional=(), context='control'):
    if type(value) is not dict or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise ValueError('exact DNS ' + context + ' record fields required')


def dns_guid(value):
    if (type(value) is not str or not dep_re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value)
            or value == '00000000-0000-0000-0000-000000000000'):
        raise ValueError('nonempty canonical DNS zone/epoch/tenant identity required')
    return value


def dns_uint(value, maximum=4294967295):
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError('typed DNS unsigned integer required')
    return value


def dns_name(value):
    # Plain lowercase ASCII subset only: no normalization, wildcard, root zone,
    # octet escapes or Unicode. Wire length is presentation length plus one.
    if (type(value) is not str or not 2 <= len(value) <= 254
            or not dep_re.fullmatch(r'(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+', value)):
        raise ValueError('bounded canonical plain DNS name required')
    return value


def dns_expiry(value):
    # Observe a UTC literal/calendar only. No wall-clock comparison, expiry
    # approval or request authorization; original bytes/fraction are retained.
    if type(value) is not str:
        raise ValueError('DNS UTC expiry literal required')
    match = dep_re.fullmatch(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.[0-9]{1,7})?Z', value)
    if not match:
        raise ValueError('DNS UTC expiry literal required')
    dns_datetime.datetime(*(int(part) for part in match.groups()), tzinfo=dns_datetime.timezone.utc)


def dns_grants(grants, zones):
    if type(grants) is not list or not 1 <= len(grants) <= 64:
        raise ValueError('bounded controller management grants required')
    actors, credentials, scopes_total = set(), set(), 0
    for grant in grants:
        dns_fields(grant, ('TenantId', 'ZoneId', 'Origin', 'Actor', 'Expires', 'CredentialHash'),
                   ('Profile', 'Actions', 'RecordScopes'), 'grant')
        tenant, zone = dns_guid(grant['TenantId']), dns_guid(grant['ZoneId'])
        origin = dns_name(grant['Origin'])
        if zones.get(zone) != origin:
            raise ValueError('management grant exceeds exact publisher zone scope')
        actor = grant['Actor']
        if type(actor) is not str or not dep_re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}', actor):
            raise ValueError('bounded plain management actor required')
        dns_expiry(grant['Expires'])
        encoded = grant['CredentialHash']
        if type(encoded) is not str or not dep_re.fullmatch(r'[A-Za-z0-9+/]{43}=', encoded):
            raise ValueError('canonical 32-byte credential hash required')
        decoded = dns_base64.b64decode(encoded, validate=True)
        if len(decoded) != 32 or dns_base64.b64encode(decoded).decode('ascii') != encoded:
            raise ValueError('canonical 32-byte credential hash required')
        if (tenant, zone, actor) in actors or (tenant, zone, encoded) in credentials:
            raise ValueError('duplicate scoped management identity or credential hash')
        actors.add((tenant, zone, actor)); credentials.add((tenant, zone, encoded))
        profile = grant.get('Profile', 'zone')
        if profile not in ('zone', 'records', 'acme'):
            raise ValueError('supported management profile required')
        actions = grant.get('Actions')
        if actions is None:
            actions = ['edit', 'patch', 'read', 'status'] if profile == 'zone' else []
        if (type(actions) is not list or not 1 <= len(actions) <= 6
                or any(type(action) is not str or action not in ('edit', 'patch', 'read', 'status', 'import', 'export') for action in actions)
                or len(set(actions)) != len(actions)):
            raise ValueError('bounded unique management actions required')
        scopes = grant.get('RecordScopes')
        if scopes is None:
            scopes = []
        if (type(scopes) is not list or len(scopes) > 64 or (profile == 'zone' and scopes)
                or (profile != 'zone' and (not scopes or any(action in ('edit', 'import', 'export') for action in actions)))):
            raise ValueError('profile-specific management scope required')
        seen = set()
        for scope in scopes:
            dns_fields(scope, ('Owner', 'Type'), context='record scope')
            owner, kind = dns_name(scope['Owner']), dns_uint(scope['Type'], 65535)
            if (not (owner == origin or owner.endswith('.' + origin)) or kind in (0, 6, 41) or 249 <= kind <= 255
                    or (profile == 'acme' and (kind != 16 or not owner.startswith('_acme-challenge.')))
                    or (owner, kind) in seen):
                raise ValueError('bounded unique in-zone record scope required')
            seen.add((owner, kind))
        scopes_total += len(scopes)
    return scopes_total


def dns_control_observe(captured, plan):
    records, summaries = [], []
    for role, leaf in (('controller', 'control-plane.json'), ('authoritative-replica', 'authority.json')):
        value = release_json(captured[leaf])
        dns_fields(value, ('Epoch', 'TargetNode', 'Zones', 'KeyFile'),
                   ('ConnectionStringFile', 'PublicationSocket', 'Grants', 'SigningScanSeconds'))
        epoch = dns_guid(value['Epoch'])
        if value['TargetNode'] != plan['dns_nodes']['authoritative-replica']:
            raise ValueError('exact declared replica target-node correspondence required')
        runtime = '/run/mk8.dns/' + role + '/inputs/'
        if value['KeyFile'] != runtime + 'key.pem':
            raise ValueError('DNS role-owned key reference required')
        rows = value['Zones']
        if type(rows) is not list or not 1 <= len(rows) <= 64:
            raise ValueError('bounded complete DNS zones required')
        zones, origins, margins = {}, set(), []
        for zone in rows:
            dns_fields(zone, ('ZoneId', 'Origin'), ('SigningKeyFile', 'SignatureLifetimeSeconds', 'DnskeyTtl', 'RenewBeforeSeconds'), 'zone')
            identifier, origin = dns_guid(zone['ZoneId']), dns_name(zone['Origin'])
            if identifier in zones or origin in origins:
                raise ValueError('unique DNS zone identities and origins required')
            zones[identifier] = origin; origins.add(origin)
            lifetime = dns_uint(zone.get('SignatureLifetimeSeconds', 604800))
            dns_uint(zone.get('DnskeyTtl', 3600))
            margin = zone.get('RenewBeforeSeconds')
            if margin is not None:
                dns_uint(margin)
            key = zone.get('SigningKeyFile')
            if key is None:
                if lifetime != 604800 or zone.get('DnskeyTtl', 3600) != 3600 or margin is not None:
                    raise ValueError('unsigned/replica zone cannot carry private signing policy')
            else:
                if role != 'controller' or key != runtime + 'zone-' + identifier + '.pk8':
                    raise ValueError('DNS controller-owned signing key reference required')
                if not 3600 <= lifetime <= 2592000:
                    raise ValueError('bounded signing lifetime required')
                actual_margin = lifetime // 4 if margin is None else margin
                if not 60 <= actual_margin <= lifetime - 60:
                    raise ValueError('bounded renewal margin required')
                margins.append(actual_margin)
        if plan['dns_zone'] + '.' not in origins:
            raise ValueError('declared public DNS zone must be in the control scope')
        scan = dns_uint(value.get('SigningScanSeconds', 60))
        if not 1 <= scan <= 300 or any(scan > margin // 2 for margin in margins) or (not margins and scan != 60):
            raise ValueError('bounded signing scan declaration required')
        if role == 'controller':
            if (value.get('ConnectionStringFile') != runtime + 'database.txt'
                    or value.get('PublicationSocket') != '/run/mk8.dns/authoritative-replica/publication.sock'):
                raise ValueError('DNS role-owned controller database/publication references required')
            scope_count = dns_grants(value.get('Grants'), zones)
            grant_count = len(value['Grants'])
        else:
            if (value.get('ConnectionStringFile') is not None or value.get('PublicationSocket') is not None
                    or value.get('Grants') not in (None, [])):
                raise ValueError('replica cannot receive controller declarations')
            scope_count, grant_count = 0, 0
        records.append((epoch, value['TargetNode'], zones))
        summaries.append({'role': role, 'original_bytes': len(captured[leaf]),
                          'original_sha256': dep_hash.sha256(captured[leaf]).hexdigest(),
                          'epoch_declaration': epoch, 'target_node_declaration': value['TargetNode'],
                          'zones': [{'id': key, 'origin': origin} for key, origin in sorted(zones.items())],
                          'grant_count': grant_count, 'record_scope_count': scope_count,
                          'private_signing_reference_count': len(margins),
                          'authority': {name: False for name in DNS_CONFIGURATION_AUTHORITY}})
    if records[0] != records[1]:
        raise ValueError('complete controller/replica epoch/target/zone correspondence required')
    return summaries

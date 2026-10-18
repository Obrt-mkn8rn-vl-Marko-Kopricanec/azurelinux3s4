"""Check exact private DNS P-256 key inputs with pinned local OpenSSL.

This validates key shape, native consistency, public/private correspondence and
explicit public-key pins. It never signs DNS/publication data or starts DNS.
"""

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
ALGORITHM = bytes.fromhex('301306072a8648ce3d020106082a8648ce3d030107')
PUBLIC_PREFIX = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d03010703420004')
P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
GUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'


def module(name):
    spec = importlib.util.spec_from_file_location('dns_key_' + name, ROOT/'Bootstrap'/(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PREFLIGHT = module('preflight')
INPUTS = module('tls_inputs')
RELEASE = INPUTS.RELEASE


def der(raw, offset, tag):
    if type(raw) is not bytes or not 0 <= offset < len(raw)-1 or raw[offset] != tag:
        raise ValueError('complete canonical DNS key DER tag required')
    size = raw[offset+1]; start = offset+2
    if size & 0x80:
        count = size & 0x7f
        if not 1 <= count <= 2 or start+count > len(raw) or raw[start] == 0:
            raise ValueError('bounded minimal DNS key DER length required')
        size = int.from_bytes(raw[start:start+count], 'big'); start += count
        if size < 128 or count == 2 and size < 256:
            raise ValueError('nonminimal DNS key DER length')
    if start+size > len(raw):
        raise ValueError('incomplete DNS key DER content')
    return raw[start:start+size], start+size


def pkcs8(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 4096:
        raise ValueError('bounded DNS PKCS8 bytes required')
    body, end = der(raw, 0, 0x30)
    prefix = b'\x02\x01\x00'+ALGORITHM
    if end != len(raw) or not body.startswith(prefix):
        raise ValueError('exact complete unencrypted named-P256 PKCS8 required')
    key, end = der(body, len(prefix), 4)
    if end != len(body):
        raise ValueError('DNS PKCS8 attributes or trailing data unsupported')
    inner, end = der(key, 0, 0x30)
    if end != len(key) or not inner.startswith(b'\x02\x01\x01'):
        raise ValueError('complete EC private-key version required')
    scalar, end = der(inner, 3, 4)
    if len(scalar) != 32 or not 1 <= int.from_bytes(scalar, 'big') < P256_ORDER:
        raise ValueError('bounded nonzero P256 private scalar required')
    if end != len(inner):
        point, end = der(inner, end, 0xa1)
        public, point_end = der(point, 0, 3)
        if end != len(inner) or point_end != len(point) or len(public) != 66 or public[:2] != b'\x00\x04':
            raise ValueError('one complete uncompressed EC public component required')
    return raw


def public_key(raw):
    if type(raw) is not bytes or len(raw) != 91 or not raw.startswith(PUBLIC_PREFIX):
        raise ValueError('exact named-P256 uncompressed public SPKI required')
    return raw


def pin(value):
    if type(value) is not str or not re.fullmatch('[0-9a-f]{64}', value):
        raise ValueError('explicit canonical public-key pin required')
    return value


def audit(private_root, manifest, openssl_sha256, publication_public_key_sha256, zone_keys):
    if os.geteuid() == 0 or os.geteuid() != os.getegid():
        raise ValueError('unprivileged developer with matching UID/GID required')
    pin(publication_public_key_sha256)
    if type(zone_keys) is not dict or len(zone_keys) > 64:
        raise ValueError('complete bounded explicit zone key pins required')
    for identifier, digest in zone_keys.items():
        if type(identifier) is not str or not re.fullmatch(GUID, identifier):
            raise ValueError('canonical zone key identity required')
        pin(digest)
    root_path = Path(RELEASE.absolute(private_root)); contract = RELEASE.contracts()
    parts = contract['deployment_path'](manifest)
    with contextlib.ExitStack() as stack:
        links = []
        root = RELEASE.anchor(stack, str(root_path), links); root_identity = RELEASE.identity(os.fstat(root))
        manifest_source = INPUTS.private_input(stack, links, root_path.joinpath(*parts))
        before = PREFLIGHT.preflight(root_path, manifest, include_candidate=True)
        if before['manifest_sha256'] != manifest_source[2][1]:
            raise ValueError('DNS key preflight original manifest changed')
        rows = before['candidate']['dns_credentials']
        if type(rows) is not list or [row['role'] for row in rows] != ['controller', 'authoritative-replica']:
            raise ValueError('complete ordered DNS credential observations required')
        captured, prepared, zone_paths, controls = {}, {}, {}, {}
        for row in rows:
            role = row['role']; runtime = '/run/mk8.dns/'+role+'/inputs/'
            if row['unit'] != 'mk8-dns-'+role+'.service' or type(row['inputs']) is not list:
                raise ValueError('exact DNS unit credential observations required')
            found = {}
            for item in row['inputs']:
                name = item['id']
                control = '/etc/mk8.dns/'+('control-plane.json' if role == 'controller' else 'authority.json')
                source = control if name == 'control.json' else '/etc/mk8.dns/'+role+'/'+name
                if (type(name) is not str or name in found or
                        not re.fullmatch(r'control\.json|key\.pem|database\.txt|zone-'+GUID+r'\.pk8', name)
                        or item['source'] != source or item['destination'] != runtime+name):
                    raise ValueError('exact complete DNS credential paths required')
                current = INPUTS.private_input(stack, links, root_path/source[1:])
                if (type(item['bytes']) is not int or not 0 < item['bytes'] <= (65536 if name == 'control.json' else 4096)
                        or current[2][:2] != (item['bytes'], item['sha256'])):
                    raise ValueError('DNS key input differs from fresh candidate commitment')
                found[name] = current
                captured[role+'/'+name] = current
            if not {'control.json','key.pem'} <= found.keys():
                raise ValueError('complete DNS control and key observations required')
            value = contract['release_json'](found['control.json'][2][2]); controls[role] = value
            expected = {'control.json','key.pem'} | ({'database.txt'} if role == 'controller' else set())
            for zone in value['Zones']:
                name = 'zone-'+zone['ZoneId']+'.pk8'
                if zone.get('SigningKeyFile') is not None:
                    if role != 'controller' or zone['SigningKeyFile'] != runtime+name:
                        raise ValueError('controller-only exact zone signing reference required')
                    expected.add(name);zone_paths[zone['ZoneId']] = role+'/'+name
            if found.keys() != expected:
                raise ValueError('complete exact original DNS credential source set required')
            if role == 'controller':
                prepared[role+'/key.pem'] = pkcs8(INPUTS.pem_blocks(found['key.pem'][2][2], {'PRIVATE KEY'}, 1)[0])
            else:
                prepared[role+'/key.pem'] = public_key(INPUTS.pem_blocks(found['key.pem'][2][2], {'PUBLIC KEY'}, 1)[0])
        if zone_keys.keys() != zone_paths.keys():
            raise ValueError('exact configured zone signing key pin set required')
        for identifier, name in zone_paths.items():
            prepared[name] = pkcs8(captured[name][2][2])
        replica_public = prepared['authoritative-replica/key.pem']
        if hashlib.sha256(replica_public).hexdigest() != publication_public_key_sha256:
            raise ValueError('DNS replica public key differs from explicit pin')
        native = INPUTS.NativeOpenSSL(stack, openssl_sha256)
        version = native.run(['version','-v']).decode('ascii').strip()
        if native.last_stderr or not re.fullmatch(r'OpenSSL 3\.[0-9]+\.[0-9]+[^\r\n]{0,180}',version):
            raise ValueError('OpenSSL 3 DNS key checker required')
        def checked(name, is_public=False):
            raw = prepared[name]
            flags = ['-pubin'] if is_public else []
            confirmation = native.run(['pkey','-inform','DER','-passin','pass:',*flags,
                                       '-pubcheck' if is_public else '-check','-noout'],raw)
            if confirmation != b'Key is valid\n' or native.last_stderr:
                raise ValueError('native DNS key consistency confirmation refused')
            if is_public: return raw
            derived = native.run(['pkey','-inform','DER','-passin','pass:','-pubout','-outform','DER',
                                  '-ec_conv_form','uncompressed','-ec_param_enc','named_curve'],raw)
            if native.last_stderr: raise ValueError('native DNS public-key derivation refused')
            return public_key(derived)
        controller_public = checked('controller/key.pem')
        checked('authoritative-replica/key.pem', True)
        if controller_public != replica_public:
            raise ValueError('DNS publication controller and replica keys differ')
        zones = []
        for identifier, name in zone_paths.items():
            public = checked(name); digest = hashlib.sha256(public).hexdigest()
            if digest != zone_keys[identifier]:
                raise ValueError('DNSSEC key differs from explicit zone pin')
            zones.append({'zone_id': identifier, 'source': '/etc/mk8.dns/'+name,
                          'algorithm_declaration': 13, 'public_spki_sha256': digest,
                          'public_xy_sha256': hashlib.sha256(public[-64:]).hexdigest()})
        after = PREFLIGHT.preflight(root_path, manifest, include_candidate=True)
        if after != before:
            raise ValueError('complete application plan changed during DNS key checks')
        for parent, leaf, original, identity in (manifest_source, *captured.values()):
            fresh, _ = RELEASE.read_file(parent,leaf,INPUTS.INPUT_LIMIT,capture=True,expected=identity)
            if fresh != original: raise ValueError('original DNS key source changed')
        if RELEASE.identity(os.fstat(root)) != root_identity:
            raise ValueError('DNS key private root changed')
        RELEASE.check_links(links);native.check()
        result = {'scope':'PRIVATE APPLICATION DNS P256 KEY PREFLIGHT',
                  'manifest_sha256':before['manifest_sha256'],'publication_sha256':before['publication_sha256'],
                  'software_sha256':before['software_sha256'],'files':before['files'],
                  'publication_public_spki_sha256':publication_public_key_sha256,
                  'epoch_declaration':controls['controller']['Epoch'],
                  'target_node_declaration':controls['controller']['TargetNode'],'zone_keys':zones,
                  'sources':{name:{'bytes':row[2][0],'sha256':row[2][1],'identity':list(row[3])}
                             for name,row in captured.items()},
                  'openssl':{'path':INPUTS.OPENSSL,'sha256':openssl_sha256,'version':version,
                             'identity':list(RELEASE.identity(native.before)),'commands':native.commands},
                  'checks':{'publication_private_and_public_keys_consistent':True,'publication_pair_matches_pin':True,
                            'all_configured_zone_private_keys_consistent_and_pinned':True,
                            'original_sources_and_complete_plan_reobserved':True},
                  'authority':{'key_intent_or_scope_authenticated':False,'epoch_or_node_authenticated':False,
                               'keys_loaded_by_dotnet':False,'publication_or_dnssec_signature_created':False,
                               'dnssec_zone_or_delegation_proven':False,'vendor_crypto_authenticated':False,
                               'installed':False,'application_started':False,'network_or_gpu_changed':False,'server_ready':False},
                  'limits':['The exact original controller PKCS8 PEM, replica public-only PEM and configured zone PKCS8 DER sources remain unmodified. The supported named-P256 representation is intentionally narrower than every form .NET might import.',
                            'Local native key consistency and explicit public fingerprints establish mathematical input correspondence, not signer authority, entropy, key provenance/rotation, authenticated zone/epoch/node intent, DS/DNSKEY publication or actual application use.',
                            'No publication/activation/DNSSEC message is signed. Native command receipts contain only counts/hashes and public output identities, never private key material.',
                            'Private byte copies are not a physical zeroization or hostile same-UID secrecy guarantee. Trusted native dependencies, sequential non-atomic observations and ordinary timeouts retain their limits. No listener, service, account, target or GPU operation occurs.']}
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('root','manifest','openssl-sha256','publication-public-key-sha256'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--zone-key',action='append',default=[],metavar='ZONE_ID=SPKI_SHA256')
    args=parser.parse_args(argv)
    try:
        zone_keys={}
        for value in args.zone_key:
            name,separator,digest=value.partition('=')
            if not separator or name in zone_keys:raise ValueError('unique explicit zone key pins required')
            zone_keys[name]=digest
        result=audit(args.root,args.manifest,args.openssl_sha256,args.publication_public_key_sha256,zone_keys)
        output=json.dumps(result,sort_keys=True,separators=(',',':'))
        if len(output)>1024*1024:raise ValueError('DNS key receipt bound')
    except (OSError,ValueError,TypeError,AttributeError,KeyError,MemoryError,RecursionError,
            OverflowError,UnicodeError,subprocess.SubprocessError):
        print('Private DNS key preflight refused',file=sys.stderr)
        return 75
    print(output)
    return 0


if __name__=='__main__':
    sys.exit(main())

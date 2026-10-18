"""Check complete private Email key rings and explicitly pinned RSA keys offline.

No token, message, MFA secret or ciphertext is created; no DB or Blob is read.
"""

import argparse
import base64
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


def module(name):
    spec = importlib.util.spec_from_file_location('email_keys_'+name, ROOT/'Bootstrap'/(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PREFLIGHT = module('preflight')
INPUTS = module('tls_inputs')
KEYS = module('key_formats')
RELEASE = INPUTS.RELEASE
SIGNERS = {'oauth': 'oauth-signing.txt', 'dkim': 'dkim-key.pem'}


def symmetric(raw):
    if type(raw) is not bytes or not re.fullmatch(rb'[A-Za-z0-9+/]{43}=\n?', raw):
        raise ValueError('one canonical base64 32-byte Email key required')
    encoded = raw[:-1] if raw.endswith(b'\n') else raw
    decoded = base64.b64decode(encoded, validate=True)
    if len(decoded) != 32 or base64.b64encode(decoded) != encoded:
        raise ValueError('canonical Email key padding and length required')
    return decoded


def url64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def jwk_thumbprint(modulus, exponent):
    values = {'e': url64(exponent.to_bytes((exponent.bit_length()+7)//8, 'big')), 'kty': 'RSA',
              'n': url64(modulus.to_bytes((modulus.bit_length()+7)//8, 'big'))}
    return url64(hashlib.sha256(json.dumps(values, sort_keys=True, separators=(',', ':')).encode('ascii')).digest())


def capture_role(stack, links, root, row, namespace):
    role = row['role']; runtime = '/run/credentials/mk8-email-'+role+'.service/'
    if row['unit'] != 'mk8-email-'+role+'.service' or type(row['inputs']) is not list:
        raise ValueError('exact complete Email credential unit required')
    # Capture the original startup first, then reconstruct its complete selected
    # set using the same shipped pure planner. A receipt never supplies the plan.
    config = INPUTS.private_input(stack, links, root/('etc/mk8.email/'+role+'.json'))
    selected = namespace['email_credential_plan'](role, config[2][2])
    found = {}
    for item in row['inputs']:
        name = item['id']
        if type(name) is not str or name not in selected or name in found:
            raise ValueError('exact unique complete Email credential IDs required')
        source, original, maximum = selected[name]
        if item['source'] != source or item['destination'] != runtime+name:
            raise ValueError('exact original Email credential paths required')
        current = config if name == 'config.json' else INPUTS.private_input(stack, links, root/source[1:])
        if (type(item['bytes']) is not int or not 0 < item['bytes'] <= maximum
                or current[2][:2] != (item['bytes'], item['sha256'])
                or original is not None and current[2][2] != original):
            raise ValueError('Email credential differs from fresh source commitment')
        found[name] = current
    if found.keys() != selected.keys():
        raise ValueError('complete selected Email credential source set required')
    return found, namespace['release_json'](config[2][2])


def audit(private_root, manifest, openssl_sha256, signing_keys):
    if os.geteuid() == 0 or os.geteuid() != os.getegid():
        raise ValueError('unprivileged developer with matching UID/GID required')
    if (type(signing_keys) is not dict or signing_keys.keys()-SIGNERS.keys()
            or any(type(pin) is not str or not re.fullmatch('[0-9a-f]{64}',pin) for pin in signing_keys.values())):
        raise ValueError('explicit exact Email RSA public-key pins required')
    root_path = Path(RELEASE.absolute(private_root)); contract = RELEASE.contracts()
    parts = contract['deployment_path'](manifest)
    with contextlib.ExitStack() as stack:
        links = []
        root = RELEASE.anchor(stack,str(root_path),links); root_identity = RELEASE.identity(os.fstat(root))
        manifest_source = INPUTS.private_input(stack,links,root_path.joinpath(*parts))
        before = PREFLIGHT.preflight(root_path,manifest,include_candidate=True)
        namespace, software = PREFLIGHT.shipped_library()
        if before['manifest_sha256'] != manifest_source[2][1] or before['software_sha256'] != software:
            raise ValueError('Email key original manifest or software changed')
        rows = before['candidate']['email_credentials']
        if type(rows) is not list or [row['role'] for row in rows] != ['worker','gateway']:
            raise ValueError('complete ordered Email role observations required')
        captured, configurations, rings = {}, {}, {}
        for row in rows:
            role = row['role']
            found, value = capture_role(stack,links,root_path,row,namespace)
            captured.update({role+'/'+name: item for name,item in found.items()}); configurations[role] = value
            messaging = value['Messaging']
            ring = {messaging.get('EncryptionKeyId','primary'): symmetric(found['messaging-key.txt'][2][2])}
            for key in messaging.get('DecryptionKeys',[]):
                ring[key['Id']] = symmetric(found['messaging-decrypt-'+key['Id']+'.txt'][2][2])
            rings[role] = ring
        if rings['worker'] != rings['gateway']:
            raise ValueError('complete Email role key rings must have identical IDs and decoded keys')
        mfa = captured.get('worker/mfa-key.txt')
        if mfa is not None: symmetric(mfa[2][2])
        prepared = {}
        for role, name in SIGNERS.items():
            source = captured.get('worker/'+name)
            if source is not None:
                raw = INPUTS.pem_blocks(source[2][2],{'PRIVATE KEY'},1)[0]
                prepared[role] = (raw, KEYS.rsa_private(raw))
        if signing_keys.keys() != prepared.keys():
            raise ValueError('exact configured Email signing key pin set required')
        # Every original role/key declaration and representation precedes native
        # calls, including the last prior key and optional disabled-role keys.
        native = INPUTS.NativeOpenSSL(stack,openssl_sha256)
        version = native.run(['version','-v']).decode('ascii').strip()
        if native.last_stderr or not re.fullmatch(r'OpenSSL 3\.[0-9]+\.[0-9]+[^\r\n]{0,180}',version):
            raise ValueError('OpenSSL 3 Email key checker required')
        signers = []
        for role, (raw, components) in prepared.items():
            confirmation = native.run(['pkey','-inform','DER','-passin','pass:','-check','-noout'],raw)
            if confirmation != b'Key is valid\n' or native.last_stderr:
                raise ValueError('native Email RSA key consistency confirmation refused')
            public = native.run(['pkey','-inform','DER','-passin','pass:','-pubout','-outform','DER'],raw)
            if native.last_stderr or KEYS.rsa_public(public) != components:
                raise ValueError('native Email RSA public components differ')
            digest = hashlib.sha256(public).hexdigest()
            if digest != signing_keys[role]:
                raise ValueError('Email signing key differs from explicit public pin')
            signers.append({'purpose':role,'source':'/etc/mk8.email/worker/'+SIGNERS[role],
                            'public_spki_sha256':digest,'modulus_bits':components[0].bit_length(),
                            'public_exponent':components[1], 'jwk_thumbprint_sha256':jwk_thumbprint(*components)})
        if PREFLIGHT.preflight(root_path,manifest,include_candidate=True) != before:
            raise ValueError('complete application plan changed during Email key checks')
        for parent,leaf,original,identity in (manifest_source,*captured.values()):
            fresh,_ = RELEASE.read_file(parent,leaf,INPUTS.INPUT_LIMIT,capture=True,expected=identity)
            if fresh != original: raise ValueError('original Email key source changed')
        if RELEASE.identity(os.fstat(root)) != root_identity:
            raise ValueError('Email key private root changed')
        RELEASE.check_links(links); native.check()
        result = {'scope':'PRIVATE APPLICATION EMAIL KEY PREFLIGHT','manifest_sha256':before['manifest_sha256'],
                  'publication_sha256':before['publication_sha256'],'software_sha256':before['software_sha256'],
                  'files':before['files'],'messaging_key_ids':sorted(rings['worker']),
                  'active_key_ids':{role:value['Messaging'].get('EncryptionKeyId','primary')
                                    for role,value in configurations.items()},
                  'mfa_key_checked':mfa is not None,'signing_keys':signers,
                  'sources':{name:{'bytes':row[2][0],'sha256':row[2][1],'identity':list(row[3])}
                             for name,row in captured.items()},
                  'openssl':{'path':INPUTS.OPENSSL,'sha256':openssl_sha256,'version':version,
                             'identity':list(RELEASE.identity(native.before)),'commands':native.commands},
                  'checks':{'complete_role_key_rings_match':True,'all_selected_key_representations_checked':True,
                            'all_selected_rsa_keys_consistent_and_pinned':True,'complete_plan_and_sources_reobserved':True},
                  'authority':{'key_intent_or_entropy_authenticated':False,'database_or_archive_key_coverage_proven':False,
                               'rotation_or_retirement_safe':False,'dotnet_or_mimekit_import_proven':False,
                               'oidc_tokens_or_dkim_signatures_created':False,'mfa_or_messaging_crypto_exercised':False,
                               'dkim_dns_or_oidc_trust_published':False,'vendor_crypto_authenticated':False,
                               'installed':False,'application_started':False,'network_or_gpu_changed':False,'server_ready':False},
                  'limits':['The full original key rings must agree by identifier and decoded 32-byte value; active IDs may differ during a declared rotation. This does not inspect existing DB, Blob or archive encryption-key references.',
                            'Canonical base64 with at most one LF and unencrypted two-prime PKCS8 RSA with 2048..8192-bit modulus/exponent 65537 are deliberately narrower than original importer syntax. No key contents are normalized on disk.',
                            'Caller SPKI fingerprints are explicit inputs, not authenticated key intent, entropy, revocation, DKIM selector DNS or OIDC issuer trust. An empty signing-key list proves no RSA role check.',
                            'Local OpenSSL input consistency is not original .NET/MimeKit execution, cryptographic messaging/MFA use, token or message signing, service startup, target or GPU work.',
                            'Private byte copies are not physical zeroization or hostile same-UID protection. Native dependency trust, sequential non-atomic observations, ordinary timeouts and historical validation gaps remain.']}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root','manifest','openssl-sha256'): parser.add_argument('--'+name,required=True)
    for name in SIGNERS: parser.add_argument('--'+name+'-public-key-sha256')
    args = parser.parse_args(argv)
    try:
        pins = {name:getattr(args,name+'_public_key_sha256') for name in SIGNERS
                if getattr(args,name+'_public_key_sha256') is not None}
        result = audit(args.root,args.manifest,args.openssl_sha256,pins)
        output = json.dumps(result,sort_keys=True,separators=(',',':'))
        if len(output)>1024*1024: raise ValueError('Email key receipt bound')
    except (OSError,ValueError,TypeError,AttributeError,KeyError,MemoryError,RecursionError,
            OverflowError,UnicodeError,subprocess.SubprocessError):
        print('Private Email key preflight refused',file=sys.stderr)
        return 75
    print(output)
    return 0


if __name__ == '__main__':
    sys.exit(main())

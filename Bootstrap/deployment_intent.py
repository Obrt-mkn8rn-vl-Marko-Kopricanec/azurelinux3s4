"""Describe or verify signed exact private deployment inputs without applying them.

The descriptor binds logical paths and bytes, not incidental developer inodes.
Original protected reads, whole release admission and fresh plans stay mandatory.
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
import time


ROOT = Path(__file__).resolve().parents[1]
DOMAIN = b'azurelinux3s4 deployment-intent attestation v1\n'
FIELDS = {'schema','purpose','intent_sha256','key_sha256','sequence','not_before','not_after'}


def module(name):
    spec = importlib.util.spec_from_file_location('deployment_intent_'+name,ROOT/'Bootstrap'/(name+'.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


PREFLIGHT = module('preflight')
ATTEST = module('release_attestation')
INPUTS = ATTEST.INPUTS
RELEASE = ATTEST.RELEASE


def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n').encode('ascii')


def commitment(row):
    if (type(row['bytes']) is not int or not 0 < row['bytes'] <= 1024*1024
            or type(row['sha256']) is not str or not re.fullmatch('[0-9a-f]{64}',row['sha256'])):
        raise ValueError('bounded complete intent byte commitment required')
    return {key:row[key] for key in ('bytes','sha256')}


def collect(private_root,manifest):
    apps = PREFLIGHT.preflight(private_root,manifest,include_candidate=True,include_sources=True)
    deployment = PREFLIGHT.preflight(private_root,manifest,'deployment',True,True)
    contract = RELEASE.contracts()
    candidate = apps['candidate']
    deployment_digest = hashlib.sha256(encoded(deployment['candidate'])[:-1]).hexdigest()
    if (apps['manifest_sha256'] != deployment['manifest_sha256']
            or apps['software_sha256'] != deployment['software_sha256']
            or candidate['deployment_candidate_sha256'] != deployment_digest):
        raise ValueError('application and deployment intent plans differ')
    sources = apps['protected_inputs']
    if (type(sources) is not list or not 1 <= len(sources) <= 1024
            or [row['file'] for row in sources] != sorted({row['file'] for row in sources})):
        raise ValueError('complete unique ordered protected input census required')
    observed = {}
    for row in sources:
        if type(row) is not dict or row.keys() != {'file','bytes','sha256','mode'} or row['mode'] != '0600':
            raise ValueError('exact private original input commitments required')
        contract['deployment_path'](row['file'])
        observed[row['file']] = commitment(row)
    if manifest not in observed or observed[manifest]['sha256'] != apps['manifest_sha256']:
        raise ValueError('original manifest missing from protected input census')
    if deployment['protected_inputs'] != [next(row for row in sources if row['file']==manifest)]:
        raise ValueError('fixed deployment original source census required')
    expected = {manifest: observed[manifest]}
    def add(path,row):
        bound = commitment(row)
        if path in expected and expected[path] != bound:
            raise ValueError('conflicting original input commitments')
        expected[path] = bound
    for row in candidate['configuration']:
        add(row['file'],row)
        if 'ipc_identity' in row:
            add(row['ipc_identity']['source'],row['ipc_identity'])
    for name in ('dns_credentials','email_credentials'):
        for role in candidate[name]:
            for row in role['inputs']: add(row['source'],row)
    if expected != observed:
        raise ValueError('protected source census differs from complete original application inputs')
    releases = []
    if [row['app'] for row in candidate['releases']] != list(contract['DEP_APPS']):
        raise ValueError('complete ordered release intent required')
    declared = deployment['candidate']['manifest']['releases']
    for row in candidate['releases']:
        app = row['app']; declaration = declared[app]
        if (row['declaration'] != declaration or row['manifest_sha256'] != declaration['manifest_sha256']
                or row['directory'] != '/opt/'+app+'/releases/'+declaration['commit']):
            raise ValueError('exact original release declaration required')
        releases.append({'application':app,**declaration})
    def payloads(plan,application):
        rows = plan['publication']['files']; actual = {row['file']:row for row in plan['files']}
        if len(actual) != len(plan['files']) or type(rows) is not list or not rows:
            raise ValueError('complete unique generated file census required')
        result = []
        for row in rows:
            stored = row['stored'] if application else row['file']
            if stored not in actual or commitment(row) != commitment(actual[stored]) or row['mode'] not in ('0600','0644','0755'):
                raise ValueError('generated intent payload differs from actual bytes')
            result.append({'file':row['file'],'stored':stored,'mode':row['mode'],**commitment(row)})
        if len({row['stored'] for row in result}) != len(result) or actual.keys() != {'manifest.json','candidate.json','publication.json',*(row['stored'] for row in result)}:
            raise ValueError('complete generated payload set required')
        return result
    intent = {'schema':1,'purpose':'azurelinux3s4-deployment-inputs','manifest_path':manifest,
              'software_sha256':apps['software_sha256'],'protected_inputs':sources,'releases':releases,
              'deployment_files':payloads(deployment,False),'application_files':payloads(apps,True)}
    raw = encoded(intent)
    if len(raw)>512*1024: raise ValueError('complete deployment intent bound')
    return {'intent':intent,'intent_bytes':len(raw),'intent_sha256':hashlib.sha256(raw).hexdigest(),
            'observations':{'application_publication_sha256':apps['publication_sha256'],
                            'deployment_publication_sha256':deployment['publication_sha256']}}


def envelope(raw,intent_sha256,key_sha256,minimum_sequence,current):
    if (type(raw) is not bytes or not 0<len(raw)<=16384 or not raw.endswith(b'\n')
            or any(byte!=10 and not 32<=byte<=126 for byte in raw)):
        raise ValueError('bounded canonical intent attestation required')
    value = json.loads(raw,object_pairs_hook=ATTEST.unique,parse_constant=ATTEST.constant)
    if type(value) is not dict or value.keys()!=FIELDS:
        raise ValueError('exact intent attestation fields required')
    expected = {'schema':1,'purpose':'azurelinux3s4-deployment-intent','intent_sha256':intent_sha256,'key_sha256':key_sha256}
    if any(type(value[name]) is not type(item) or value[name]!=item for name,item in expected.items()):
        raise ValueError('attestation differs from exact deployment intent or key')
    if (type(minimum_sequence) is not int or not 1<=minimum_sequence<2**63
            or type(current) is not int or not 946684800<=current<=4102444800
            or type(value['sequence']) is not int or not minimum_sequence<=value['sequence']<2**63
            or any(type(value[name]) is not int for name in ('not_before','not_after'))
            or not 946684800<=value['not_before']<value['not_after']<=4102444800
            or value['not_after']-value['not_before']>ATTEST.MAX_VALIDITY
            or not value['not_before']<=current<value['not_after']):
        raise ValueError('intent sequence or validity window refused')
    if encoded(value)!=raw: raise ValueError('intent attestation must already be canonical')
    return value


def describe(private_root,manifest):
    with contextlib.ExitStack() as stack:
        links=[]; root=RELEASE.anchor(stack,RELEASE.absolute(private_root),links)
        identity=RELEASE.identity(os.fstat(root)); before=collect(private_root,manifest)
        if collect(private_root,manifest)!=before or RELEASE.identity(os.fstat(root))!=identity:
            raise ValueError('deployment intent sources changed')
        RELEASE.check_links(links)
    return {'scope':'UNSIGNED PRIVATE DEPLOYMENT INTENT DESCRIPTION',**before,'signed':False,'server_ready':False}


def audit(private_root,manifest,attestation,signature,public_key,public_key_sha256,openssl_sha256,minimum_sequence,at=None):
    if type(public_key_sha256) is not str or not re.fullmatch('[0-9a-f]{64}',public_key_sha256):
        raise ValueError('explicit canonical deployment intent key pin required')
    current=int(time.time()) if at is None else at
    with contextlib.ExitStack() as stack:
        links=[]; root=RELEASE.anchor(stack,RELEASE.absolute(private_root),links)
        root_identity=RELEASE.identity(os.fstat(root)); before=collect(private_root,manifest)
        captured={name:INPUTS.private_input(stack,links,path) for name,path in
                  (('attestation',attestation),('signature',signature),('public_key',public_key))}
        raw=captured['attestation'][2][2]; signed=captured['signature'][2][2]; key=captured['public_key'][2][2]
        if len(key)!=44 or not key.startswith(ATTEST.ED25519_SPKI) or hashlib.sha256(key).hexdigest()!=public_key_sha256 or len(signed)!=64:
            raise ValueError('pinned Ed25519 key and detached intent signature required')
        selected=envelope(raw,before['intent_sha256'],public_key_sha256,minimum_sequence,current)
        native=INPUTS.NativeOpenSSL(stack,openssl_sha256)
        version=native.run(['version','-v']).decode('ascii').strip()
        if native.last_stderr or not re.fullmatch(r'OpenSSL 3\.[0-9]+\.[0-9]+[^\r\n]{0,180}',version):
            raise ValueError('OpenSSL 3 intent verifier required')
        message=DOMAIN+raw
        fds={name:INPUTS.sealed_input(stack,'deployment-intent-'+name,data) for name,data in
             (('key',key),('signature',signed),('message',message))}
        path=lambda name:'/proc/self/fd/'+str(fds[name])
        result=native.run(['pkeyutl','-verify','-pubin','-keyform','DER','-inkey',path('key'),'-rawin',
                           '-sigfile',path('signature'),'-in',path('message')],descriptors=tuple(fds.values()))
        if result!=b'Signature Verified Successfully\n' or native.last_stderr:
            raise ValueError('native deployment intent signature confirmation refused')
        if collect(private_root,manifest)!=before:
            raise ValueError('complete deployment intent changed during signature verification')
        for parent,leaf,original,identity in captured.values():
            fresh,_=RELEASE.read_file(parent,leaf,INPUTS.INPUT_LIMIT,capture=True,expected=identity)
            if fresh!=original: raise ValueError('original intent signature source changed')
        if RELEASE.identity(os.fstat(root))!=root_identity: raise ValueError('deployment intent private root changed')
        RELEASE.check_links(links); native.check()
        result={'scope':'PINNED-KEY PRIVATE DEPLOYMENT INTENT PREFLIGHT',**before,'attestation':selected,
                'evaluation_unix_seconds':current,'explicit_time_supplied':at is not None,'minimum_sequence':minimum_sequence,
                'signed_message_bytes':len(message),'signed_message_sha256':hashlib.sha256(message).hexdigest(),
                'sources':{name:{'bytes':row[2][0],'sha256':row[2][1],'identity':list(row[3])} for name,row in captured.items()},
                'openssl':{'path':INPUTS.OPENSSL,'sha256':openssl_sha256,'version':version,
                           'identity':list(RELEASE.identity(native.before)),'commands':native.commands},
                'checks':{'ed25519_signature_valid_for_pinned_key':True,'complete_protected_input_hashes_bound':True,
                          'complete_generated_files_and_release_declarations_bound':True,'originals_and_plans_reobserved':True},
                'authority':{'signer_identity_or_intent_authority_authenticated':False,'key_revocation_checked':False,
                             'clock_or_sequence_floor_authenticated':False,'rollback_floor_persisted':False,
                             'release_build_or_runtime_authenticated':False,'credential_semantics_or_use_proven':False,
                             'signed_or_published':False,'installed':False,'application_started':False,
                             'network_or_gpu_changed':False,'server_ready':False},
                'limits':['The signature binds exact original protected configuration and nested credential hashes, four admitted release manifest declarations, both software artifacts and complete generated payload commitments. It does not select or authorize the caller key, clock or sequence floor.',
                          'Logical paths and byte/mode commitments are portable across qualified developer copies; incidental inode/UID/timestamps are outside the signed descriptor. Live complete publication observations still must match before and after within this invocation.',
                          'Only inputs consumed by the fixed shipped plan are covered. Future environment/NSS/drop-ins, DB/Blob/state/archive contents, service behavior and actual native credential use remain separate obligations.',
                          'No private key is accepted, signature created, input rewritten, rollback floor advanced, network request made or host/service/GPU action supplied. Native dependency trust, ordinary timeouts and sequential non-atomic observations retain their limits.']}
    return result


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('root','manifest'): parser.add_argument('--'+name,required=True)
    parser.add_argument('--describe',action='store_true')
    for name in ('attestation','signature','public-key','public-key-sha256','openssl-sha256'):
        parser.add_argument('--'+name)
    parser.add_argument('--minimum-sequence',type=int); parser.add_argument('--at',type=int)
    args=parser.parse_args(argv)
    try:
        supplied=[args.attestation,args.signature,args.public_key,args.public_key_sha256,args.openssl_sha256,args.minimum_sequence]
        if args.describe:
            if any(value is not None for value in supplied) or args.at is not None:
                raise ValueError('description accepts no verification options')
            result=describe(args.root,args.manifest)
        else:
            if any(value is None for value in supplied): raise ValueError('complete explicit intent verification inputs required')
            result=audit(args.root,args.manifest,*supplied,args.at)
        output=json.dumps(result,sort_keys=True,separators=(',',':'))
        if len(output)>1024*1024: raise ValueError('deployment intent receipt bound')
    except (OSError,ValueError,TypeError,AttributeError,KeyError,MemoryError,RecursionError,
            OverflowError,UnicodeError,subprocess.SubprocessError):
        print('Private deployment intent refused',file=sys.stderr)
        return 75
    print(output)
    return 0


if __name__=='__main__':
    sys.exit(main())

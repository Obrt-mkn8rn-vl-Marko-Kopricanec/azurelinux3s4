"""Bounded dynamic symbol/VERSYM DATA and explicit-provider availability.

The conservative profile requires a complete section table as well as matching
dynamic tags. It does not implement hash lookup, relocation or loader scope.
"""

import hashlib
import importlib.util
from pathlib import Path
import struct


TAGS = {6, 11, 0x6ffffff0}
SYMBOL_LIMIT = 65536
TOTAL_LIMIT = 131072
SECTION_LIMIT = 8192
HASH_SPEC = importlib.util.spec_from_file_location('elf_symbol_hashes', Path(__file__).with_name('elf_hashes.py'))
HASHES = importlib.util.module_from_spec(HASH_SPEC)
HASH_SPEC.loader.exec_module(HASHES)


def declarations(data,tags,strings,file_offset,text_at,requirements,definitions,hashes=False):
    if (len(tags.get(6,[]))!=1 or tags.get(11)!=[24] or len(tags.get(0x6ffffff0,[]))>1):
        raise ValueError('complete unique ELF dynamic symbol tags required')
    header=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
    start,entry_size,count,names=header[6],header[11],header[12],header[13]
    if (entry_size!=64 or not 1<=count<=SECTION_LIMIT or start<64 or start>len(data)
            or count*64>len(data)-start or not 0<=names<count):
        raise ValueError('bounded complete nonextended ELF section headers required for symbols')
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,start+index*64) for index in range(count)]
    if any(sections[0]): raise ValueError('canonical empty section zero required')
    tables=[row for row in sections if row[1]==11]
    if len(tables)!=1: raise ValueError('one exact dynamic symbol section required')
    table=tables[0]
    _,_,flags,address,offset,size,link,local_count,align,stride=table
    if (flags!=2 or address!=tags[6][0] or address%8 or offset%8 or align!=8 or stride!=24
            or size%24 or not 1<=size//24<=SYMBOL_LIMIT or not 0<link<count
            or not 1<=local_count<=size//24 or file_offset(address,size)!=offset):
        raise ValueError('dynamic symbol section and tag correspondence required')
    symbol_count=size//24; names_section=sections[link]
    if (names_section[1:6]!=(3,2,tags[5][0],file_offset(tags[5][0],len(strings)),len(strings))
            or names_section[8:]!=(1,0)):
        raise ValueError('exact linked dynamic string section required')
    ranges=[(start,start+count*64),(offset,offset+size),
            (names_section[4],names_section[4]+len(strings))]
    versions={}
    for kind,rows in (('definition',definitions),('requirement',
            [{**row,'library':group['library']} for group in requirements for row in group['versions']])):
        for row in rows:
            index=row['index']
            if (not 1<=index<0x8000 or index in versions
                    or kind=='requirement' and index<2
                    or kind=='definition' and index==1 and not row['base']):
                raise ValueError('unique supported GNU symbol version indices required')
            versions[index]={'kind':kind,**{name:row[name] for name in ('name','hash')}}
            if kind=='requirement':versions[index]['library']=row['library']
    version_bytes=None
    if 0x6ffffff0 in tags:
        if tags[0x6ffffff0][0]%2:raise ValueError('aligned dynamic symbol versions required')
        version_start=file_offset(tags[0x6ffffff0][0],symbol_count*2)
        version_bytes=data[version_start:version_start+symbol_count*2]
        ranges.append((version_start,version_start+symbol_count*2))
        numbers=struct.unpack('<'+'H'*symbol_count,version_bytes)
    elif versions:
        raise ValueError('declared versions require a complete VERSYM table')
    else:
        numbers=tuple(0 if index<local_count else 1 for index in range(symbol_count))
    ranges.sort()
    if any(left[1]>right[0] for left,right in zip(ranges,ranges[1:])):
        raise ValueError('nonoverlapping symbol, string, version and section tables required')
    symbols=[]; byte_budget=0
    for index in range(symbol_count):
        name,info,other,section,value,length=struct.unpack_from('<IBBHQQ',data,offset+index*24)
        binding,kind=info>>4,info&15
        if index==0 and ((name,info,other,section,value,length)!=(0,0,0,0,0,0) or numbers[0]!=0):
            raise ValueError('canonical undefined dynamic symbol zero required')
        if (binding not in (0,1,2,10) or kind not in (0,1,2,3,4,5,6,10) or other not in (0,1,2,3)
                or (index<local_count)!=(binding==0)
                or not (section<count or section==0xfff1)
                or binding==0 and other==3
                or kind in (3,4) and binding!=0
                or kind==3 and not 0<section<count
                or kind==4 and section!=0xfff1):
            raise ValueError('supported binding/type/visibility/section symbol declarations required')
        label=text_at(strings,name); version_index=numbers[index]&0x7fff; hidden=bool(numbers[index]&0x8000)
        if index and (binding!=0 and not label or section==0 and (binding not in (1,2) or other!=0)):
            raise ValueError('named global/weak default-visibility undefined symbols required')
        if (binding==0 and numbers[index]!=0 or hidden and version_index<=1
                or section==0 and index and version_index==0
                or version_index>1 and version_index not in versions):
            raise ValueError('complete supported per-symbol version association required')
        version=versions.get(version_index) if version_index>1 else None
        if section==0 and version is not None and version['kind']!='requirement':
            raise ValueError('undefined symbol must reference an explicit required version')
        byte_budget+=len(label)+200
        if byte_budget>8*1024*1024:raise ValueError('dynamic symbol declaration byte bound')
        symbols.append({'index':index,'name':label,'binding':binding,'type':kind,'visibility':other,
                        'section':section,'value':value,'size':length,'version_index':version_index,
                        'version_hidden':hidden,'version':version})
    result={'count':symbol_count,'local_count':local_count,
            'table_sha256':hashlib.sha256(data[offset:offset+size]).hexdigest(),
            'versym_sha256':None if version_bytes is None else hashlib.sha256(version_bytes).hexdigest(),
            'symbols':symbols}
    if hashes:
        result['hash_tables']=HASHES.inspect(data,tags,sections,sections.index(table),ranges,symbols,
            {symbol['index'] for symbol in symbols if exported(symbol)},file_offset)
    return result


def exported(symbol):
    return (symbol['section']!=0 and symbol['binding'] in (1,2,10) and symbol['visibility'] in (0,3)
            and symbol['type'] in (0,1,2,5,6,10)
            and (symbol['value']!=0 or symbol['section']==0xfff1 or symbol['type']==6)
            and symbol['version_index']!=0
            and (symbol['version'] is None or symbol['version']['kind']=='definition'))


def compatible(required,provided):
    if required==6 or provided==6:return required==provided
    if required==0:return provided in (0,1,2,5,10)
    if required in (2,10):return provided in (2,10)
    if required in (1,5):return provided in (1,5)
    return required==provided


def availability(roles,release_objects,provider_objects,bindings):
    all_objects={('release',name):value for name,value in release_objects.items()}
    all_objects.update({('providers',name):value for name,value in provider_objects.items()})
    result=[]; total=0; comparisons=0
    for role in roles:
        selected=[(row['source'],row['path']) for row in role['objects']]
        exports={}; requirements=[]
        for source,path in selected:
            table=all_objects[(source,path)]['dynamic_symbols'];total+=table['count']
            if total>TOTAL_LIMIT:raise ValueError('aggregate symbol declaration count bound')
            for symbol in table['symbols']:
                if symbol['index']==0:continue
                if symbol['section']==0:
                    requirements.append((source,path,symbol));continue
                if not exported(symbol):
                    continue
                exports.setdefault(symbol['name'],[]).append((source,path,symbol))
        rows=[]
        for source,path,symbol in requirements:
            version=symbol['version'];matches=[]
            bound=None
            if version is not None:
                bound=bindings[role['role']].get(version['library'])
                if bound is None:raise ValueError('versioned symbol requires explicit library binding')
            for target_source,target_path,provided in exports.get(symbol['name'],[]):
                comparisons+=1
                if comparisons>1024*1024:raise ValueError('symbol comparison work bound')
                if not compatible(symbol['type'],provided['type']):continue
                supplied_version=provided['version']
                if version is not None:
                    if (target_source!=bound['source'] or target_path!=bound['path'] or supplied_version is None
                            or supplied_version['name']!=version['name'] or supplied_version['hash']!=version['hash']):continue
                elif supplied_version is not None and provided['version_hidden']:
                    continue
                matches.append({'source':target_source,'path':target_path,'symbol_index':provided['index'],
                                'type':provided['type'],'binding':provided['binding']})
                if len(matches)>128:raise ValueError('symbol candidate multiplicity bound')
            weak=symbol['binding']==2
            if not matches and not weak:
                raise ValueError('missing strong declared symbol candidate: '+role['role']+'/'+symbol['name'])
            rows.append({'object_source':source,'object':path,'symbol_index':symbol['index'],'name':symbol['name'],
                         'type':symbol['type'],'weak':weak,'version':version,'candidates':matches,
                         'definition_available':bool(matches)})
        result.append({'role':role['role'],'requirements':rows,
                       'missing_weak_symbols':sum(not row['definition_available'] for row in rows)})
    return result

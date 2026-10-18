"""Bounded x86-64 RELA/RELR declarations and initial write ranges, never applied."""

import hashlib
import struct


TAGS = {2,7,8,9,20,23,30,35,36,37,0x6ffffff9}
UNSUPPORTED = {17,18,19,22,0x6ffffffa,0x6000000f,0x60000010,0x60000011,0x60000012,
               0x6fffe000,0x6fffe001,0x6fffe003}
ENTRY_LIMIT = 131072
RELR_WORD_LIMIT = 65536
UINT64 = 1 << 64
TYPES = {0:('NONE',0),1:('64',8),2:('PC32',4),6:('GLOB_DAT',8),7:('JUMP_SLOT',8),
         8:('RELATIVE',8),10:('32',4),11:('32S',4),16:('DTPMOD64',8),17:('DTPOFF64',8),
         18:('TPOFF64',8),32:('SIZE32',4),33:('SIZE64',8),36:('TLSDESC',16),
         37:('IRELATIVE',8),38:('RELATIVE64',8)}


def declarations(data,tags,file_offset,loads,symbols):
    if UNSUPPORTED.intersection(tags) or any(len(tags.get(tag,[]))>1 for tag in TAGS):
        raise ValueError('unique supported RELA/RELR declarations without REL/text relocations required')
    flags=tags.get(30,[0])[0]
    if flags&4:raise ValueError('declared text relocations are outside the writable-data profile')
    tables=[];records=[];ranges=[];destinations=[]

    def mapped(address,size):
        if not 0<=address<UINT64 or not 0<size<=UINT64-address:
            raise ValueError('bounded relocation virtual range required')
        matches=[row for row in loads if row['address']<=address
                 and address+size<=row['address']+row['memory']]
        if len(matches)!=1:raise ValueError('relocation range must map to one initial load segment')
        return matches[0]

    def destination(address,size):
        row=mapped(address,size)
        if not row['flags']&2 or row['flags']&1:
            raise ValueError('relocation destination must be initially writable and nonexecutable')
        destinations.append((address,address+size))
        return row

    def table(kind,address,size,stride,limit):
        if size%stride or size//stride>limit or (size==0)!=(address==0):
            raise ValueError('complete bounded relocation table dimensions required')
        start=file_offset(address,size) if size else 0
        if size and (address%8 or start%8):raise ValueError('aligned relocation table required')
        raw=data[start:start+size]
        if size:ranges.append((start,start+size))
        tables.append({'kind':kind,'virtual_address':address,'bytes':size,'entries':size//stride,
                       'sha256':hashlib.sha256(raw).hexdigest()})
        return raw

    def append(row):
        if len(records)>=ENTRY_LIMIT:raise ValueError('expanded relocation count bound')
        records.append(row)

    groups=[]
    if 7 in tags or 8 in tags:
        if not {7,8,9}<=tags.keys() or tags[9]!=[24]:
            raise ValueError('complete RELA address, size and exact entry width required')
        groups.append(('rela',table('rela',tags[7][0],tags[8][0],24,ENTRY_LIMIT)))
    if {2,20,23}.intersection(tags):
        if not {2,20,23}<=tags.keys() or tags[20]!=[7]:
            raise ValueError('complete RELA-only PLT declaration required')
        groups.append(('plt',table('plt',tags[23][0],tags[2][0],24,ENTRY_LIMIT)))
    if 9 in tags and (tags[9]!=[24] or not groups):
        raise ValueError('RELA entry width requires an actual RELA declaration')
    relative_count=tags.get(0x6ffffff9,[0])[0]
    if 0x6ffffff9 in tags and (7 not in tags or relative_count>tags[8][0]//24):
        raise ValueError('RELACOUNT must fit the complete ordinary RELA table')
    for group,raw in groups:
        for ordinal,(address,info,addend) in enumerate(struct.iter_unpack('<QQq',raw)):
            index,kind=info>>32,info&0xffffffff
            if kind not in TYPES or index>=len(symbols):
                raise ValueError('supported relocation type and complete symbol index required')
            if group=='plt' and kind not in (0,7,36,37):
                raise ValueError('supported PLT relocation type required')
            if group=='rela' and ordinal<relative_count and (kind!=8 or index!=0):
                raise ValueError('RELACOUNT prefix must contain only symbol-free RELATIVE records')
            label,width=TYPES[kind]
            if kind==0:
                if address or index or addend:raise ValueError('canonical empty NONE relocation required')
            else:
                destination(address,width)
                if kind in (8,37,38):
                    if index:raise ValueError('relative relocation must not reference a symbol')
                elif kind in (16,17,18,36):
                    if (index==0 and kind!=16) or index and symbols[index]['type']!=6:
                        raise ValueError('TLS relocation must bind a TLS declaration or local module')
                elif index==0 or symbols[index]['type'] not in (0,1,2,5,10):
                    raise ValueError('ordinary relocation must bind a code/data symbol declaration')
                if kind in (6,7) and addend:
                    raise ValueError('canonical zero GLOB_DAT/JUMP_SLOT addend required')
                if kind==37:
                    resolver=mapped(addend,1)
                    if not resolver['flags']&1 or resolver['flags']&2:
                        raise ValueError('IRELATIVE resolver declaration must name initial nonwritable executable memory')
            append({'table':group,'ordinal':ordinal,'address':address,'bytes':width,
                    'type':'R_X86_64_'+label,'symbol_index':index,
                    'symbol':symbols[index]['name'] if index else None,'addend':addend})
    if {35,36,37}.intersection(tags):
        if not {35,36,37}<=tags.keys() or tags[37]!=[8]:
            raise ValueError('complete RELR address, size and exact word width required')
        raw=table('relr',tags[36][0],tags[35][0],8,RELR_WORD_LIMIT)
        where=None;previous=-1
        for ordinal,(entry,) in enumerate(struct.iter_unpack('<Q',raw)):
            if entry&1:
                if where is None or where>UINT64-63*8:
                    raise ValueError('RELR bitmap requires a bounded preceding address')
                addresses=[where+(bit-1)*8 for bit in range(1,64) if entry&(1<<bit)]
                where+=63*8
            else:
                addresses=[entry];where=entry+8
            for address in addresses:
                if address<=previous:raise ValueError('strictly increasing unique RELR destinations required')
                previous=address;load=destination(address,8)
                delta=address-load['address'];available=min(8,max(0,load['bytes']-delta))
                start=load['offset']+delta
                initial=data[start:start+available]+b'\0'*(8-available)
                append({'table':'relr','ordinal':ordinal,'address':address,'bytes':8,
                        'type':'R_X86_64_RELATIVE_PACKED','symbol_index':0,'symbol':None,
                        'initial_word':int.from_bytes(initial,'little')})
    ranges.sort();destinations.sort()
    if any(left[1]>right[0] for left,right in zip(ranges,ranges[1:])):
        raise ValueError('separate nonoverlapping relocation tables required')
    if any(left[1]>right[0] for left,right in zip(destinations,destinations[1:])):
        raise ValueError('nonoverlapping relocation write ranges required; composition unsupported')
    return {'tables':tables,'records':records,'count':len(records),'relative_prefix_count':relative_count,
            'dynamic_flags':flags,'writes':len(destinations),'applied':False,
            'limits':'Initial mapped write ranges and typed references only; no relocated values, overflow, TLS layout, resolver/CPU/ABI behavior or runtime binding proven.'}

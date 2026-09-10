#!/usr/bin/env python3
"""Target-agnostic Rijndael-256 ECB/CBC known-window scanner."""
from __future__ import annotations
import hashlib
BS=32
A105={9,10,13}|set(range(32,127))|{0xE2,0x80,0x93,0x94,0x98,0x99,0xA6}
P3={0x93,0x94,0x98,0x99,0xA6}
INITIAL=(0,1,2); TERMINAL=(0,1,2)

def step(state:int,value:int)->int|None:
    if state==0:
        if value in {9,10,13} or 32<=value<=126:return 0
        if value==0xE2:return 1
        return None
    if state==1:return 2 if value==0x80 else None
    if state==2:return 0 if value in P3 else None
    raise AssertionError(state)

def classify(data:bytes)->dict:
    states=set(INITIAL)
    for i,value in enumerate(data):
        if value not in A105:
            return {'classification':'rejected_a105','accepted':False,'ending_states':[],
              'witness':{'offset':i,'byte':value,'reason':'outside A105'}}
        following={n for state in states if (n:=step(state,value)) is not None}
        if not following:
            return {'classification':'rejected_fsa_transition','accepted':False,'ending_states':[],
              'witness':{'offset':i,'byte':value,'prior_states':sorted(states),'reason':'no five-sequence FSA transition'}}
        states=following
    accepted=bool(states & set(TERMINAL))
    assert accepted
    return {'classification':'retained','accepted':True,'ending_states':sorted(states),'witness':None}

def decode_window(stream:bytes,offset:int,mode:str,decrypt_block)->tuple[bytes,list[bytes],bytes]:
    if mode=='ecb':
        raw=stream[offset:offset+64]; assert len(raw)==64
        blocks=[decrypt_block(raw[:32]),decrypt_block(raw[32:])]
        return blocks[0]+blocks[1],blocks,raw
    if mode=='cbc':
        raw=stream[offset:offset+96]; assert len(raw)==96
        c0,c1,c2=raw[:32],raw[32:64],raw[64:]
        blocks=[bytes(x^y for x,y in zip(decrypt_block(c1),c0)),bytes(x^y for x,y in zip(decrypt_block(c2),c1))]
        return blocks[0]+blocks[1],blocks,raw
    raise ValueError(mode)

def scan(stream:bytes,mode:str,decrypt_block,collect_all:bool=False)->dict:
    assert len(stream)==546
    window=64 if mode=='ecb' else 96 if mode=='cbc' else 0
    assert window
    retained=[]; all_rows=[]; counts={'rejected_a105':0,'rejected_fsa_transition':0,'retained':0}; examples=[]
    for offset in range(len(stream)-window+1):
        plain,blocks,raw=decode_window(stream,offset,mode,decrypt_block)
        endpoint=classify(plain); counts[endpoint['classification']]+=1
        row={'offset':offset,'input_window_sha256':hashlib.sha256(raw).hexdigest(),
          'plaintext_hex':plain.hex(),'decrypted_blocks_hex':[x.hex() for x in blocks],**endpoint}
        if collect_all: all_rows.append(row)
        if endpoint['accepted']:retained.append(row)
        elif len(examples)<3:examples.append(row)
    result={'mode':mode,'stream_bytes':len(stream),'window_bytes':window,'tested_offsets':len(stream)-window+1,
      'class_counts':counts,'retained':retained,'first_rejections':examples}
    if collect_all: result['rows']=all_rows
    return result

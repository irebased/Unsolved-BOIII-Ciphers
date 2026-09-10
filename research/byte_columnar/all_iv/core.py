#!/usr/bin/env python3
"""All-IV necessary-prefix predicate for rectangular variant-B byte columns."""
from __future__ import annotations
import hashlib
from Crypto.Cipher import AES

IDENTITY="ASTRA"
KEY=b"Zombies"+bytes(9)
BLOCK_SIZE=16
PUNCT3={0x93,0x94,0x98,0x99,0xA6}

def fsa_step(state:int,value:int)->int|None:
    if state==0:
        if value in {9,10,13} or 32<=value<=126: return 0
        if value==0xE2: return 1
        return None
    if state==1: return 2 if value==0x80 else None
    if state==2: return 0 if value in PUNCT3 else None
    raise AssertionError(state)

def propagate(states:set[int],data:bytes)->set[int]:
    current=set(states)
    for value in data:
        following=set()
        for state in current:
            next_state=fsa_step(state,value)
            if next_state is not None: following.add(next_state)
        current=following
        if not current: break
    return current

def cfb8_decrypt(ciphertext:bytes,iv:bytes)->bytes:
    assert len(iv)==BLOCK_SIZE
    return AES.new(KEY,AES.MODE_CFB,iv=iv,segment_size=8).decrypt(ciphertext)

def iv_independent_suffix(ciphertext_prefix:bytes)->bytes:
    """Decrypt positions >=16 directly from their ciphertext-only registers."""
    assert len(ciphertext_prefix)>=BLOCK_SIZE
    ecb=AES.new(KEY,AES.MODE_ECB)
    out=bytearray()
    for i in range(BLOCK_SIZE,len(ciphertext_prefix)):
        out.append(ciphertext_prefix[i]^ecb.encrypt(ciphertext_prefix[i-BLOCK_SIZE:i])[0])
    return bytes(out)

def exposed_first_column(observed:bytes,width:int,rank:int)->bytes:
    assert width in (13,14) and len(observed)==546 and len(observed)%width==0
    assert 0<=rank<width
    return observed[rank::width]

def evaluate(observed:bytes,width:int)->dict:
    rows=len(observed)//width
    assert rows in (39,42)
    tested=[]
    rejected=[]
    retained=[]
    for rank in range(width):
        chunk=exposed_first_column(observed,width,rank)
        assert len(chunk)==rows
        suffix=iv_independent_suffix(chunk)
        end_states=sorted(propagate({0,1,2},suffix))
        row={"observed_rank":rank,"chunk_sha256":hashlib.sha256(chunk).hexdigest(),
             "suffix_sha256":hashlib.sha256(suffix).hexdigest(),
             "suffix_bytes":len(suffix),"end_state_set":end_states,
             "necessary_prefix_retained":bool(end_states)}
        tested.append(row)
        (retained if end_states else rejected).append(rank)
    weight_per_rejected=1
    for x in range(2,width): weight_per_rejected*=x
    rejected_weight=len(rejected)*weight_per_rejected
    expected=weight_per_rejected*width
    return {"identity":IDENTITY,"width":width,"rows":rows,
      "tested_first_column_ranks":tested,"rejected_ranks":rejected,
      "retained_ranks":retained,"weight_per_rejected_rank":weight_per_rejected,
      "rejected_completion_weight":rejected_weight,
      "expected_completion_weight":expected,
      "complete_every_iv_exclusion":rejected_weight==expected,
      "claim":"retained ranks are unresolved first-column classes, not plaintext or full-permutation survivors"}

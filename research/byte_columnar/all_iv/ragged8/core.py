#!/usr/bin/env python3
"""Eight-byte-block ragged-B all-IV necessary-prefix predicate."""
import hashlib,importlib.util,math
from functools import lru_cache
from pathlib import Path
from Crypto.Cipher import Blowfish,DES
IDENTITY="ASTRA";BS=8
KEYS={"des":b"Zombies\0","blowfish":b"Zombies","blowfish_compat":b"Zombies"}
P3={0x93,0x94,0x98,0x99,0xA6}
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
COMPAT=ROOT/"research/rev7-20260909-codex/hex_cfb/native_compat"
def word_reverse(x):return x[3::-1]+x[7:3:-1]
@lru_cache(None)
def _compat():
    spec=importlib.util.spec_from_file_location("astra_source_check",COMPAT/"source_check.py")
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
    fn,size=mod.load_algorithm(COMPAT/"source_build/libblowfish_compat.so","blowfish_compat")
    assert size>0
    return fn
def block(cipher,value):
    assert len(value)==BS
    if cipher=="des":return DES.new(KEYS[cipher],DES.MODE_ECB).encrypt(value)
    if cipher=="blowfish":return Blowfish.new(KEYS[cipher],Blowfish.MODE_ECB).encrypt(value)
    if cipher=="blowfish_compat":return _compat()(KEYS[cipher],value)
    raise ValueError(cipher)
def cfb8(data,cipher,iv,decrypt):
    assert len(iv)==BS
    reg=iv;out=bytearray()
    for b in data:
        v=b^block(cipher,reg)[0];ct=b if decrypt else v
        out.append(v);reg=reg[1:]+bytes([ct])
    return bytes(out)
def step(s,b):
    if s==0:
        if b in {9,10,13} or 32<=b<=126:return 0
        return 1 if b==0xe2 else None
    if s==1:return 2 if b==0x80 else None
    if s==2:return 0 if b in P3 else None
    raise AssertionError
def prefix(observed,w,rank):
    if not 2<=w<=len(observed) or not 0<=rank<w:raise ValueError
    q=len(observed)//w;return bytes(observed[rank:q*w:w])
def suffix(p,cipher):
    if len(p)<BS:raise ValueError
    return bytes(p[i]^block(cipher,p[i-BS:i])[0] for i in range(BS,len(p)))
def inspect(observed,w,rank,cipher):
    q,r=divmod(len(observed),w);p=prefix(observed,w,rank)
    row={"rank":rank,"slice":{"start":rank,"stop":q*w,"stride":w},
      "prefix_hex":p.hex(),"prefix_sha256":hashlib.sha256(p).hexdigest(),"prefix_bytes":q}
    if q<=BS:return row|{"supported":False,"reason":"floor(n/w) <= 8; no IV-independent byte"}
    tail=suffix(p,cipher);states={0,1,2};fail=None
    for off,b in enumerate(tail):
        before=sorted(states);states={v for s in states if (v:=step(s,b)) is not None}
        if not states:
            fail={"suffix_offset":off,"chunk_plaintext_offset":BS+off,
              "plaintext_byte":b,"states_before":before,"states_after":[]};break
    return row|{"supported":True,"suffix_hex":tail.hex(),
      "suffix_sha256":hashlib.sha256(tail).hexdigest(),"suffix_bytes":len(tail),
      "end_states":sorted(states),"rejected":not states,"first_failure":fail}
def evaluate(observed,w,cipher,stop=True):
    q,r=divmod(len(observed),w)
    base={"identity":IDENTITY,"cipher":cipher,"n":len(observed),"width":w,"q":q,"r":r,
      "conventions":["first","last"],"conventions_alias":r==0,
      "chunk_start_states":[0,1,2],"terminal_zero_required":False}
    if q<=BS:return base|{"supported":False,"ranks_examined":0,"rejected_rank":None,
      "complete_every_iv_every_order_exclusion":False,"unresolved":True,
      "reason":"no guaranteed IV-independent suffix"}
    rows=[];bad=None
    for rank in range(w):
        x=inspect(observed,w,rank,cipher);rows.append(x)
        if x["rejected"]:
            bad=rank
            if stop:break
    closed=bad is not None
    return base|{"supported":True,"ranks_examined":len(rows),"inspected":rows,
      "rejected_rank":bad,"completion_weight_per_convention":math.factorial(w) if closed else 0,
      "complete_every_iv_every_order_exclusion":closed,"unresolved":not closed}

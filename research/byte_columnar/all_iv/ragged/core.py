#!/usr/bin/env python3
"""All-IV necessary predicate using ragged-B guaranteed full rows."""
import hashlib,math
from Crypto.Cipher import AES
IDENTITY="ASTRA"; KEY=b"Zombies"+bytes(9); BS=16
PUNCT3={0x93,0x94,0x98,0x99,0xA6}
def step(s,b):
    if s==0:
        if b in {9,10,13} or 32<=b<=126:return 0
        return 1 if b==0xe2 else None
    if s==1:return 2 if b==0x80 else None
    if s==2:return 0 if b in PUNCT3 else None
    raise AssertionError(s)
def propagate(states,data):
    states=set(states)
    for b in data:
        states={v for s in states if (v:=step(s,b)) is not None}
        if not states:break
    return states
def prefix(observed,w,rank):
    if not 2<=w<=len(observed) or not 0<=rank<w:raise ValueError
    q=len(observed)//w
    return observed[rank:q*w:w]
def suffix(p):
    if len(p)<BS:raise ValueError
    e=AES.new(KEY,AES.MODE_ECB)
    return bytes(p[i]^e.encrypt(p[i-BS:i])[0] for i in range(BS,len(p)))
def inspect(observed,w,rank):
    q,r=divmod(len(observed),w); p=prefix(observed,w,rank)
    row={"rank":rank,"slice":{"start":rank,"stop":q*w,"stride":w},
      "prefix_hex":p.hex(),"prefix_sha256":hashlib.sha256(p).hexdigest(),"prefix_bytes":q}
    if q<=BS:
        return row|{"supported":False,"reason":"floor(n/w) <= 16; no IV-independent byte"}
    tail=suffix(p); states={0,1,2}; fail=None
    for off,b in enumerate(tail):
        after={v for s in states if (v:=step(s,b)) is not None}
        if not after:
            fail={"suffix_offset":off,"chunk_plaintext_offset":BS+off,
                  "plaintext_byte":b,"states_before":sorted(states),"states_after":[]}
            states=set();break
        states=after
    return row|{"supported":True,"suffix_hex":tail.hex(),
      "suffix_sha256":hashlib.sha256(tail).hexdigest(),"suffix_bytes":len(tail),
      "end_states":sorted(states),"rejected":not states,"first_failure":fail}
def evaluate(observed,w,stop_after_first_bad=True):
    q,r=divmod(len(observed),w)
    base={"identity":IDENTITY,"n":len(observed),"width":w,"q":q,"r":r,
      "conventions":["first","last"],"conventions_alias":r==0,
      "chunk_start_states":[0,1,2],"terminal_zero_required":False}
    if q<=BS:
        return base|{"supported":False,"ranks_examined":0,"rejected_rank":None,
          "complete_every_iv_every_order_exclusion":False,"unresolved":True,
          "reason":"no guaranteed IV-independent suffix"}
    rows=[];bad=None
    for rank in range(w):
        x=inspect(observed,w,rank);rows.append(x)
        if x["rejected"]:
            bad=rank
            if stop_after_first_bad:break
    closed=bad is not None
    return base|{"supported":True,"ranks_examined":len(rows),"inspected":rows,
      "rejected_rank":bad,"completion_weight_per_convention":math.factorial(w) if closed else 0,
      "complete_every_iv_every_order_exclusion":closed,"unresolved":not closed,
      "claim":("one unavoidable bad chunk excludes every order and every external IV"
               if closed else "all examined prefixes retained; unresolved")}

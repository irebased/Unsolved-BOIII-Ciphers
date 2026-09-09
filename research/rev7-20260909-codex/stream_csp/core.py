#!/usr/bin/env python3
"""Synthetic-only exact CSP for a global hexadecimal-symbol bijection."""
from __future__ import annotations
import hashlib,itertools,math
from dataclasses import dataclass,asdict
from Crypto.Cipher import AES,Blowfish,DES

HEX="0123456789ABCDEF"
RELAXED={9,10,13}|set(range(32,127))|{0xE2,0x80,0x93,0x94,0x98,0x99}

def specs():
 return {"aes128":(AES,b"Zombies".ljust(16,b"\0")),"blowfish":(Blowfish,b"Zombies"),"des":(DES,b"Zombies".ljust(8,b"\0"))}
def ivs(block):
 raw=b"Zombies"
 return {"ascii_zero":b"0"*block,"nul":b"\0"*block,"sha1_prefix":hashlib.sha1(raw).digest()[:block]}
def keystream(cipher,mode,iv,n):
 mod,key=specs()[cipher];ecb=mod.new(key,mod.MODE_ECB);reg=iv;out=bytearray()
 if mode=="ofb8":
  for _ in range(n):
   k=ecb.encrypt(reg)[0];out.append(k);reg=reg[1:]+bytes([k])
 elif mode=="fullblock_ofb":
  while len(out)<n: reg=ecb.encrypt(reg);out.extend(reg)
 else: raise ValueError(mode)
 return bytes(out[:n])
def display_encode(ct,mapping):
 inv=[0]*16
 for d,a in enumerate(mapping):inv[a]=d
 return "".join(HEX[inv[n]] for b in ct for n in (b>>4,b&15))
def decode(display,mapping):
 return bytes((mapping[HEX.index(display[i])]<<4)|mapping[HEX.index(display[i+1])] for i in range(0,len(display),2))
def valid_fsa(data):
 state=0
 for b in data:
  if state==0:
   if b in {9,10,13} or 32<=b<=126:continue
   if b==0xE2:state=1;continue
   return False
  if state==1:
   if b==0x80:state=2;continue
   return False
  if b in (0x93,0x94,0x98,0x99):state=0;continue
  return False
 return state==0

def relations(display,ks):
 rel={}
 for i,k in enumerate(ks):
  h=HEX.index(display[2*i]);l=HEX.index(display[2*i+1]);key=(h,l)
  allowed={(a,b) for a in range(16) for b in range(16)
           if (a==b if h==l else a!=b) and (((a<<4)|b)^k) in RELAXED}
  rel[key]=allowed if key not in rel else rel[key]&allowed
 return rel

@dataclass
class Stats:
 nodes:int=0;pruned:int=0;relaxed_complete:int=0;fsa_complete:int=0
 rejected_weight:int=0;terminal_weight:int=0;max_assigned:int=0;capped:bool=False

def propagate(mapping,used,rel):
 domains={v:set(range(16))-used for v in range(16) if mapping[v]<0}
 changed=True
 while changed:
  changed=False
  singles={}
  for v,d in domains.items():
   if not d:return None
   if len(d)==1:
    x=next(iter(d))
    if x in singles:return None
    singles[x]=v
  for x,owner in singles.items():
   for v,d in domains.items():
    if v!=owner and x in d:d.remove(x);changed=True
  for (h,l),pairs in rel.items():
   if h==l:
    d={mapping[h]} if mapping[h]>=0 else domains[h]
    nd={a for a in d if (a,a) in pairs}
    if not nd:return None
    if mapping[h]<0 and nd!=domains[h]:domains[h]=nd;changed=True
    continue
   dh={mapping[h]} if mapping[h]>=0 else domains[h]
   dl={mapping[l]} if mapping[l]>=0 else domains[l]
   nh={a for a in dh if any(a==x and b in dl for x,b in pairs)}
   nl={b for b in dl if any(b==y and a in dh for a,y in pairs)}
   if not nh or not nl:return None
   if mapping[h]<0 and nh!=domains[h]:domains[h]=nh;changed=True
   if mapping[l]<0 and nl!=domains[l]:domains[l]=nl;changed=True
 return domains

def solve(display,ks,node_limit=1_000_000,seed=None):
 assert len(display)==2*len(ks) and set(display)<=set(HEX)
 rel=relations(display,ks);mapping=[-1]*16;seed=seed or {};used=set()
 for k,v in seed.items():
  assert mapping[k]<0 and v not in used;mapping[k]=v;used.add(v)
 expected=math.factorial(16-len(seed));st=Stats();solutions=[]
 root=propagate(mapping,used,rel)
 if root is None:
  st.pruned=1;st.rejected_weight=expected
  return solutions,st,rel
 def rec(domains):
  if st.capped:return
  if st.nodes>=node_limit:st.capped=True;return
  st.nodes+=1;assigned=sum(x>=0 for x in mapping);st.max_assigned=max(st.max_assigned,assigned)
  if assigned==16:
   ct=decode(display,mapping);plain=bytes(a^b for a,b in zip(ct,ks))
   st.relaxed_complete+=1;st.terminal_weight+=1
   ok=valid_fsa(plain)
   if ok:st.fsa_complete+=1
   solutions.append({"mapping":tuple(mapping),"plaintext":plain,"fsa_valid":ok})
   return
  var=min(domains,key=lambda v:(len(domains[v]),v))
  for value in sorted(set(range(16))-used):
   mapping[var]=value;used.add(value)
   if value not in domains[var]:
    st.pruned+=1;st.rejected_weight+=math.factorial(16-sum(x>=0 for x in mapping))
   else:
    nd=propagate(mapping,used,rel)
    if nd is None:
     st.pruned+=1;st.rejected_weight+=math.factorial(16-sum(x>=0 for x in mapping))
    else:rec(nd)
   used.remove(value);mapping[var]=-1
 rec(root)
 cert=st.rejected_weight+st.terminal_weight
 assert cert<=expected
 if not st.capped:assert cert==expected
 return solutions,st,rel

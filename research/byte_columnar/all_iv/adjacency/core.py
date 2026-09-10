#!/usr/bin/env python3
"""Necessary ordered-chunk adjacency graph for rectangular variant B."""
import hashlib,importlib.util
from Crypto.Cipher import AES
from pathlib import Path
IDENTITY="ASTRA";HERE=Path(__file__).resolve().parent
R8=HERE.parent/"ragged8/core.py"
BSIZES={"aes128":16,"des":8,"blowfish":8,"blowfish_compat":8}
AESKEY=b"Zombies"+bytes(9)
spec=importlib.util.spec_from_file_location("audited_ragged8_core",R8);r8=importlib.util.module_from_spec(spec);spec.loader.exec_module(r8)
def block(cipher,value):
 if cipher=="aes128":return AES.new(AESKEY,AES.MODE_ECB).encrypt(value)
 return r8.block(cipher,value)
def cfb8(data,cipher,iv,decrypt):
 b=BSIZES[cipher];assert len(iv)==b;reg=iv;out=bytearray()
 for x in data:
  y=x^block(cipher,reg)[0];ct=x if decrypt else y;out.append(y);reg=reg[1:]+bytes([ct])
 return bytes(out)
def suffix(pair,cipher):
 b=BSIZES[cipher];return bytes(pair[i]^block(cipher,pair[i-b:i])[0] for i in range(b,len(pair)))
def trace(data,b):
 states={0,1,2};failure=None
 for off,x in enumerate(data):
  before=sorted(states);states={v for s in states if (v:=r8.step(s,x)) is not None}
  if not states:
   failure={"suffix_offset":off,"pair_plaintext_offset":b+off,
    "plaintext_byte":x,"states_before":before,"states_after":[]};break
 return sorted(states),failure
def weak_components(w,edges):
 adj=[set() for _ in range(w)]
 for a,b in edges:adj[a].add(b);adj[b].add(a)
 unseen=set(range(w));parts=[]
 while unseen:
  root=min(unseen);stack=[root];part=set()
  while stack:
   x=stack.pop()
   if x in part:continue
   part.add(x);unseen.discard(x);stack.extend(adj[x]-part)
  parts.append(sorted(part))
 return parts
def evaluate(observed,w,cipher):
 if len(observed)%w:raise ValueError("rectangular input required")
 q=len(observed)//w;b=BSIZES[cipher]
 base={"identity":IDENTITY,"cipher":cipher,"n":len(observed),"width":w,"q":q,"block_size":b,
  "variant":"B","start_states":[0,1,2],"terminal_zero_required":False}
 if not (q<=b<2*q):
  return base|{"supported":False,"reason":"requires q <= block_size < 2q"}
 chunks=[bytes(observed[j::w]) for j in range(w)];rows=[];edges=[]
 for a in range(w):
  for z in range(w):
   if a==z:continue
   pair=chunks[a]+chunks[z];tail=suffix(pair,cipher);states,fail=trace(tail,b);kept=bool(states)
   if kept:edges.append((a,z))
   rows.append({"from_rank":a,"to_rank":z,"chunk_a_hex":chunks[a].hex(),"chunk_b_hex":chunks[z].hex(),
    "pair_sha256":hashlib.sha256(pair).hexdigest(),"suffix_hex":tail.hex(),
    "suffix_sha256":hashlib.sha256(tail).hexdigest(),"suffix_bytes":len(tail),
    "end_states":states,"edge_retained":kept,"first_failure":fail})
 indeg=[0]*w;outdeg=[0]*w
 for a,z in edges:outdeg[a]+=1;indeg[z]+=1
 zi=[i for i,x in enumerate(indeg) if x==0];zo=[i for i,x in enumerate(outdeg) if x==0]
 parts=weak_components(w,edges);reasons=[]
 if len(zi)>=2:reasons.append("at_least_two_zero_indegree_vertices")
 if len(zo)>=2:reasons.append("at_least_two_zero_outdegree_vertices")
 if w>1 and len(parts)>=2:reasons.append("weakly_disconnected")
 closed=bool(reasons)
 return base|{"supported":True,"ordered_pair_witnesses":rows,"retained_edges":[list(x) for x in edges],
  "indegrees":indeg,"outdegrees":outdeg,"zero_indegree_vertices":zi,"zero_outdegree_vertices":zo,
  "weak_components":parts,"closure_reasons":reasons,"complete_every_iv_order_exclusion":closed,
  "unresolved":not closed,"claim":("no directed Hamiltonian path can exist by declared closure rule" if closed else "graph remains unresolved; no Hamiltonian search performed")}

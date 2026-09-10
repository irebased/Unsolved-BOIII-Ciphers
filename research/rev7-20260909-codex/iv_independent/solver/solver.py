#!/usr/bin/env python3
"""IV-independent CFB8 global displayed-hex-bijection solver (DES only)."""
from __future__ import annotations
import math
from dataclasses import dataclass,asdict
from functools import lru_cache
from Crypto.Cipher import DES
HEX="0123456789ABCDEF";KEY=b"Zombies\0";BS=8
RELAXED=set((9,10,13))|set(range(32,127))|{0xE2,0x80,0x93,0x94,0x98,0x99,0xA6}
THIRDS={0x93,0x94,0x98,0x99,0xA6}
@dataclass
class Stats:
 nodes:int=0;rejected_plaintext:int=0;maximum_depth:int=0;aborted_at_node_limit:bool=False
 rejected_completion_weight:int=0;terminal_completion_weight:int=0;rejected_strict_fsa:int=0
@dataclass
class Solution:
 mapping:tuple[int,...];plaintext_suffix:bytes
class Solver:
 def __init__(self,display:str,node_limit:int,seed_mapping=None,reference_scan=False):
  self.display="".join(display.split()).upper();assert len(self.display)%2==0
  self.pairs=[(HEX.index(self.display[i]),HEX.index(self.display[i+1])) for i in range(0,len(self.display),2)]
  assert len(self.pairs)>BS;self.node_limit=node_limit;self.reference_scan=reference_scan
  self.window_sets=[frozenset(x for pair in self.pairs[i-BS:i+1] for x in pair) for i in range(BS,len(self.pairs))]
  self.order,self.geometry=self._order();self.rank={s:i for i,s in enumerate(self.order)}
  self.mapping=[-1]*16;self.used=0
  for k,v in sorted((seed_mapping or {}).items()):
   assert 0<=k<16 and 0<=v<16 and self.mapping[k]<0 and not self.used>>v&1;self.mapping[k]=v;self.used|=1<<v
  self.todo=[s for s in self.order if self.mapping[s]<0];self.todo_index={s:i for i,s in enumerate(self.todo)}
  self.activate=[[] for _ in self.todo];self.prebound=[]
  for i,w in zip(range(BS,len(self.pairs)),self.window_sets):
   pending=[x for x in w if self.mapping[x]<0]
   if pending:self.activate[max(self.todo_index[x] for x in pending)].append(i)
   else:self.prebound.append(i)
  self.stats=Stats();self.solutions=[];self.fact=[math.factorial(i) for i in range(17)]
  self.ecb=DES.new(KEY,DES.MODE_ECB)
 def _order(self):
  freq=[0]*16
  for a,b in self.pairs:freq[a]+=1;freq[b]+=1
  m=min(map(len,self.window_sets));candidates=[(i,w) for i,w in enumerate(self.window_sets) if len(w)==m]
  anchor_i,anchor=max(candidates,key=lambda iw:(sum(v<=iw[1] for v in self.window_sets),-iw[0]))
  order=sorted(anchor,key=lambda s:(-freq[s],s));selected=set(order);bound=sum(w<=selected for w in self.window_sets);counts=[bound]
  while len(order)<16:
   choices=[]
   for s in set(range(16))-selected:
    after=selected|{s};new=sum(w<=after for w in self.window_sets)-bound;contained=sum(s in w for w in self.window_sets);choices.append((new,contained,-s,s))
   _,_,_,s=max(choices);order.append(s);selected.add(s);bound=sum(w<=selected for w in self.window_sets);counts.append(bound)
  return tuple(order),{"anchor_window_suffix_index":anchor_i+BS,"anchor_unique_symbols":m,"anchor_symbols":sorted(anchor),"symbol_order":order,"fully_bound_window_counts":counts}
 @lru_cache(maxsize=500000)
 def enc(self,b):return self.ecb.encrypt(b)
 def byte(self,i):a,b=self.pairs[i];return self.mapping[a]<<4|self.mapping[b]
 def window_ok(self,i):
  reg=bytes(self.byte(j) for j in range(i-BS,i));plain=self.byte(i)^self.enc(reg)[0];return plain in RELAXED
 def newly_ok(self,assigned_depth):return all(self.window_ok(i) for i in self.activate[assigned_depth])
 def all_bound_ok(self):
  return all(not all(self.mapping[x]>=0 for x in w) or self.window_ok(i) for i,w in zip(range(BS,len(self.pairs)),self.window_sets))
 def suffix(self):
  return bytes(self.byte(i)^self.enc(bytes(self.byte(j) for j in range(i-BS,i)))[0] for i in range(BS,len(self.pairs)))
 @staticmethod
 def strict_suffix_ok(data):
  states={0,1,2}
  for v in data:
   nxt=set()
   for state in states:
    if state==0:
     if v in (9,10,13) or 32<=v<=126:nxt.add(0)
     elif v==0xE2:nxt.add(1)
    elif state==1 and v==0x80:nxt.add(2)
    elif state==2 and v in THIRDS:nxt.add(0)
   states=nxt
   if not states:return False
  return 0 in states
 def rec(self,depth):
  if self.stats.aborted_at_node_limit:return
  if self.stats.nodes>=self.node_limit:self.stats.aborted_at_node_limit=True;return
  self.stats.nodes+=1;assigned=16-len(self.todo)+depth;self.stats.maximum_depth=max(self.stats.maximum_depth,assigned)
  if depth==len(self.todo):
   suffix=self.suffix()
   if self.strict_suffix_ok(suffix):self.stats.terminal_completion_weight+=1;self.solutions.append(Solution(tuple(self.mapping),suffix))
   else:self.stats.rejected_strict_fsa+=1;self.stats.rejected_completion_weight+=1
   return
  symbol=self.todo[depth]
  for value in range(16):
   if self.used>>value&1:continue
   self.mapping[symbol]=value;self.used|=1<<value;remaining=len(self.todo)-depth-1
   ok=self.all_bound_ok() if self.reference_scan else self.newly_ok(depth)
   if ok:self.rec(depth+1)
   else:self.stats.rejected_plaintext+=1;self.stats.rejected_completion_weight+=self.fact[remaining]
   self.used^=1<<value;self.mapping[symbol]=-1
   if self.stats.aborted_at_node_limit:break
 def run(self):
  if all(self.window_ok(i) for i in self.prebound):self.rec(0)
  else:self.stats.rejected_plaintext=1;self.stats.rejected_completion_weight=self.fact[len(self.todo)]
  return self.solutions,self.stats
 def result(self):
  expected=self.fact[len(self.todo)];cert=self.stats.rejected_completion_weight+self.stats.terminal_completion_weight
  return {"identity":"ASTRA","cipher":"des","block_size":BS,"node_limit":self.node_limit,"seeded_entries":16-len(self.todo),"expected_completion_weight":expected,"certificate_weight":cert,"certificate_complete":not self.stats.aborted_at_node_limit and cert==expected,"unaccounted_mapping_weight":expected-cert,"geometry":self.geometry,"stats":asdict(self.stats),"solutions":[{"mapping":list(x.mapping),"plaintext_suffix_hex":x.plaintext_suffix.hex()} for x in self.solutions]}
def solve(display,node_limit,seed_mapping=None,reference_scan=False):
 s=Solver(display,node_limit,seed_mapping,reference_scan);s.run();return s.result()

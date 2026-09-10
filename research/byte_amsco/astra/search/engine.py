#!/usr/bin/env python3
"""Lazy byte-AMSCO inverse and seven-backend all-IV CFB8 endpoint engine."""
from __future__ import annotations
import hashlib,itertools,math
from dataclasses import dataclass
RELAXED={9,10,13,*range(32,127),0xe2,0x80,0x93,0x94,0x98,0x99,0xa6};THIRDS={0x93,0x94,0x98,0x99,0xa6}
@dataclass(frozen=True)
class Geometry:
 n:int;width:int;start:int;column_lengths:tuple[int,...];natural_columns:tuple[int,...];within_columns:tuple[int,...]
 @classmethod
 def build(cls,n,width,start):
  if n<0 or not 2<=width<=9 or start not in (1,2):raise ValueError('geometry')
  lengths=[0]*width;columns=[];within=[];natural=0;cell=0;size=start
  while natural<n:
   take=min(size,n-natural);col=cell%width
   for _ in range(take):columns.append(col);within.append(lengths[col]);lengths[col]+=1;natural+=1
   cell+=1;size=3-size
  assert len(columns)==len(within)==n and sum(lengths)==n
  return cls(n,width,start,tuple(lengths),tuple(columns),tuple(within))
 def starts(self,order):
  if tuple(sorted(order))!=tuple(range(self.width)):raise ValueError('order')
  out=[0]*self.width;cursor=0
  for col in order:out[col]=cursor;cursor+=self.column_lengths[col]
  assert cursor==self.n;return tuple(out)
 def gather(self,observed,order,length=None):
  if len(observed)!=self.n:raise ValueError('observed length')
  length=self.n if length is None else length
  if not 0<=length<=self.n:raise ValueError('length')
  starts=self.starts(order)
  return bytes(observed[starts[c]+o] for c,o in zip(self.natural_columns[:length],self.within_columns[:length]))
def transition(states,value):
 out=set()
 for state in states:
  if state==0:
   if value in (9,10,13) or 32<=value<=126:out.add(0)
   elif value==0xe2:out.add(1)
  elif state==1 and value==0x80:out.add(2)
  elif state==2 and value in THIRDS:out.add(0)
 return out
def evaluate_order(observed,geometry,order,backends):
 """Evaluate all backends while gathering one shared natural ciphertext prefix."""
 starts=geometry.starts(order);recovered=bytearray();states={name:{0,1,2} for name in backends};tested={name:bytearray() for name in backends};rows={};active=set(backends)
 for i,(col,within) in enumerate(zip(geometry.natural_columns,geometry.within_columns)):
  recovered.append(observed[starts[col]+within])
  for name in tuple(active):
   backend=backends[name];b=backend.block_size
   if i<b:continue
   value=recovered[i]^backend.encrypt_block(bytes(recovered[i-b:i]))[0];tested[name].append(value)
   if value not in RELAXED:
    rows[name]={'cipher':name,'classification':'rejected_a105','accepted':False,'order':list(order),'rejection':{'ciphertext_index':i,'suffix_offset':i-b,'plaintext_byte':value,'reason':'outside A105'},'tested_suffix_bytes':len(tested[name]),'tested_suffix_sha256':hashlib.sha256(tested[name]).hexdigest(),'recovered_cipher_prefix_bytes':len(recovered),'recovered_cipher_prefix_sha256':hashlib.sha256(recovered).hexdigest(),'full_suffix_hex':None};active.remove(name);continue
   nxt=transition(states[name],value)
   if not nxt:
    rows[name]={'cipher':name,'classification':'rejected_fsa_transition','accepted':False,'order':list(order),'rejection':{'ciphertext_index':i,'suffix_offset':i-b,'plaintext_byte':value,'prior_states':sorted(states[name]),'reason':'no five-sequence FSA transition'},'tested_suffix_bytes':len(tested[name]),'tested_suffix_sha256':hashlib.sha256(tested[name]).hexdigest(),'recovered_cipher_prefix_bytes':len(recovered),'recovered_cipher_prefix_sha256':hashlib.sha256(recovered).hexdigest(),'full_suffix_hex':None};active.remove(name);continue
   states[name]=nxt
  if not active:break
 for name in tuple(active):
  backend=backends[name]
  if 0 in states[name]:classification='retained';accepted=True;rejection=None;full=bytes(tested[name]).hex()
  else:classification='rejected_fsa_terminal';accepted=False;rejection={'ciphertext_index':geometry.n,'suffix_offset':geometry.n-backend.block_size,'prior_states':sorted(states[name]),'reason':'true stream end requires state 0'};full=None
  rows[name]={'cipher':name,'classification':classification,'accepted':accepted,'order':list(order),'rejection':rejection,'tested_suffix_bytes':len(tested[name]),'tested_suffix_sha256':hashlib.sha256(tested[name]).hexdigest(),'recovered_cipher_prefix_bytes':len(recovered),'recovered_cipher_prefix_sha256':hashlib.sha256(recovered).hexdigest(),'full_suffix_hex':full};active.remove(name)
 assert set(rows)==set(backends)
 return [rows[name] for name in backends]
def grid_transform_count(widths=range(2,10),starts=(1,2),orientations=4):return sum(math.factorial(w) for w in widths)*len(tuple(starts))*orientations
def context_count(backend_count=7):return grid_transform_count()*backend_count

def scan_geometry(observed,width,start,backends,on_result=None,order_limit=None):
 """Enumerate one geometry exactly (or an explicit synthetic prefix for benchmarking)."""
 geometry=Geometry.build(len(observed),width,start);orders=0;contexts=0;counts={}
 iterator=itertools.permutations(range(width))
 if order_limit is not None:iterator=itertools.islice(iterator,order_limit)
 for order in iterator:
  rows=evaluate_order(observed,geometry,order,backends);orders+=1;contexts+=len(rows)
  for row in rows:
   counts[row['classification']]=counts.get(row['classification'],0)+1
   if on_result is not None:on_result(width,start,order,row)
 expected=orders*len(backends);assert contexts==expected
 if order_limit is None:assert orders==math.factorial(width)
 return {'width':width,'start':start,'orders':orders,'backend_contexts':contexts,'classification_counts':counts,'complete_geometry':order_limit is None}

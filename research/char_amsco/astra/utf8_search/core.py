#!/usr/bin/env python3
from __future__ import annotations
"""Indexed character-AMSCO CFB8 filter using the complete RFC 3629 byte grammar."""
from dataclasses import dataclass
import hashlib,json

STATE_NAMES=("boundary","remain1","remain2","remain3","after_E0","after_ED","after_F0","after_F4")
B,R1,R2,R3,E0,ED,F0,F4=range(8)
INITIAL_MASK=(1<<B)|(1<<R1)|(1<<R2)|(1<<R3)
TERMINAL_MASK=1<<B
HEX={c:i for i,c in enumerate("0123456789ABCDEF")};HEX.update({c.lower():i for c,i in tuple(HEX.items())})

def states(mask):return [STATE_NAMES[i] for i in range(8) if mask&(1<<i)]
def transition(state,value):
 if state==B:
  if value<=0x7f:return B
  if 0xc2<=value<=0xdf:return R1
  if value==0xe0:return E0
  if 0xe1<=value<=0xec or 0xee<=value<=0xef:return R2
  if value==0xed:return ED
  if value==0xf0:return F0
  if 0xf1<=value<=0xf3:return R3
  if value==0xf4:return F4
  return None
 if state==R1:return B if 0x80<=value<=0xbf else None
 if state==R2:return R1 if 0x80<=value<=0xbf else None
 if state==R3:return R2 if 0x80<=value<=0xbf else None
 if state==E0:return R1 if 0xa0<=value<=0xbf else None
 if state==ED:return R1 if 0x80<=value<=0x9f else None
 if state==F0:return R2 if 0x90<=value<=0xbf else None
 if state==F4:return R2 if 0x80<=value<=0x8f else None
 raise ValueError("state")
def step(mask,value):
 out=0
 for state in range(8):
  if mask&(1<<state):
   nxt=transition(state,value)
   if nxt is not None:out|=1<<nxt
 return out

def rejection_reason(prior,value):
 if prior==1<<B:
  if 0x80<=value<=0xbf:return "stray_continuation"
  if value in (0xc0,0xc1):return "overlong_lead"
  if value>=0xf5:return "lead_above_U+10FFFF_or_invalid"
  return "invalid_lead"
 if prior==1<<E0:return "E0_first_continuation_outside_A0_BF"
 if prior==1<<ED:return "ED_first_continuation_outside_80_9F_surrogate_guard"
 if prior==1<<F0:return "F0_first_continuation_outside_90_BF"
 if prior==1<<F4:return "F4_first_continuation_outside_80_8F_max_scalar_guard"
 return "missing_or_invalid_continuation"

@dataclass(frozen=True)
class IndexedLayout:
 n:int;width:int;start:str;column_of:tuple;within_column:tuple;column_lengths:tuple
 @classmethod
 def compile(cls,n,width,start,geometry):
  if n<=0 or n%2:raise ValueError("positive even natural hex length")
  if not 2<=width<=9 or start not in ("12","21"):raise ValueError("layout parameters")
  cols=[-1]*n;within=[-1]*n;lengths=[0]*width
  for col,pos,actual,_nominal in geometry.production_cells(n,width,start):
   for off in range(actual):cols[pos+off]=col;within[pos+off]=lengths[col];lengths[col]+=1
  if min(cols+within)<0 or sum(lengths)!=n:raise AssertionError("layout")
  return cls(n,width,start,tuple(cols),tuple(within),tuple(lengths))
 def starts(self,order):
  order=tuple(order)
  if len(order)!=self.width or tuple(sorted(order))!=tuple(range(self.width)):raise ValueError("permutation")
  starts=[0]*self.width;cursor=0
  for col in order:starts[col]=cursor;cursor+=self.column_lengths[col]
  if cursor!=self.n:raise AssertionError("length")
  return tuple(starts)
 def observed_index(self,natural,starts):return starts[self.column_of[natural]]+self.within_column[natural]
 def gather_byte(self,text,index,starts):
  if len(text)!=self.n:raise ValueError("observed length")
  a,b=2*index,2*index+1
  try:return (HEX[text[self.observed_index(a,starts)]]<<4)|HEX[text[self.observed_index(b,starts)]]
  except KeyError as exc:raise ValueError("nonhex") from exc
 def gather_bytes(self,text,order):
  starts=self.starts(order);return bytes(self.gather_byte(text,i,starts) for i in range(self.n//2))

class Search:
 def __init__(self,layout,text,backends):
  if len(text)!=layout.n or any(c not in HEX for c in text):raise ValueError("observed hex")
  if not backends:raise ValueError("backends")
  self.layout=layout;self.text=text;self.backends=dict(backends)
 def evaluate_order(self,order):
  starts=self.layout.starts(order);cipher=bytearray();masks={n:INITIAL_MASK for n in self.backends};suffix={n:bytearray() for n in self.backends};active=set(self.backends);witness={};callbacks=0;gathered=0
  for index in range(self.layout.n//2):
   value=self.layout.gather_byte(self.text,index,starts);cipher.append(value);gathered+=1
   for name in tuple(active):
    backend=self.backends[name];b=backend.block_size
    if index<b:continue
    plain=value^backend.encrypt_block(bytes(cipher[index-b:index]))[0];callbacks+=1;suffix[name].append(plain)
    prior=masks[name];masks[name]=step(prior,plain)
    if not masks[name]:
     witness[name]={"kind":"byte_rejection","plaintext_offset":index,"byte":plain,"byte_hex":f"{plain:02x}","prior_state_mask":prior,"prior_states":states(prior),"reason":rejection_reason(prior,plain)};active.remove(name)
   if not active:break
  retained=[]
  for name in sorted(active):
   if masks[name]&TERMINAL_MASK:retained.append({"backend":name,"suffix_offset":self.backends[name].block_size,"ending_state_mask":masks[name],"suffix_hex":bytes(suffix[name]).hex()})
   else:witness[name]={"kind":"terminal_rejection","plaintext_offset":self.layout.n//2,"prior_state_mask":masks[name],"prior_states":states(masks[name]),"reason":"incomplete_utf8_at_true_end"}
  return {"order":list(order),"contexts":len(self.backends),"gathered_ciphertext_bytes":gathered,"block_callbacks":callbacks,"rejected":len(self.backends)-len(retained),"retained":retained,"rejection_witnesses":{k:witness[k] for k in sorted(witness)}}
 def scan(self,orders):
  totals={"orders":0,"contexts":0,"gathered_ciphertext_bytes":0,"block_callbacks":0,"rejected":0,"retained":0};digest=hashlib.sha256();survivors=[];first=None;last=None;classes={}
  for order in orders:
   row=self.evaluate_order(order);encoded=json.dumps(row,sort_keys=True,separators=(",",":")).encode()+b"\n";digest.update(encoded)
   if first is None:first=row
   last=row
   if row["retained"]:survivors.append(row)
   for witness in row["rejection_witnesses"].values():classes[witness["reason"]]=classes.get(witness["reason"],0)+1
   totals["orders"]+=1;totals["contexts"]+=row["contexts"];totals["gathered_ciphertext_bytes"]+=row["gathered_ciphertext_bytes"];totals["block_callbacks"]+=row["block_callbacks"];totals["rejected"]+=row["rejected"];totals["retained"]+=len(row["retained"])
  if totals["contexts"]!=totals["rejected"]+totals["retained"]:raise AssertionError("accounting")
  return {"totals":totals,"stream_ndjson_sha256":digest.hexdigest(),"first_row":first,"last_row":last,"survivor_rows":survivors,"rejection_reason_counts":dict(sorted(classes.items()))}

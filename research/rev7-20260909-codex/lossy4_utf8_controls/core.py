#!/usr/bin/env python3
"""Exact 201-codepoint DFA-set DES all-IV masked suffix frontier."""
from __future__ import annotations
from functools import lru_cache
import hashlib,itertools
from Crypto.Cipher import DES
KEY=b'Zombies\0';MAX_FRONTIER=100_000;MAX_ACCEPTED=5_000_000
CODEPOINTS=(9,10,13,*range(0x20,0x7f),*range(0xa0,0x100),0x2013,0x2014,0x2018,0x2019,0x201c,0x201d,0x2026)
CP_SET=frozenset(CODEPOINTS);WORDS=tuple(chr(cp).encode('utf-8') for cp in CODEPOINTS);BYTE_UNION=frozenset(b for w in WORDS for b in w)
BOUNDARY,AFTER_C2,AFTER_C3,AFTER_E2,AFTER_E280=range(5)
INITIAL=frozenset((BOUNDARY,AFTER_C2,AFTER_C3,AFTER_E2,AFTER_E280));TERMINAL=frozenset((BOUNDARY,));PUNCT_THIRD=frozenset((0x93,0x94,0x98,0x99,0x9c,0x9d,0xa6));SINGLES=frozenset((9,10,13,*range(0x20,0x7f)))
def hb(x):return hashlib.sha256(x).hexdigest()
def step_one(state,b):
 if state==BOUNDARY:
  if b in SINGLES:return BOUNDARY
  if b==0xc2:return AFTER_C2
  if b==0xc3:return AFTER_C3
  if b==0xe2:return AFTER_E2
 elif state==AFTER_C2 and 0xa0<=b<=0xbf:return BOUNDARY
 elif state==AFTER_C3 and 0x80<=b<=0xbf:return BOUNDARY
 elif state==AFTER_E2 and b==0x80:return AFTER_E280
 elif state==AFTER_E280 and b in PUNCT_THIRD:return BOUNDARY
 return None
def step(states,b):return frozenset(x for s in states if (x:=step_one(s,b)) is not None)
@lru_cache(maxsize=None)
def valid_next(states):return bytes(b for b in range(256) if step(states,b))
def accepts_suffix(data):
 states=INITIAL
 for b in data:
  states=step(states,b)
  if not states:return False
 return BOUNDARY in states
def strict_prefix_oracle(data):
 prefixes=(b'',b'\xc2',b'\xc3',b'\xe2',b'\xe2\x80');witnesses=[]
 for prefix in prefixes:
  try:text=(prefix+data).decode('utf-8')
  except UnicodeDecodeError:continue
  if all(ord(ch) in CP_SET for ch in text):witnesses.append(prefix.hex())
 return witnesses
def reconstruct(observed,nbytes,indices):
 indices=tuple(indices)
 if len(indices)!=len(observed) or sorted(set(indices))!=sorted(indices) or any(i<0 or i>=2*nbytes for i in indices):raise ValueError('invalid source map')
 if any(c not in '0123456789ABCDEF' for c in observed):raise ValueError('uppercase hex required')
 vals=bytearray(nbytes);masks=bytearray(nbytes)
 for ch,index in zip(observed,indices):
  nib=int(ch,16);byte=index//2
  if index&1:vals[byte]|=nib;masks[byte]|=15
  else:vals[byte]|=nib<<4;masks[byte]|=240
 return bytes(vals),bytes(masks)
def domains(vals,masks):return [tuple(c for c in range(256) if (c&m)==(v&m)) for v,m in zip(vals[:8],masks[:8])]
def roots_and_proof(vals,masks):
 ds=domains(vals,masks);roots=[bytes(x) for x in itertools.product(*ds)];direct={bytes(x) for x in itertools.product(*(tuple(c for c in range(256) if (c&m)==(v&m)) for v,m in zip(vals[:8],masks[:8])))};assert len(roots)==len(set(roots))==len(direct) and set(roots)==direct
 return roots,{'mask_prefix':[f'{x:02x}' for x in masks[:8]],'compatible_counts_per_byte':[len(x) for x in ds],'generated_count':len(roots),'unique_count':len(set(roots)),'direct_product_count':len(direct),'generator_equals_direct_mask_product':True,'registers_digest_sha256':hb(b''.join(roots))}
def finish(complete,reason,total,nbytes,proof,solutions,counts,accepted,calls,maxlive,started,completed,unexamined,partial):
 assert accepted==sum(counts) and started==completed+(partial is not None) and completed+unexamined+(partial is not None)==total and complete==(completed==total and partial is None)
 assert all(len(bytes.fromhex(x['suffix_plaintext_hex']))==nbytes-8 and len(bytes.fromhex(x['ciphertext_hex']))==nbytes and BOUNDARY in x['endpoint_states'] for x in solutions)
 return {'complete':complete,'capped_reason':reason,'natural_bytes':nbytes,'initial_register_proof':proof,'initial_registers_total':total,'roots_started':started,'roots_completed':completed,'roots_unexamined':unexamined,'partial_root':partial,'accepted_states':accepted,'accepted_states_by_suffix_byte':counts,'block_calls':calls,'max_live_frontier_per_root':maxlive,'solutions_are_terminal_only':True,'solution_count':len(solutions),'solutions':solutions}
def search(observed,nbytes,indices,max_frontier=MAX_FRONTIER,max_accepted=MAX_ACCEPTED):
 vals,masks=reconstruct(observed,nbytes,indices);roots,proof=roots_and_proof(vals,masks);total=len(roots);e=DES.new(KEY,DES.MODE_ECB);solutions=[];counts=[0]*(nbytes-8);accepted=calls=maxlive=started=completed=0
 for ri,seed in enumerate(roots):
  started+=1;front=[(seed,b'',seed,INITIAL)]
  for pos in range(8,nbytes):
   nxt=[];parents=choices_seen=0;v=vals[pos];m=masks[pos]
   for reg,pt,ct,states in front:
    k=e.encrypt(reg)[0];calls+=1;parents+=1
    candidates=(bytes((v^k,)) if m==255 else valid_next(states))
    for plain in candidates:
     choices_seen+=1;ns=step(states,plain);c=v if m==255 else plain^k
     if not ns or (c&m)!=(v&m):continue
     if accepted>=max_accepted:
      part={'root_index':ri,'root_hex':seed.hex(),'position':pos,'reason':'max_accepted','frontier_before':len(front),'parents_processed':parents,'choices_examined':choices_seen,'next_frontier_constructed':len(nxt),'next_valid_candidate_not_added':True}
      return finish(False,'max_accepted',total,nbytes,proof,solutions,counts,accepted,calls,max(maxlive,len(nxt)),started,completed,total-ri-1,part)
     if len(nxt)>=max_frontier:
      part={'root_index':ri,'root_hex':seed.hex(),'position':pos,'reason':'max_frontier','frontier_before':len(front),'parents_processed':parents,'choices_examined':choices_seen,'next_frontier_constructed':len(nxt),'next_valid_candidate_not_added':True}
      return finish(False,'max_frontier',total,nbytes,proof,solutions,counts,accepted,calls,max(maxlive,len(nxt)),started,completed,total-ri-1,part)
     nxt.append((reg[1:]+bytes((c,)),pt+bytes((plain,)),ct+bytes((c,)),ns));accepted+=1;counts[pos-8]+=1
   front=nxt;maxlive=max(maxlive,len(front))
   if not front:break
  if front and pos==nbytes-1:
   for _,pt,ct,states in front:
    if BOUNDARY in states:solutions.append({'initial_register_hex':seed.hex(),'suffix_plaintext_hex':pt.hex(),'ciphertext_hex':ct.hex(),'endpoint_states':sorted(states),'initial_contexts':sorted(INITIAL),'suffix_plaintext_sha256':hb(pt),'ciphertext_sha256':hb(ct)})
  completed+=1
 return finish(True,None,total,nbytes,proof,solutions,counts,accepted,calls,maxlive,started,completed,0,None)
def manual_suffix(seed,cipher_suffix):
 e=DES.new(KEY,DES.MODE_ECB);reg=bytearray(seed);out=bytearray()
 for c in cipher_suffix:out.append(c^e.encrypt(bytes(reg))[0]);reg[:]=reg[1:]+bytes((c,))
 return bytes(out)

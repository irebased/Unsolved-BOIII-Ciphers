#!/usr/bin/env python3
"""Generic exact DES all-IV printable-suffix frontier for an explicit source emission map."""
from __future__ import annotations
import hashlib,itertools
from Crypto.Cipher import DES
KEY=b'Zombies\0';ALLOWED=bytes(range(32,127));MAX_FRONTIER=100_000;MAX_ACCEPTED=5_000_000

def hb(x):return hashlib.sha256(x).hexdigest()
def reconstruct(observed:str,nbytes:int,emission_indices):
 indices=tuple(emission_indices)
 if len(indices)!=len(observed):raise ValueError('observation/map length mismatch')
 if sorted(set(indices))!=sorted(indices) or any(i<0 or i>=2*nbytes for i in indices):raise ValueError('invalid or duplicate emission index')
 if any(c not in '0123456789ABCDEF' for c in observed):raise ValueError('uppercase hex required')
 vals=bytearray(nbytes);masks=bytearray(nbytes)
 for ch,index in zip(observed,indices):
  nib=int(ch,16);byte=index//2
  if index&1:vals[byte]|=nib;masks[byte]|=0x0f
  else:vals[byte]|=nib<<4;masks[byte]|=0xf0
 return bytes(vals),bytes(masks)
def compatible_values(value,mask,domain=range(256)):return tuple(x for x in domain if (x&mask)==(value&mask))
def compatible_registers(vals,masks,block_size=8):
 domains=[compatible_values(v,m) for v,m in zip(vals[:block_size],masks[:block_size])]
 for root in itertools.product(*domains):yield bytes(root)
def root_proof(vals,masks):
 domains=[compatible_values(v,m) for v,m in zip(vals[:8],masks[:8])];roots=list(itertools.product(*domains));packed=[bytes(x) for x in roots]
 direct={bytes(x) for x in itertools.product(*(tuple(c for c in range(256) if (c&m)==(v&m)) for v,m in zip(vals[:8],masks[:8])))}
 assert len(packed)==len(set(packed))==len(direct) and set(packed)==direct
 return packed,{'mask_prefix':[f'{x:02x}' for x in masks[:8]],'compatible_counts_per_byte':[len(x) for x in domains],'generated_count':len(packed),'unique_count':len(set(packed)),'direct_product_count':len(direct),'generator_equals_direct_mask_product':True,'registers_digest_sha256':hb(b''.join(packed))}
def finish(complete,reason,total,nbytes,proof,solutions,counts,accepted,calls,max_live,started,completed,unexamined,partial):
 assert accepted==sum(counts);assert started==completed+(partial is not None);assert completed+unexamined+(partial is not None)==total
 assert complete==(completed==total and partial is None)
 assert all(len(bytes.fromhex(x['suffix_plaintext_hex']))==nbytes-8 and len(bytes.fromhex(x['ciphertext_hex']))==nbytes for x in solutions)
 return {'complete':complete,'capped_reason':reason,'natural_bytes':nbytes,'initial_register_proof':proof,'initial_registers_total':total,'roots_started':started,'roots_completed':completed,'roots_unexamined':unexamined,'partial_root':partial,'accepted_states':accepted,'accepted_states_by_suffix_byte':counts,'block_calls':calls,'max_live_frontier_per_root':max_live,'solutions_are_terminal_only':True,'solution_count':len(solutions),'solutions':solutions}
def search(observed,nbytes,emission_indices,max_frontier=MAX_FRONTIER,max_accepted=MAX_ACCEPTED,allowed=ALLOWED):
 if nbytes<9 or max_frontier<1 or max_accepted<0:raise ValueError('invalid search parameters')
 vals,masks=reconstruct(observed,nbytes,emission_indices);roots,proof=root_proof(vals,masks);total=len(roots);e=DES.new(KEY,DES.MODE_ECB)
 solutions=[];counts=[0]*(nbytes-8);accepted=calls=max_live=started=completed=0
 for root_index,seed in enumerate(roots):
  started+=1;front=[(seed,b'',seed)]
  for pos in range(8,nbytes):
   nxt=[];parents_processed=choices_examined=0;v=vals[pos];m=masks[pos]
   for reg,pt,ct in front:
    k=e.encrypt(reg)[0];calls+=1;parents_processed+=1;choices=(bytes((v^k,)) if m==255 else allowed)
    for plain in choices:
     choices_examined+=1;c=v if m==255 else plain^k
     if plain not in allowed or (c&m)!=(v&m):continue
     if accepted>=max_accepted:
      part={'root_index':root_index,'root_hex':seed.hex(),'position':pos,'reason':'max_accepted','frontier_before':len(front),'parents_processed':parents_processed,'choices_examined':choices_examined,'next_frontier_constructed':len(nxt),'next_valid_candidate_not_added':True}
      return finish(False,'max_accepted',total,nbytes,proof,solutions,counts,accepted,calls,max(max_live,len(nxt)),started,completed,total-root_index-1,part)
     if len(nxt)>=max_frontier:
      part={'root_index':root_index,'root_hex':seed.hex(),'position':pos,'reason':'max_frontier','frontier_before':len(front),'parents_processed':parents_processed,'choices_examined':choices_examined,'next_frontier_constructed':len(nxt),'next_valid_candidate_not_added':True}
      return finish(False,'max_frontier',total,nbytes,proof,solutions,counts,accepted,calls,max(max_live,len(nxt)),started,completed,total-root_index-1,part)
     nxt.append((reg[1:]+bytes((c,)),pt+bytes((plain,)),ct+bytes((c,))));accepted+=1;counts[pos-8]+=1
   front=nxt;max_live=max(max_live,len(front))
   if not front:break
  if front and pos==nbytes-1:
   for _,pt,ct in front:solutions.append({'initial_register_hex':seed.hex(),'suffix_plaintext_hex':pt.hex(),'ciphertext_hex':ct.hex(),'suffix_plaintext_sha256':hb(pt),'ciphertext_sha256':hb(ct)})
  completed+=1
 return finish(True,None,total,nbytes,proof,solutions,counts,accepted,calls,max_live,started,completed,0,None)
def manual_suffix(seed,cipher_suffix):
 e=DES.new(KEY,DES.MODE_ECB);reg=bytearray(seed);out=bytearray()
 for c in cipher_suffix:out.append(c^e.encrypt(bytes(reg))[0]);reg[:]=reg[1:]+bytes((c,))
 return bytes(out)

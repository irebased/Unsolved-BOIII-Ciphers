#!/usr/bin/env python3
"""Exact masked-CFB8 frontier for the literal legacy AMSCO key 2016."""
from Crypto.Cipher import AES,DES
from dataclasses import dataclass
import hashlib,time
ALLOWED=bytes([32]+list(range(65,91)))
MASK_CYCLE=(0xff,0x0f,0xf0)
def lossy_emit(hextext:str)->str:
 assert len(hextext)%6==0 and all(c in '0123456789ABCDEF' for c in hextext)
 rows=[hextext[i:i+6] for i in range(0,len(hextext),6)]
 return ''.join(r[3:5] for r in rows)+''.join(r[0:2] for r in rows)
def reconstruct_masks(observed:str,nbytes:int):
 assert nbytes%3==0 and len(observed)==4*(nbytes//3) and all(c in '0123456789ABCDEF' for c in observed)
 rows=nbytes//3;vals=[0]*nbytes;masks=[0]*nbytes
 for r in range(rows):
  first=observed[2*r:2*r+2];second=observed[2*rows+2*r:2*rows+2*r+2]
  vals[3*r]=int(second,16);masks[3*r]=0xff
  vals[3*r+1]=int(first[0],16);masks[3*r+1]=0x0f
  vals[3*r+2]=int(first[1],16)<<4;masks[3*r+2]=0xf0
 assert tuple(masks)==MASK_CYCLE*(nbytes//3)
 return bytes(vals),bytes(masks)
def cipher_spec(name):
 if name=='des':return DES.new(b'Zombies\0',DES.MODE_ECB),8,b'Zombies\0'
 if name=='aes128':return AES.new(b'Zombies'+b'\0'*9,AES.MODE_ECB),16,b'Zombies'+b'\0'*9
 raise ValueError(name)
def encrypt_cfb8(name,iv,plain):
 _,bs,key=cipher_spec(name);mod=DES if name=='des' else AES
 return mod.new(key,mod.MODE_CFB,iv=iv,segment_size=8).encrypt(plain)
def manual_decrypt(name,iv,ct):
 e,bs,_=cipher_spec(name);reg=bytearray(iv);out=[]
 for c in ct:
  out.append(c^e.encrypt(bytes(reg))[0]);reg[:]=reg[1:]+bytes([c])
 return bytes(out)
def search(name,iv,observed,nbytes,max_frontier=100000,max_accepted=5000000,allowed=ALLOWED):
 vals,masks=reconstruct_masks(observed,nbytes);e,bs,_=cipher_spec(name);assert len(iv)==bs
 frontier=[(iv,b'',b'')];counts=[];accepted=0;calls=0;t0=time.perf_counter()
 for pos,(v,m) in enumerate(zip(vals,masks)):
  nxt=[]
  for reg,pt,ct in frontier:
   k=e.encrypt(reg)[0];calls+=1
   if m==0xff:
    c=v;p=c^k
    if p in allowed:nxt.append((reg[1:]+bytes([c]),pt+bytes([p]),ct+bytes([c])))
   else:
    for p in allowed:
     c=p^k
     if c&m==v&m:nxt.append((reg[1:]+bytes([c]),pt+bytes([p]),ct+bytes([c])))
   if len(nxt)>max_frontier:
    return {'complete':False,'capped_reason':'max_frontier','stopped_after_bytes':pos,'frontier_counts':counts,'max_frontier':max(counts+[len(nxt)]),'accepted_states':accepted+len(nxt),'block_calls':calls,'seconds':time.perf_counter()-t0,'solutions':[]}
  accepted+=len(nxt);counts.append(len(nxt))
  if accepted>max_accepted:
   return {'complete':False,'capped_reason':'max_accepted','stopped_after_bytes':pos+1,'frontier_counts':counts,'max_frontier':max(counts),'accepted_states':accepted,'block_calls':calls,'seconds':time.perf_counter()-t0,'solutions':[]}
  frontier=nxt
  if not frontier:break
 sols=[{'plaintext_hex':pt.hex(),'ciphertext_hex':ct.hex(),'plaintext_sha256':hashlib.sha256(pt).hexdigest(),'ciphertext_sha256':hashlib.sha256(ct).hexdigest()} for _,pt,ct in frontier]
 return {'complete':True,'capped_reason':None,'stopped_after_bytes':len(counts),'frontier_counts':counts,'max_frontier':max(counts,default=1),'accepted_states':accepted,'block_calls':calls,'seconds':time.perf_counter()-t0,'solutions':sols}

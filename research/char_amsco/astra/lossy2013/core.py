#!/usr/bin/env python3
"""Exact source-derived geometry and masked-CFB8 frontier for literal key 2013."""
from __future__ import annotations
from Crypto.Cipher import AES,DES
import hashlib,time

ALLOWED=bytes(range(32,127))
KEYS=("2013","2014")

def cell_positions(length,width):
    if length<0 or width<=0: raise ValueError("invalid length or width")
    rows=[]; pos=0; cell=0; size=2
    while pos<length:
        take=min(size,length-pos); row=cell//width; col=cell%width
        while len(rows)<=row: rows.append([])
        rows[row].append((col,tuple(range(pos,pos+take))))
        pos+=take;cell+=1;size=3-size
    return rows

def emission_indices(length,key):
    """Natural input indices emitted by the original row-label overwrite/read order."""
    if not key or any(c not in "0123456789" for c in key): raise ValueError("decimal digit key required")
    rows=cell_positions(length,len(key)); labelled=[]
    for cells in rows:
        row={}
        for col,positions in cells: row[int(key[col])]=positions
        labelled.append(row)
    out=[]
    for label in range(1,len(key)+1):
        for row in labelled: out.extend(row.get(label,()))
    return tuple(out)

def emit(text,key="2013"):
    return "".join(text[i] for i in emission_indices(len(text),key))

def emitted_length(length,key="2013"):
    return len(emission_indices(length,key))

def compatible_even_input_lengths(observed_length,upper=None,key="2013"):
    if observed_length<0: raise ValueError("negative observed length")
    if upper is None: upper=2*(observed_length+len(key)+1)
    return [n for n in range(0,upper+1,2) if emitted_length(n,key)==observed_length]

def reconstruct(observed,nbytes,key="2013"):
    natural_chars=2*nbytes
    indices=emission_indices(natural_chars,key)
    if len(indices)!=len(observed): raise ValueError("observed length mismatch")
    if any(c not in "0123456789ABCDEF" for c in observed): raise ValueError("uppercase hex required")
    vals=bytearray(nbytes);masks=bytearray(nbytes)
    for c,index in zip(observed,indices):
        nib=int(c,16); b=index//2
        if index%2: vals[b]|=nib;masks[b]|=0x0f
        else: vals[b]|=nib<<4;masks[b]|=0xf0
    return bytes(vals),bytes(masks)

def cipher_spec(name):
    if name=="des": return DES.new(b"Zombies\0",DES.MODE_ECB),8,b"Zombies\0"
    if name=="aes128": return AES.new(b"Zombies"+b"\0"*9,AES.MODE_ECB),16,b"Zombies"+b"\0"*9
    raise ValueError(name)

def encrypt_cfb8(name,iv,plaintext):
    _,bs,key=cipher_spec(name);mod=DES if name=="des" else AES
    return mod.new(key,mod.MODE_CFB,iv=iv,segment_size=8).encrypt(plaintext)

def decrypt_cfb8(name,iv,ciphertext):
    e,bs,_=cipher_spec(name)
    if len(iv)!=bs: raise ValueError("IV length")
    reg=bytearray(iv);out=bytearray()
    for c in ciphertext:
        out.append(c^e.encrypt(bytes(reg))[0]);reg[:]=reg[1:]+bytes((c,))
    return bytes(out)

def search(name,iv,observed,nbytes,key="2013",max_frontier=100000,max_accepted=5000000,allowed=ALLOWED):
    vals,masks=reconstruct(observed,nbytes,key);e,bs,_=cipher_spec(name)
    if len(iv)!=bs: raise ValueError("IV length")
    frontier=[(bytes(iv),b"",b"")];counts=[];accepted=0;calls=0;t0=time.perf_counter()
    for pos,(v,m) in enumerate(zip(vals,masks)):
        nxt=[]
        for reg,pt,ct in frontier:
            k=e.encrypt(reg)[0];calls+=1
            if m==0xff:
                c=v;p=c^k
                if p in allowed:nxt.append((reg[1:]+bytes((c,)),pt+bytes((p,)),ct+bytes((c,))))
            else:
                for p in allowed:
                    c=p^k
                    if c&m==v&m:nxt.append((reg[1:]+bytes((c,)),pt+bytes((p,)),ct+bytes((c,))))
            if len(nxt)>max_frontier:
                return {"complete":False,"capped_reason":"max_frontier","stopped_after_bytes":pos,"frontier_counts":counts,"frontier_count_at_stop":len(nxt),"accepted_states":accepted+len(nxt),"block_calls":calls,"seconds":time.perf_counter()-t0,"solutions":[]}
        accepted+=len(nxt);counts.append(len(nxt));frontier=nxt
        if accepted>max_accepted:
            return {"complete":False,"capped_reason":"max_accepted","stopped_after_bytes":pos+1,"frontier_counts":counts,"frontier_count_at_stop":len(frontier),"accepted_states":accepted,"block_calls":calls,"seconds":time.perf_counter()-t0,"solutions":[]}
        if not frontier: break
    solutions=[{"plaintext_hex":pt.hex(),"ciphertext_hex":ct.hex(),"plaintext_sha256":hashlib.sha256(pt).hexdigest(),"ciphertext_sha256":hashlib.sha256(ct).hexdigest()} for _,pt,ct in frontier]
    return {"complete":True,"capped_reason":None,"stopped_after_bytes":len(counts),"frontier_counts":counts,"frontier_count_at_stop":len(frontier),"accepted_states":accepted,"block_calls":calls,"seconds":time.perf_counter()-t0,"solutions":solutions}

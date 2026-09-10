#!/usr/bin/env python3
"""Synthetic-only partial-observation invariant for source-certified lossy AMSCO maps."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
IDENTITY='ASTRA';SYMS='0123456789ABCDEF';HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
INV=ROOT/'research/char_amsco/astra/lossy4_onechar_inventory/inventory.json'
INV_SOURCE=ROOT/'research/char_amsco/astra/lossy4_onechar_inventory/inventory.py'
ANALYZE=ROOT/'research/char_amsco/astra/cryptool_bug/analyze.py'
PINS={str(INV.relative_to(ROOT)):'fa9d7463848918d2eaddfe6afdf013f2d5b6b1d1c2011aa5d0aa5a197eec4fe2',str(INV_SOURCE.relative_to(ROOT)):'6990162132bd5d2d3c77ef3fce00d07c1f807fb33845283021ebbf4fe4323b50',str(ANALYZE.relative_to(ROOT)):'ba66b3c844cf5784749587af960a11163d5e47deddf523a04530bea4f5d9629b'}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def verify_pins():
 for rel,want in PINS.items():assert sha(ROOT/rel)==want,(rel,sha(ROOT/rel),want)
def source_indices(length,key):
 # Literal PHP geometry: alternating 2/1 cells, four natural columns,
 # duplicate numeric labels overwrite whole earlier cells in each row.
 rows=[];pos=0;cell=0;size=2
 while pos<length:
  row=cell//4;col=cell%4
  while len(rows)<=row:rows.append({})
  take=min(size,length-pos);rows[row][int(key[col])]=tuple(range(pos,pos+take))
  pos+=take;cell+=1;size=3-size
 return tuple(i for label in range(1,5) for row in rows for i in row.get(label,()))
def orient(s,name):
 if name=='forward':return s
 if name=='full_hex_reverse':return s[::-1]
 if name=='byte_reverse':return ''.join(reversed([s[i:i+2] for i in range(0,len(s),2)]))
 if name=='nibble_swap':return ''.join(s[i+1]+s[i] for i in range(0,len(s),2))
 raise ValueError(name)
def reconstruct(observed_oriented,indices,natural_length,orientation):
 observed=orient(observed_oriented,orientation) # all four transforms are involutions
 assert len(observed)==len(indices) and len(set(indices))==len(indices)
 out=[None]*natural_length
 for i,ch in zip(indices,observed):out[i]=ch
 return out
def coords(square,s):return divmod(square.index(s),4)
def bifid_encrypt_block(plain,square):
 pairs=[coords(square,s) for s in plain];digits=[r for r,c in pairs]+[c for r,c in pairs]
 return ''.join(square[4*digits[i]+digits[i+1]] for i in range(0,len(digits),2))
def bifid_encrypt(plain,square,period):return ''.join(bifid_encrypt_block(plain[a:a+period],square) for a in range(0,len(plain),period))
def natural_pairs(seq,period):
 assert len(seq)%2==0 and period>0
 for a in range(0,len(seq),period):
  L=min(period,len(seq)-a);assert L%2==0
  h=L//2
  for j in range(h):yield seq[a+j],seq[a+h+j]
def known_pair_hist(partial,period):
 hist=[0]*256
 for a,b in natural_pairs(partial,period):
  if a is not None and b is not None:hist[16*int(a,16)+int(b,16)]+=1
 return hist
def full_pair_hist(cipher,period):
 hist=[0]*256
 for a,b in natural_pairs(cipher,period):hist[16*int(a,16)+int(b,16)]+=1
 return hist
def endpoint_codepoints():return tuple(sorted({9,10,13,*range(32,127),*range(0xA0,0x100),0x2013,0x2014,0x2018,0x2019,0x201C,0x201D,0x2026}))
def synthetic_text(variant=0):
 cps=list(endpoint_codepoints());cps=cps[variant%len(cps):]+cps[:variant%len(cps)]
 raw=(''.join(chr(x) for x in cps)*2).encode('utf-8');raw+=bytes((65+(i+variant)%26 for i in range(655-len(raw))))
 assert len(raw)==655 and set(raw)==({*range(32,127),9,10,13,0xC2,0xC3,0xE2,*range(0x80,0xC0)})
 assert all(ord(ch) in endpoint_codepoints() for ch in raw.decode('utf-8'))
 return raw

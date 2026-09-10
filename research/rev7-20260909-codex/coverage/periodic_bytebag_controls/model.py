#!/usr/bin/env python3
"""Exact repeating-key byte-bag necessary-condition model."""
from __future__ import annotations
from typing import Iterable
IDENTITY="ASTRA"
CODEPOINTS=(9,10,13,*range(0x20,0x7f),*range(0xa0,0x100),0x2013,0x2014,0x2018,0x2019,0x201c,0x201d,0x2026)
assert len(CODEPOINTS)==201 and len(set(CODEPOINTS))==201
CODEWORDS=tuple(chr(cp).encode("utf-8") for cp in CODEPOINTS)
BYTE_BAG=frozenset(b for word in CODEWORDS for b in word)
assert len(BYTE_BAG)==165
ALL=(1<<256)-1
ORIENTATIONS=("forward","reverse","byte_reverse","nibble_swap")
OPERATIONS=("xor","subtract")
def transform_byte(cipher:int,key:int,operation:str)->int:
 if operation=="xor":return cipher^key
 if operation=="subtract":return (cipher-key)&255
 raise ValueError(operation)
def candidate_mask(cipher:int,operation:str)->int:
 if not 0<=cipher<256:raise ValueError(cipher)
 if operation=="xor":values=(cipher^plain for plain in BYTE_BAG)
 elif operation=="subtract":values=((cipher-plain)&255 for plain in BYTE_BAG)
 else:raise ValueError(operation)
 out=0
 for k in values:out|=1<<k
 return out
def residue_masks_fast(ciphertext:bytes,period:int,operation:str)->tuple[int,...]:
 if period<=0:raise ValueError("period must be positive")
 masks=[ALL]*period
 for i,value in enumerate(ciphertext):masks[i%period]&=candidate_mask(value,operation)
 return tuple(masks)
def residue_masks_slow(ciphertext:bytes,period:int,operation:str)->tuple[int,...]:
 if period<=0:raise ValueError("period must be positive")
 out=[]
 for residue in range(period):
  column=ciphertext[residue::period];mask=0
  for key in range(256):
   if all(transform_byte(x,key,operation) in BYTE_BAG for x in column):mask|=1<<key
  out.append(mask)
 return tuple(out)
def orient_hex(value:str,name:str)->str:
 if len(value)%2:raise ValueError("hex length must be even")
 pairs=[value[i:i+2] for i in range(0,len(value),2)]
 if name=="forward":return value
 if name=="reverse":return value[::-1]
 if name=="byte_reverse":return "".join(reversed(pairs))
 if name=="nibble_swap":return "".join(x[::-1] for x in pairs)
 raise ValueError(name)
def mask_hex(mask:int)->str:return f"{mask:064x}"
def mask_values(mask:int)->list[int]:return [k for k in range(256) if mask>>k&1]

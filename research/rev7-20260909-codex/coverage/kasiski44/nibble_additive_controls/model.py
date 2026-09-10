#!/usr/bin/env python3
"""Target-free nibble-additive necessary byte-mask model."""
from __future__ import annotations
import importlib.util
from pathlib import Path
HERE=Path(__file__).resolve().parent
PBC=HERE.parents[1]/"periodic_bytebag_controls"
spec=importlib.util.spec_from_file_location("periodic_bytebag_model",PBC/"model.py")
bytebag=importlib.util.module_from_spec(spec);spec.loader.exec_module(bytebag)
IDENTITY="ASTRA";OPERATIONS=("subtract","beaufort");ALL=(1<<256)-1
BYTE_BAG=bytebag.BYTE_BAG;CODEPOINTS=bytebag.CODEPOINTS;CODEWORDS=bytebag.CODEWORDS

def decrypt_byte(cipher:int,key:int,operation:str)->int:
 ch,cl=cipher>>4,cipher&15;kh,kl=key>>4,key&15
 if operation=="subtract":return ((ch-kh)&15)<<4|((cl-kl)&15)
 if operation=="beaufort":return ((kh-ch)&15)<<4|((kl-cl)&15)
 raise ValueError(operation)

def encrypt_byte(plain:int,key:int,operation:str)->int:
 ph,pl=plain>>4,plain&15;kh,kl=key>>4,key&15
 if operation=="subtract":return ((ph+kh)&15)<<4|((pl+kl)&15)
 if operation=="beaufort":return ((kh-ph)&15)<<4|((kl-pl)&15)
 raise ValueError(operation)

def candidate_mask(cipher:int,operation:str)->int:
 out=0
 for key in range(256):
  if decrypt_byte(cipher,key,operation) in BYTE_BAG:out|=1<<key
 return out

def residue_masks_fast(ciphertext:bytes,period:int,operation:str):
 if period<=0:raise ValueError(period)
 masks=[ALL]*period
 for i,c in enumerate(ciphertext):masks[i%period]&=candidate_mask(c,operation)
 return tuple(masks)

def residue_masks_slow(ciphertext:bytes,period:int,operation:str):
 if period<=0:raise ValueError(period)
 return tuple(sum(1<<k for k in range(256) if all(decrypt_byte(c,k,operation) in BYTE_BAG for c in ciphertext[r::period])) for r in range(period))

def paired_period(hex_period:int)->int:
 if hex_period<=0:raise ValueError(hex_period)
 return hex_period//2 if hex_period%2==0 else hex_period

def mask_hex(mask:int)->str:return f"{mask:064x}"
def mask_values(mask:int):return [k for k in range(256) if mask>>k&1]

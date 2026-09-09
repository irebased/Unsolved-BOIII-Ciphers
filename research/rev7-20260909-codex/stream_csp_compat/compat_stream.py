#!/usr/bin/env python3
"""Synthetic-only Blowfish-compat fixed-keystream constructions."""
from __future__ import annotations
import hashlib,sys
from pathlib import Path
from Crypto.Cipher import Blowfish
HERE=Path(__file__).resolve().parent
RESEARCH=HERE.parent
NATIVE=RESEARCH/"hex_cfb"/"native_compat"
sys.path.insert(0,str(NATIVE))
import source_check
KEY=b"Zombies";BLOCK=8
def word_reverse(value:bytes)->bytes:
 assert len(value)==8
 return value[3::-1]+value[7:3:-1]
def load_block():
 block,size=source_check.load_algorithm(NATIVE/"source_build"/"libblowfish_compat.so","blowfish_compat")
 return lambda value:block(KEY,value)
def ivs():
 return {"ascii_zero":b"0"*8,"nul":b"\0"*8,"sha1_prefix":hashlib.sha1(KEY).digest()[:8]}
def ofb8_keystream(block,iv,n):
 reg=iv;out=bytearray()
 for _ in range(n):
  k=block(reg)[0];out.append(k);reg=reg[1:]+bytes([k])
 return bytes(out)
def fullblock_recurrence(block,iv,n):
 reg=iv;out=bytearray()
 while len(out)<n:
  reg=block(reg);out.extend(reg)
 return bytes(out[:n])
def fullblock_conjugated(iv,n):
 padded=((n+7)//8)*8
 standard=Blowfish.new(KEY,Blowfish.MODE_OFB,iv=word_reverse(iv)).encrypt(bytes(padded))
 transformed=b"".join(word_reverse(standard[i:i+8]) for i in range(0,padded,8))
 return transformed[:n]
def keystream(mode,iv,n,block=None):
 block=block or load_block()
 if mode=="ofb8":return ofb8_keystream(block,iv,n)
 if mode=="fullblock_ofb":return fullblock_recurrence(block,iv,n)
 raise ValueError(mode)

#!/usr/bin/env python3
"""Small, explicit TEA primitive and four standard stream-like modes."""
import struct
DELTA=0x9E3779B9; MASK=0xffffffff

def _words(block,endian): return struct.unpack(('>' if endian=='be' else '<')+'2I',block)
def _key(key,endian): return struct.unpack(('>' if endian=='be' else '<')+'4I',key)
def _pack(a,b,endian): return struct.pack(('>' if endian=='be' else '<')+'2I',a,b)
def encrypt_block(block,key,endian='be'):
 if len(block)!=8 or len(key)!=16: raise ValueError('TEA requires 8-byte block and 16-byte key')
 v0,v1=_words(block,endian); k=_key(key,endian); s=0
 for _ in range(32):
  s=(s+DELTA)&MASK
  v0=(v0+((((v1<<4)&MASK)+k[0]) ^ (v1+s) ^ ((v1>>5)+k[1])))&MASK
  v1=(v1+((((v0<<4)&MASK)+k[2]) ^ (v0+s) ^ ((v0>>5)+k[3])))&MASK
 return _pack(v0,v1,endian)
def decrypt_block(block,key,endian='be'):
 if len(block)!=8 or len(key)!=16: raise ValueError('TEA requires 8-byte block and 16-byte key')
 v0,v1=_words(block,endian); k=_key(key,endian); s=(DELTA*32)&MASK
 for _ in range(32):
  v1=(v1-((((v0<<4)&MASK)+k[2]) ^ (v0+s) ^ ((v0>>5)+k[3])))&MASK
  v0=(v0-((((v1<<4)&MASK)+k[0]) ^ (v1+s) ^ ((v1>>5)+k[1])))&MASK
  s=(s-DELTA)&MASK
 return _pack(v0,v1,endian)
def crypt(data,key,iv,mode,endian='be',decrypt=True):
 if len(iv)!=8: raise ValueError('IV must be 8 bytes')
 if mode not in ('cfb8','ncfb','ofb','ctr'): raise ValueError('mode')
 out=bytearray(); reg=bytearray(iv)
 if mode=='cfb8':
  for x in data:
   y=x^encrypt_block(bytes(reg),key,endian)[0]; out.append(y)
   reg[:]=reg[1:]+bytes([x if decrypt else y])
 elif mode=='ncfb':
  for off in range(0,len(data),8):
   chunk=data[off:off+8]; z=bytes(a^b for a,b in zip(chunk,encrypt_block(bytes(reg),key,endian)));out+=z
   feedback=chunk if decrypt else z
   if len(chunk)==8: reg[:]=feedback
 elif mode=='ofb':
  for off in range(0,len(data),8):
   reg[:]=encrypt_block(bytes(reg),key,endian); chunk=data[off:off+8];out+=bytes(a^b for a,b in zip(chunk,reg))
 elif mode=='ctr':
  counter=int.from_bytes(iv,'big')
  for off in range(0,len(data),8):
   chunk=data[off:off+8]; ks=encrypt_block(counter.to_bytes(8,'big'),key,endian);out+=bytes(a^b for a,b in zip(chunk,ks));counter=(counter+1)&((1<<64)-1)
 return bytes(out)

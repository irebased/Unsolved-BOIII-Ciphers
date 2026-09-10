#!/usr/bin/env python3
import json,sys
from Crypto.Cipher import AES,DES,Blowfish

def key(name,k):
 b=k.encode("ascii")
 if name=="rijndael-128": return b+b"\0"*(16-len(b))
 if name=="des": return b+b"\0"*(8-len(b))
 return b

def stream(name,k,iv,n):
 kb=key(name,k)
 if name=="rijndael-128": e=AES.new(kb,AES.MODE_ECB)
 elif name=="des": e=DES.new(kb,DES.MODE_ECB)
 elif name=="blowfish": e=Blowfish.new(kb,Blowfish.MODE_ECB)
 else: raise ValueError(name)
 reg=bytes.fromhex(iv); out=bytearray()
 for _ in range(n):
  v=e.encrypt(reg)[0];out.append(v);reg=reg[1:]+bytes([v])
 return bytes(out)

def main():
 req=json.load(sys.stdin);rows=[]
 for r in req:
  z=stream(r["cipher"],r["key"],r["iv_hex"],r["length"])
  rows.append({"id":r["id"],"keystream_hex":z.hex()})
 json.dump(rows,sys.stdout,separators=(",",":"))
if __name__=="__main__":main()

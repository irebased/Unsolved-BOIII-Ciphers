#!/usr/bin/env python3
import hashlib,json,random
from pathlib import Path
import model
HERE=Path(__file__).resolve().parent; OUT=HERE/'controls.json'
def sha(b): return hashlib.sha256(b).hexdigest()
def ref_encrypt(block,key,endian):
 bo='big' if endian=='be' else 'little';v=[int.from_bytes(block[:4],bo),int.from_bytes(block[4:],bo)];k=[int.from_bytes(key[i:i+4],bo) for i in range(0,16,4)];s=0
 for i in range(32):
  s=(s+0x9e3779b9)&0xffffffff
  v[0]=(v[0]+(((v[1]<<4)+k[0])^(v[1]+s)^((v[1]>>5)+k[1])))&0xffffffff
  v[1]=(v[1]+(((v[0]<<4)+k[2])^(v[0]+s)^((v[0]>>5)+k[3])))&0xffffffff
 return b''.join(x.to_bytes(4,bo) for x in v)
def main():
 assert model.encrypt_block(bytes(8),bytes(16),'be').hex()=='41ea3a0a94baa940'
 assert model.decrypt_block(bytes.fromhex('41ea3a0a94baa940'),bytes(16),'be')==bytes(8)
 rng=random.Random(0x544541); blocks=[]
 for endian in ('be','le'):
  for i in range(256):
   k=rng.randbytes(16); b=rng.randbytes(8); c=model.encrypt_block(b,k,endian)
   assert c==ref_encrypt(b,k,endian);assert model.decrypt_block(c,k,endian)==b
  blocks.append({'endian':endian,'random_block_roundtrips':256})
 text=(b'TEA synthetic binary layer control: '+bytes(range(32,127))+b' UTF8 \xc2\xa0 \xe2\x80\xa6. ')*8;text=text[:546].ljust(546,b'X')
 modes=[]
 for keyname,key0 in [('Zombies',b'Zombies'),('ZOMBIES',b'ZOMBIES')]:
  key=key0.ljust(16,b'\0')
  for ivname,iv in [('null',bytes(8)),('ascii0',b'0'*8)]:
   for endian in ('be','le'):
    for mode in ('cfb8','ncfb','ofb','ctr'):
     ct=model.crypt(text,key,iv,mode,endian,False);pt=model.crypt(ct,key,iv,mode,endian,True)
     assert pt==text
     modes.append({'key':keyname,'key_hex':key.hex(),'iv':ivname,'iv_hex':iv.hex(),'packing':endian,'mode':mode,'length':len(text),'plaintext_sha256':sha(text),'ciphertext_sha256':sha(ct),'roundtrip':True})
 out={'identity':'ASTRA','target_evaluated':False,'primitive':{'name':'TEA','rounds':32,'delta':'9e3779b9','block_bytes':8,'key_bytes':16,'kat':{'key_hex':'00'*16,'plaintext_hex':'00'*8,'ciphertext_hex':'41ea3a0a94baa940','packing':'be','passed':True}},'block_controls':blocks,'mode_controls':modes,'assertions':{'mode_rows':len(modes),'all_roundtrip':all(r['roundtrip'] for r in modes),'two_packings':True,'two_keys':True,'two_ivs':True,'four_modes':True},'source_hashes':{'model.py':sha((HERE/'model.py').read_bytes()),'controls.py':sha((HERE/'controls.py').read_bytes())},'limits':['Synthetic only; no Rev7 bytes were read.','The duplicate Python block equation is control-flow parity, not a distinct primitive implementation.','The zero-key KAT is a published/common TEA known-answer vector; source provenance must be pinned before target authorization.']}
 b=(json.dumps(out,sort_keys=True,indent=2)+'\n').encode()
 if OUT.exists(): assert OUT.read_bytes()==b
 else: OUT.write_bytes(b)
 print(json.dumps({'status':'PASS','rows':len(modes),'sha256':sha(b)},sort_keys=True))
if __name__=='__main__': main()

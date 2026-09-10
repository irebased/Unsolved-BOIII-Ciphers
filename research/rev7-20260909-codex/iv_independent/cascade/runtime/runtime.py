#!/usr/bin/env python3
"""Target-agnostic seven-backend ECB/CFB8 runtime for cascade interval work."""
from __future__ import annotations
import ctypes, hashlib, subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
KEY = b"Zombies"
SOURCE_COMMIT = "3bd338e2f808e985f5b229a7642d48c26615993f"
SOURCE_HASHES = {
 "bfcompat/blowfish-compat.c":"3584374a6bae4df8899e82d36255bbac0472904aed2095e3c08c57a5dd5b4cad",
 "bfcompat/blowfish.h":"bb4a14ecbd5dc92105b290d9261ed562a980c6e42b0d9b4b56e62b4b6c39665b",
 "bfcompat/libdefs.h":"cdffb7ef7bc27b6eea90b73174077c377d8260ffd111fb8de3c2bbc938e28a31",
 "bfcompat/mcrypt_modules.h":"2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180",
 "bfcompat/COPYING.LIB":"ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532",
 "twofish/twofish.c":"20e72e38b445868fe71a0274e0b9bd658c6f30cb1ad731eb3364d82e319af598",
 "twofish/twofish.h":"c233e43572b5837f9eddc3b6c3f495d91eaa858ade2f9eaf3bc2f959fe721a6b",
 "twofish/libdefs.h":"59fea1cda69837c7e4c016b36ebcc7172107491370670d3fce7dc55ed38b4ea9",
 "twofish/mcrypt_modules.h":"2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180",
 "twofish/COPYING.LIB":"ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532",
 "loki97/loki97.c":"4e18d184ec55776edab065cee35ac44a9269b4160d7d35ad4ea277da55ae3308",
 "loki97/libdefs.h":"556ec4fcebae614cd90d05a2fead50d9355ff39f65b44c8f4044c7f209074c6e",
 "loki97/mcrypt_modules.h":"2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180",
 "loki97/COPYING.LIB":"ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532",
}

def sha(path: Path) -> str:
 return hashlib.sha256(path.read_bytes()).hexdigest()

def verify_sources() -> None:
 for rel,want in SOURCE_HASHES.items():
  got=sha(HERE/'source'/rel)
  if got != want: raise AssertionError((rel,got,want))

def build_source_libraries(build_dir: Path) -> dict:
 """Build only into caller-owned temporary directory; returns provenance."""
 verify_sources(); build_dir.mkdir(parents=True,exist_ok=True)
 specs={
  'bfcompat':('bfcompat/blowfish-compat.c','libbfcompat.so'),
  'twofish':('twofish/twofish.c','libtwofish.so'),
  'loki97':('loki97/loki97.c','libloki97.so'),
 }
 rows={}
 outputs=[build_dir/outname for _src,outname in specs.values()]
 existing=[str(x) for x in outputs if x.exists()]
 if existing: raise FileExistsError('refusing existing build outputs: '+', '.join(existing))
 for name,(src,outname) in specs.items():
  sub=src.split('/')[0]; out=build_dir/outname
  cmd=['clang','-shared','-fPIC','-O2','-I',str(HERE/'source'/sub),str(HERE/'source'/src),'-o',str(out)]
  subprocess.run(cmd,check=True,capture_output=True)
  rows[name]={'command':cmd,'path':str(out),'sha256':sha(out)}
 rows['compiler']=subprocess.check_output(['clang','--version'],text=True).splitlines()[0]
 return rows

class Backend:
 name: str; block_size: int
 def encrypt_block(self, value: bytes) -> bytes: raise NotImplementedError
 def cfb8(self, data: bytes, iv: bytes, decrypt: bool) -> bytes:
  if len(iv)!=self.block_size: raise ValueError('IV length')
  reg=iv; out=bytearray()
  for value in data:
   transformed=value ^ self.encrypt_block(reg)[0]
   ciphertext=value if decrypt else transformed
   out.append(transformed); reg=reg[1:]+bytes([ciphertext])
  return bytes(out)
 def encrypt_cfb8(self,data:bytes,iv:bytes)->bytes:return self.cfb8(data,iv,False)
 def decrypt_cfb8(self,data:bytes,iv:bytes)->bytes:return self.cfb8(data,iv,True)
 def interval_decrypt(self, known_ciphertext: bytes, absolute_offset: int=0) -> dict:
  """Decrypt bytes whose preceding full register is inside the known interval."""
  b=self.block_size
  plain=bytes(known_ciphertext[i]^self.encrypt_block(known_ciphertext[i-b:i])[0] for i in range(b,len(known_ciphertext)))
  return {'offset':absolute_offset+min(b,len(known_ciphertext)),'block_size':b,'plaintext':plain}

class PyCryptoBackend(Backend):
 def __init__(self,name,key):
  from Crypto.Cipher import AES,DES,Blowfish,ARC2
  modules={'aes128':AES,'des':DES,'blowfish':Blowfish,'rc2':ARC2}; m=modules[name]
  kwargs={'effective_keylen':1024} if name=='rc2' else {}
  self.name=name; self.block_size=m.block_size; self.key=key; self.ecb=m.new(key,m.MODE_ECB,**kwargs)
 def encrypt_block(self,value):
  if len(value)!=self.block_size:raise ValueError('block length')
  return self.ecb.encrypt(value)

class SourceBackend(Backend):
 def __init__(self,name,library,key=KEY):
  cfg={
   'bfcompat':('blowfish_compat',8,key,len(key),key),
   'twofish':('twofish',16,key+b'\0'*(32-len(key)),16,key),
   'loki97':('loki97',16,key+b'\0'*(32-len(key)),16,key),
  }[name]
  prefix,b,memory,declared,input_key=cfg; self.name=name;self.block_size=b;self.input_key=input_key
  self.key_memory=memory;self.declared_key_length=declared;self.library_path=str(library);self.lib=ctypes.CDLL(str(library)); p=prefix+'_LTX_'
  gs=getattr(self.lib,p+'_mcrypt_get_size');gb=getattr(self.lib,p+'_mcrypt_get_block_size');gs.restype=gb.restype=ctypes.c_int
  self.sk=getattr(self.lib,p+'_mcrypt_set_key');self.en=getattr(self.lib,p+'_mcrypt_encrypt');self.de=getattr(self.lib,p+'_mcrypt_decrypt')
  self.sk.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint];self.sk.restype=ctypes.c_int
  self.en.argtypes=self.de.argtypes=[ctypes.c_void_p,ctypes.c_void_p];self.en.restype=self.de.restype=None
  self.context_bytes=gs(); assert gb()==b
  self.ctx=ctypes.create_string_buffer(self.context_bytes); self.kbuf=ctypes.create_string_buffer(memory,len(memory))
  if self.sk(self.ctx,self.kbuf,declared)!=0:raise ValueError('set_key failed')
 def _call(self,value,fn):
  if len(value)!=self.block_size:raise ValueError('block length')
  buf=ctypes.create_string_buffer(value,len(value));fn(self.ctx,buf);return buf.raw
 def encrypt_block(self,value):return self._call(value,self.en)
 def decrypt_block(self,value):return self._call(value,self.de)

def registry(build_rows:dict) -> dict[str,Backend]:
 return {
  'aes128':PyCryptoBackend('aes128',KEY+b'\0'*9),
  'des':PyCryptoBackend('des',KEY+b'\0'),
  'blowfish':PyCryptoBackend('blowfish',KEY),
  'bfcompat':SourceBackend('bfcompat',build_rows['bfcompat']['path']),
  'rc2':PyCryptoBackend('rc2',KEY),
  'twofish':SourceBackend('twofish',build_rows['twofish']['path']),
  'loki97':SourceBackend('loki97',build_rows['loki97']['path']),
 }

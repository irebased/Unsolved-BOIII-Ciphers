#!/usr/bin/env python3
"""Build the pinned libmcrypt Blowfish-compat source into an explicit path."""
import argparse,ctypes,hashlib,json,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
EXPECTED={"blowfish-compat.c":"3584374a6bae4df8899e82d36255bbac0472904aed2095e3c08c57a5dd5b4cad","blowfish.h":"bb4a14ecbd5dc92105b290d9261ed562a980c6e42b0d9b4b56e62b4b6c39665b","COPYING.LIB":"ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532","libdefs.h":"cdffb7ef7bc27b6eea90b73174077c377d8260ffd111fb8de3c2bbc938e28a31","mcrypt_modules.h":"2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180"}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def check():assert {n:sha(HERE/n) for n in EXPECTED}==EXPECTED
def build(output):
 check()
 if output.exists():raise SystemExit("refusing existing output: "+str(output))
 output.parent.mkdir(parents=True,exist_ok=True)
 cmd=["clang","-shared","-fPIC","-O2","-I",str(HERE),str(HERE/"blowfish-compat.c"),"-o",str(output)]
 subprocess.run(cmd,check=True,timeout=60,capture_output=True)
 return cmd
def load(path):
 lib=ctypes.CDLL(str(path));size=lib.blowfish_compat_LTX__mcrypt_get_size;size.restype=ctypes.c_int
 setkey=lib.blowfish_compat_LTX__mcrypt_set_key;setkey.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_int];setkey.restype=ctypes.c_int
 enc=lib.blowfish_compat_LTX__mcrypt_encrypt;enc.argtypes=[ctypes.c_void_p,ctypes.c_void_p]
 def block(key,value):
  assert len(value)==8;ctx=ctypes.create_string_buffer(size());assert setkey(ctx,key,len(key))==0
  buf=ctypes.create_string_buffer(value,8);enc(ctx,buf);return buf.raw
 return block
def main():
 p=argparse.ArgumentParser();p.add_argument("--check-sources",action="store_true");p.add_argument("--output",type=Path);a=p.parse_args()
 if a.check_sources:check();print(json.dumps({"identity":"ASTRA","sources_verified":True,"hashes":EXPECTED},sort_keys=True));return
 if a.output is None:p.error("--output required unless --check-sources")
 cmd=build(a.output);print(json.dumps({"identity":"ASTRA","output":str(a.output),"sha256":sha(a.output),"command":cmd},indent=2))
if __name__=="__main__":main()

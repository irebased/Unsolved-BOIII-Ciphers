#!/usr/bin/env python3
"""Reproduce the pinned libmcrypt standard/compat raw-key block check."""
from __future__ import annotations
import argparse,ctypes,hashlib,json,platform,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
SOURCE=HERE/"source";BUILD=HERE/"source_build";NATIVE=HERE/"native_compat"
DEFAULT=HERE/"source_check.json"
EXPECTED={"blowfish.c":"c384305eb4f5d7134e60f6deaed92bba94757826da4b8d35de8326422c286736","blowfish-compat.c":"3584374a6bae4df8899e82d36255bbac0472904aed2095e3c08c57a5dd5b4cad","blowfish.h":"bb4a14ecbd5dc92105b290d9261ed562a980c6e42b0d9b4b56e62b4b6c39665b"}
KEY=b"Zombies"
BLOCKS=(bytes(range(8)),b"00000000",bytes.fromhex("83b57b2c3434697f"))
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def word_reverse(value):return value[3::-1]+value[7:3:-1]
def compile_sources():
 assert {x:sha(SOURCE/x) for x in EXPECTED}==EXPECTED
 common=["clang","-shared","-fPIC","-O2","-Isource_build","-Isource"]
 commands=[common+["source/blowfish.c","-o","source_build/libblowfish.so"],common+["source/blowfish-compat.c","-o","source_build/libblowfish_compat.so"]]
 for command in commands:subprocess.run(command,cwd=HERE,check=True,timeout=60,capture_output=True)
 return commands
def load_algorithm(path,prefix):
 lib=ctypes.CDLL(str(path));get_size=getattr(lib,prefix+"_LTX__mcrypt_get_size");set_key=getattr(lib,prefix+"_LTX__mcrypt_set_key");encrypt=getattr(lib,prefix+"_LTX__mcrypt_encrypt")
 get_size.restype=ctypes.c_int;size=get_size()
 set_key.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_int];set_key.restype=ctypes.c_int
 encrypt.argtypes=[ctypes.c_void_p,ctypes.c_void_p];encrypt.restype=None
 def block(key,value):
  ctx=ctypes.create_string_buffer(size);assert set_key(ctx,key,len(key))==0
  buf=ctypes.create_string_buffer(value,8);encrypt(ctx,buf);return buf.raw
 return block,size
def produce(output):
 commands=compile_sources()
 standard,standard_size=load_algorithm(BUILD/"libblowfish.so","blowfish")
 compat,compat_size=load_algorithm(BUILD/"libblowfish_compat.so","blowfish_compat")
 rows=[]
 for block in BLOCKS:
  actual=compat(KEY,block)
  assert actual==word_reverse(standard(KEY,word_reverse(block)))
  native=bytes.fromhex(subprocess.check_output([str(NATIVE),"--block-encrypt",KEY.hex(),block.hex()],text=True).strip())
  assert actual==native
  rows.append({"key_hex":KEY.hex(),"block_hex":block.hex(),"fixture_provenance":"known Rev7 first 8 bytes from task context" if block==BLOCKS[2] else "synthetic fixed block","ciphertext_hex":actual.hex(),"ciphertext_sha256":hashlib.sha256(actual).hexdigest()})
 result={"identity":"ASTRA","target_evaluated":False,"rev7_file_read":False,"rev7_decryption_or_search_run":False,"rev7_prefix_fixture_used":True,"source":{"repository":"https://github.com/Distrotech/libmcrypt","commit":"3bd338e2f808e985f5b229a7642d48c26615993f","file_sha256":EXPECTED,"compiled_sources_unmodified":True},"build":{"commands":commands,"compiler_version":subprocess.check_output(["clang","--version"],text=True).splitlines()[0],"binary_sha256":{"standard":sha(BUILD/"libblowfish.so"),"compat":sha(BUILD/"libblowfish_compat.so")},"abi":{"platform":platform.platform(),"byteorder":sys.byteorder,"pointer_bytes":ctypes.sizeof(ctypes.c_void_p),"word32_bytes":4,"standard_context_bytes":standard_size,"compat_context_bytes":compat_size},"minimal_header_sha256":{"libdefs.h":sha(BUILD/"libdefs.h"),"mcrypt_modules.h":sha(BUILD/"mcrypt_modules.h")}},"actual_standard_and_compat_sources_word_reverse_relationship":True,"raw7_zombies_matches_native_word_reverse_adapter":True,"relationship_checked_rows":len(rows),"rows":rows}
 output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 return result
def verify_existing(path):
 data=json.loads(path.read_text());assert data["identity"]=="ASTRA" and data["target_evaluated"] is False
 assert data["actual_standard_and_compat_sources_word_reverse_relationship"] and data["raw7_zombies_matches_native_word_reverse_adapter"]
 assert [(x["key_hex"],x["block_hex"],x["ciphertext_hex"]) for x in data["rows"]]==[(KEY.hex(),"0001020304050607","b24067da92018993"),(KEY.hex(),"3030303030303030","ba4e4c46586fbdc0"),(KEY.hex(),"83b57b2c3434697f","7b049752cda58f6f")]
 return data
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--output",type=Path,default=DEFAULT);ap.add_argument("--verify-existing",action="store_true");a=ap.parse_args()
 if a.verify_existing:
  verify_existing(a.output);print(json.dumps({"identity":"ASTRA","verified_existing":str(a.output),"sha256":sha(a.output)},sort_keys=True));return
 if a.output.exists():raise SystemExit(f"refusing existing result: {a.output}")
 produce(a.output);print(json.dumps({"identity":"ASTRA","result":str(a.output),"sha256":sha(a.output)},sort_keys=True))
if __name__=="__main__":main()

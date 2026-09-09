#!/usr/bin/env python3
"""Preregistered raw-seven-byte BF-compat CFB8 Rev7 search.

Self-test hashes frozen artifacts and Rev7 file bytes only. It does not parse
or evaluate the target. --run-target starts four fresh-root searches.
"""
from __future__ import annotations
import argparse,ctypes,hashlib,json,math,os,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
HEX_CFB=HERE.parent
REPO=HERE.parents[3]
sys.path[:0]=[str(HERE),str(HEX_CFB)]
import controls as ref
import prototype as core
IDENTITY="ASTRA"; NODE_LIMIT=1_000_000_000; FULL_WEIGHT=math.factorial(16)
CIPHER="blowfish_compat"; ORIENTATIONS=("forward","reverse","byte_reverse","nibble_swap")
KEY=b"Zombies"; IV=b"0"*8
NATIVE=HERE/"native_compat"; ACTUAL_LIB=HERE/"source_build/libblowfish_compat.so"
CONTROLS=HERE/"controls.json"; SOURCE_REPRO=HERE/"source_check_reproduction.json"
SOURCE_ENV=HERE/"source_check_environment.json"; GATE=HERE/"target_gate.json"
REV7=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
EXPECTED_REV7_TEXT_SHA256="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
EXPECTED={
"native_compat.cpp":"c8527d2bf43494944475a20e0ffc8a99358243c8f188d394335af4ec9b0f8cb7",
"native_compat":"f19874f064bbe3b37dec359554932d2a30b2f4f7abd889228152f4e194d56201",
"controls.py":"a10cb0636113aefcd1501bf7497a31899616ed288ef1848040a663723c761980",
"controls.json":"8105dafde232eb1d245e22a0224b34b5f863dfacfa5a223758a08a46db52a835",
"prototype.py":"416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b",
"wasm_bfcompat_vectors.json":"d7c59ce2be4c790e26fa86365d883a9e6169785496ad326ff78d5b4f93b334bc",
"source_check.py":"3945fbebcc7ae8c8bd8df0b450590e149e7cbd86443bd9d92ddbae90ab91e69d",
"source_check_reproduction.json":"123724d5575fa7c2be2868d8218f774f775a395eae693e2049caa703eee47295",
"source_check_environment.json":"5688cef80310430e3568e5b9908899057f5dda81f2a5a42e0ce40c9115fce919",
"source/blowfish.c":"c384305eb4f5d7134e60f6deaed92bba94757826da4b8d35de8326422c286736",
"source/blowfish-compat.c":"3584374a6bae4df8899e82d36255bbac0472904aed2095e3c08c57a5dd5b4cad",
"source/blowfish.h":"bb4a14ecbd5dc92105b290d9261ed562a980c6e42b0d9b4b56e62b4b6c39665b",
"source/COPYING.LIB":"ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532",
"source_build/libdefs.h":"cdffb7ef7bc27b6eea90b73174077c377d8260ffd111fb8de3c2bbc938e28a31",
"source_build/mcrypt_modules.h":"2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180",
"source_build/libblowfish.so":"2aa1f36a8b30646c6e4bcee83e468628ec0d36f4272801fe649ec3acc04fb83e",
"source_build/libblowfish_compat.so":"62ba2b2d1d104aa16c8a855b8bd29af3f6ed987c0008b3a8ba20c22f12e0a319",
"rev7_mdx":"085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"}
RAW_STATS=("nodes","rejected_plaintext","complete","maximum_depth","aborted_at_node_limit","rejected_completion_weight","terminal_completion_weight","rejected_unterminated_endpoint")
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def artifact_paths():
 return {"native_compat.cpp":HERE/"native_compat.cpp","native_compat":NATIVE,
 "controls.py":HERE/"controls.py","controls.json":CONTROLS,"prototype.py":HEX_CFB/"prototype.py",
 "wasm_bfcompat_vectors.json":HERE/"wasm_bfcompat_vectors.json","source_check.py":HERE/"source_check.py",
 "source_check_reproduction.json":SOURCE_REPRO,"source_check_environment.json":SOURCE_ENV,
 "source/blowfish.c":HERE/"source/blowfish.c","source/blowfish-compat.c":HERE/"source/blowfish-compat.c",
 "source/blowfish.h":HERE/"source/blowfish.h","source/COPYING.LIB":HERE/"source/COPYING.LIB",
 "source_build/libdefs.h":HERE/"source_build/libdefs.h",
 "source_build/mcrypt_modules.h":HERE/"source_build/mcrypt_modules.h",
 "source_build/libblowfish.so":HERE/"source_build/libblowfish.so",
 "source_build/libblowfish_compat.so":ACTUAL_LIB,"rev7_mdx":REV7}
def artifact_hashes():return {name:sha(path) for name,path in artifact_paths().items()}
def atomic(path,value):
 tmp=path.with_name(path.name+".tmp");tmp.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n");os.replace(tmp,path)
def scope():
 return {"identity":IDENTITY,
 "hypothesis":"libmcrypt Blowfish-compat block primitive with raw seven-byte Zombies key, CFB8, ASCII-zero IV",
 "cipher":CIPHER,"key_hex":KEY.hex(),"key_length":len(KEY),"iv_hex":IV.hex(),
 "mode":"CFB8","segment_size_bits":8,
 "endpoint":{"ascii_bytes":"TAB LF CR and 32..126","utf8_sequences":["e28093","e28094","e28098","e28099"],"terminal_state":0},
 "orientations":list(ORIENTATIONS),"cells":4,"node_limit_per_cell":NODE_LIMIT,
 "search_semantics":"Each cell starts a fresh DFS root; node caps are non-additive.",
 "completion_certificate":"16! mapping weight; capped cells retain explicitly uncovered weight.",
 "synthetic_prefix_replay":False}
def require_gate():
 assert artifact_hashes()==EXPECTED
 c=json.loads(CONTROLS.read_text())
 assert c["identity"]==IDENTITY and c["target_evaluated"] is False and c["assertions"]["all_passed"]
 assert c["assertions"]["native_stats_weights_maps_plaintexts_equal_python"]
 assert c["model"]["fixed_key_hex"]==KEY.hex() and c["model"]["iv_hex"]==IV.hex()
 s=json.loads(SOURCE_REPRO.read_text())
 assert s["identity"]==IDENTITY and s["target_evaluated"] is False
 assert s["source"]["compiled_sources_unmodified"] and s["raw7_zombies_matches_native_word_reverse_adapter"]
 assert s["actual_standard_and_compat_sources_word_reverse_relationship"]
 assert s["build"]["binary_sha256"]["compat"]==EXPECTED["source_build/libblowfish_compat.so"]
 assert s["build"]["abi"]==json.loads(SOURCE_ENV.read_text())["abi"]
 g=json.loads(GATE.read_text())
 assert g["identity"]==IDENTITY and g["target_evaluated"] is False
 assert g["scope"]==scope() and g["artifact_hashes"]==EXPECTED
 assert g["driver_sha256"]==sha(Path(__file__))
 return g,sha(GATE)
def extract_rev7():
 text=REV7.read_text(encoding="utf-8");start=text.index("`83 B57B2")+1;end=text.index("`",start)
 value="".join(text[start:end].split()).upper()
 assert len(value)==1092 and hashlib.sha256(value.encode()).hexdigest()==EXPECTED_REV7_TEXT_SHA256
 oriented=core.orientations(value);assert tuple(oriented)==ORIENTATIONS
 return value,oriented
def native(display):
 out=json.loads(subprocess.check_output([str(NATIVE),CIPHER,str(NODE_LIMIT),display,"-"],text=True))
 assert out["identity"]==IDENTITY and out["cipher"]==CIPHER and out["node_limit"]==NODE_LIMIT
 assert out["complete"]==len(out["solutions"]) and set(RAW_STATS)<=set(out)
 assert out["expected_completion_weight"]==FULL_WEIGHT
 assert out["certificate_weight"]==out["rejected_completion_weight"]+out["terminal_completion_weight"]
 return out
class ActualCompatECB:
 def __init__(self):
  self.lib=ctypes.CDLL(str(ACTUAL_LIB))
  self.get_size=getattr(self.lib,"blowfish_compat_LTX__mcrypt_get_size")
  self.set_key=getattr(self.lib,"blowfish_compat_LTX__mcrypt_set_key")
  self.encrypt_fn=getattr(self.lib,"blowfish_compat_LTX__mcrypt_encrypt")
  self.get_size.restype=ctypes.c_int
  self.set_key.argtypes=[ctypes.c_void_p,ctypes.c_char_p,ctypes.c_int];self.set_key.restype=ctypes.c_int
  self.encrypt_fn.argtypes=[ctypes.c_void_p,ctypes.c_void_p];self.encrypt_fn.restype=None
  self.size=self.get_size();assert self.size==4168
 def encrypt(self,block):
  assert len(block)==8
  ctx=ctypes.create_string_buffer(self.size);assert self.set_key(ctx,KEY,len(KEY))==0
  buf=ctypes.create_string_buffer(block,8);self.encrypt_fn(ctx,buf);return buf.raw
def actual_cfb8(data,ecb,decrypt):
 reg=IV;out=bytearray()
 for value in data:
  transformed=value^ecb.encrypt(reg)[0];ct=value if decrypt else transformed
  out.append(transformed);reg=reg[1:]+bytes([ct])
 return bytes(out)
def endpoint_accepts(data):
 state=0
 for value in data:
  nxt=core.historical_utf8_transition(state,0,value)
  if nxt is None:return False
  state=nxt
 return state==0
def decode_display(displayed,mapping):
 return bytes((mapping[core.HEX.index(displayed[i])]<<4)|mapping[core.HEX.index(displayed[i+1])] for i in range(0,len(displayed),2))
def validate_solutions(display,solutions):
 checked=[];actual=ActualCompatECB();reference=ref.CompatECB(KEY)
 for solution in solutions:
  mapping=tuple(solution["mapping"]);plain=bytes.fromhex(solution["plaintext_hex"])
  assert len(mapping)==16 and sorted(mapping)==list(range(16))
  ciphertext=decode_display(display,mapping)
  assert plain==actual_cfb8(ciphertext,actual,True)==ref.cfb8(ciphertext,reference,IV,True)
  assert actual_cfb8(plain,actual,False)==ciphertext
  assert ref.cfb8(plain,reference,IV,False)==ciphertext
  assert core.display_encode(ciphertext,mapping)==display and endpoint_accepts(plain)
  checked.append({"mapping_display_to_nibble":list(mapping),"plaintext_hex":plain.hex(),
  "plaintext_sha256":hashlib.sha256(plain).hexdigest(),"ciphertext_sha256":hashlib.sha256(ciphertext).hexdigest(),
  "actual_unmodified_libmcrypt_compat_cfb8_validated":True,"separate_python_manual_cfb8_validated":True,
  "actual_and_reference_reencrypt_validated":True,"exact_inverse_mapping_display_reconstruction":True,
  "endpoint_fsa_terminal_state":0})
 return checked
def record_stats(out):
 cert=out["certificate_weight"];complete=not out["aborted_at_node_limit"]
 if complete:assert cert==FULL_WEIGHT
 else:assert out["nodes"]==NODE_LIMIT and cert<FULL_WEIGHT
 return {**{k:out[k] for k in RAW_STATS},"node_limit":NODE_LIMIT,"certificate_weight":cert,
 "expected_factorial_weight":FULL_WEIGHT,"search_status":"complete" if complete else "capped",
 "certificate_complete":complete and cert==FULL_WEIGHT,"unaccounted_mapping_weight":FULL_WEIGHT-cert,
 "elapsed_seconds":out["elapsed_seconds"],
 "capped_weight_interpretation":None if complete else "lower bound on eliminated full mappings; uncovered weight remains"}
def initial_result(gate_sha,cipher_sha):
 return {"identity":IDENTITY,"target_evaluated":True,
 "configuration":{**scope(),"ciphertext_sha256":cipher_sha,"gate_sha256":gate_sha,
 "driver_sha256":sha(Path(__file__)),"artifact_hashes":EXPECTED},"status":"running","cells":[]}
def run_target(output,checkpoint,resume):
 if output.exists():raise SystemExit(f"refusing existing target output: {output}")
 _gate,gate_sha=require_gate();rev7,oriented=extract_rev7()
 cipher_sha=hashlib.sha256(rev7.encode()).hexdigest();config=initial_result(gate_sha,cipher_sha)["configuration"]
 if checkpoint.exists():
  if not resume:raise SystemExit(f"refusing checkpoint without --resume: {checkpoint}")
  result=json.loads(checkpoint.read_text());assert result["configuration"]==config
 else:
  if resume:raise SystemExit("--resume requested but checkpoint absent")
  result=initial_result(gate_sha,cipher_sha)
 done={x["orientation"] for x in result["cells"]}
 for orientation in ORIENTATIONS:
  if orientation in done:continue
  displayed=oriented[orientation];out=native(displayed);survivors=validate_solutions(displayed,out["solutions"])
  row={"identity":IDENTITY,"cipher":CIPHER,"orientation":orientation,
  "displayed_sha256":hashlib.sha256(displayed.encode()).hexdigest(),"stats":record_stats(out),
  "survivor_count":len(survivors),"survivors":survivors,
  "all_survivors_actual_c_and_independent_python_reencrypt_mapping_and_terminal_fsa_validated":True}
  result["cells"].append(row);atomic(checkpoint,result)
  print(json.dumps({"cell":orientation,"status":row["stats"]["search_status"],"nodes":row["stats"]["nodes"],
  "certificate_weight":row["stats"]["certificate_weight"],"survivors":len(survivors),
  "elapsed_seconds":row["stats"]["elapsed_seconds"]}),flush=True)
 assert len(result["cells"])==4;result["status"]="complete"
 result["summary"]={"complete_cells":sum(x["stats"]["certificate_complete"] for x in result["cells"]),
 "capped_cells":sum(not x["stats"]["certificate_complete"] for x in result["cells"]),
 "survivors":sum(x["survivor_count"] for x in result["cells"]),
 "total_elapsed_seconds":sum(x["stats"]["elapsed_seconds"] for x in result["cells"])}
 atomic(checkpoint,result);os.replace(checkpoint,output)
 print(json.dumps({"identity":IDENTITY,"target_results":str(output),"sha256":sha(output),"summary":result["summary"]},indent=2),flush=True)
def main():
 ap=argparse.ArgumentParser();act=ap.add_mutually_exclusive_group(required=True)
 act.add_argument("--selftest",action="store_true");act.add_argument("--run-target",action="store_true")
 ap.add_argument("--target-output",type=Path,default=HERE/"target_results.json")
 ap.add_argument("--checkpoint",type=Path,default=HERE/"target_checkpoint.json")
 ap.add_argument("--resume",action="store_true");args=ap.parse_args()
 if args.selftest:
  if args.resume:ap.error("--resume is target-only")
  _g,gate_sha=require_gate()
  print(json.dumps({"identity":IDENTITY,"target_evaluated":False,
  "rev7_handling":"file bytes hashed only; ciphertext not extracted, parsed, oriented, or evaluated",
  "gate_sha256":gate_sha,"driver_sha256":sha(Path(__file__)),"scope":scope()},indent=2,sort_keys=True))
 else:run_target(args.target_output,args.checkpoint,args.resume)
if __name__=="__main__":main()

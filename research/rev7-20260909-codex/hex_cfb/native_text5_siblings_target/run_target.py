#!/usr/bin/env python3
"""Inert RC2/Loki97 five-punctuation target extension; no gate means no target access."""
from __future__ import annotations
import argparse,hashlib,json,math,os,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;HEX_CFB=HERE.parent;PARENT=HEX_CFB/"native_text5";REPO=HERE.parents[3]
sys.path[:0]=[str(PARENT),str(HEX_CFB),str(HERE)]
import controls as ref
import endpoint5
import prototype as core
import preflight
IDENTITY="ASTRA";LIMIT=1_000_000_000;FULL=math.factorial(16)
CIPHERS=("rc2","loki97");ORIENTATIONS=("forward","reverse","byte_reverse","nibble_swap")
NATIVE=PARENT/"native_text5";CONTROLS=PARENT/"controls.json";GATE=HERE/"target_gate.json";REV7=preflight.REV7
TEXT_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
EXPECTED={"README.md":"092c8bd4d290f01ee5d4b76fca61478f8b96d36b2b7db32bbc63523db06a9db5","controls.py":"fb1194f4e577a7e5b23e66693c87d212ac6554df4d7e1299dada37ec69c54859","controls.json":"5bc6fda80e29a9d723cc4a72436406dc0275b456635a484a2d394a6553e77891","endpoint5.py":"64516c9730f7d4381d166888b19eda612873e9edee3a2f02f8a1091e50d2529e","native_text5.cpp":"81bd9902f3f5fb0585214c2c93117523426cdc61edb524334d64412d4a5d724f","native_text5":"3b84a08161e1dde80ad5b12613e7cd6e6a0905411e4f7e9098cd5f55792fbd0d","source/rc2.c":"37c9398507cea1685255da9550f5a3a55b529b66e1bbc9a35e1996fecae7dc19","source/rc2.h":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","source/loki97.c":"4e18d184ec55776edab065cee35ac44a9269b4160d7d35ad4ea277da55ae3308","source/COPYING.LIB":"ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532","source_build/libdefs.h":"556ec4fcebae614cd90d05a2fead50d9355ff39f65b44c8f4044c7f209074c6e","source_build/mcrypt_modules.h":"2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180","source_build/rc2.o":"022a0517d79e7dfc9566ca3cf04462a7ffb62aaf9f2d4d0d8edb2ca0a2803b4e","source_build/loki97.o":"2c417e8b2b6f70e2f175d58dbb8b011be234b2fbc4c8c838960817fec13ddc06","source_build/librc2.so":"83dd446b5453e47252e8803d1143b4d235d39b1cba6efe557a94b273d318b2d6","source_build/libloki97.so":"297b73e3926d82cc52c1023c9bba53a3d1102470f3633ea2c8ed6f243347c175","prototype.py":"416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b","rev7_mdx":"085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"}
RAW=("nodes","rejected_plaintext","complete","maximum_depth","aborted_at_node_limit","rejected_completion_weight","terminal_completion_weight","rejected_unterminated_endpoint")
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
EXTENSION_FILES=("run_target.py","preflight.py","driver_controls.py","driver_controls.json","build_gate.py","target_gate.template.json","README.md")
def extension_hashes():return {x:sha(HERE/x) for x in EXTENSION_FILES}
def paths():
 d={k:PARENT/k for k in EXPECTED if k not in ("prototype.py","rev7_mdx")};d["prototype.py"]=HEX_CFB/"prototype.py";d["rev7_mdx"]=REV7;return d
def hashes():return {k:sha(v) for k,v in paths().items()}
def atomic(path,value):
 t=path.with_name(path.name+".tmp");t.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n");os.replace(t,path)
def scope():return {"identity":IDENTITY,"endpoint":{"ascii":"TAB LF CR and 32..126","utf8":["e28093","e28094","e28098","e28099","e280a6"],"terminal_state":0},"ciphers":list(CIPHERS),"cipher_conventions":{"rc2":"raw7 Zombies from pinned libmcrypt source","loki97":"selected16 with explicit zeroed32 backing from pinned libmcrypt source"},"mode":"CFB8","iv":"ASCII zero bytes at block size","orientations":list(ORIENTATIONS),"cells":8,"node_limit_per_cell":LIMIT,"search_semantics":"Each cell starts from a fresh root; caps are not additive.","certificate":"16! mapping weight when complete"}
def require_gate():
 preflight.validate();assert hashes()==EXPECTED
 c=json.loads(CONTROLS.read_text());assert c["identity"]==IDENTITY and c["target_evaluated"] is False and c["rev7_file_read"] is False and c["assertions"]["all_passed"]
 assert c["endpoint"]["utf8"]==scope()["endpoint"]["utf8"] and c["assertions"]["full16_prefix_stats_solutions_exact"]
 g=json.loads(GATE.read_text());assert g["identity"]==IDENTITY and g["target_evaluated"] is False and g["scope"]==scope() and g["artifact_hashes"]==EXPECTED and g["driver_sha256"]==sha(Path(__file__)) and g["extension_hashes"]==extension_hashes()
 return g,sha(GATE)
def extract():
 text=REV7.read_text();start=text.index("`83 B57B2")+1;end=text.index("`",start);value="".join(text[start:end].split()).upper();assert len(value)==1092 and hashlib.sha256(value.encode()).hexdigest()==TEXT_SHA;o=core.orientations(value);assert tuple(o)==ORIENTATIONS;return value,o
def native(cipher,display,limit=LIMIT,seed=None):
 seed_arg="-" if seed is None else ",".join(f"{k}:{v}" for k,v in sorted(seed.items()))
 n=json.loads(subprocess.check_output([str(NATIVE),cipher,str(limit),display,seed_arg],text=True));assert n["identity"]==IDENTITY and n["cipher"]==cipher and n["node_limit"]==limit and n["complete"]==len(n["solutions"]) and set(RAW)<=set(n);assert n["certificate_weight"]==n["rejected_completion_weight"]+n["terminal_completion_weight"];return n
def decode_display(display,mapping):return bytes((mapping[core.HEX.index(display[i])]<<4)|mapping[core.HEX.index(display[i+1])] for i in range(0,len(display),2))
def validate(cipher,display,solutions):
 checked=[];e=ref.ECB(cipher)
 for s in solutions:
  m=tuple(s["mapping"]);plain=bytes.fromhex(s["plaintext_hex"]);assert len(m)==16 and sorted(m)==list(range(16));ct=decode_display(display,m);assert plain==ref.cfb8(ct,e,True);assert ref.cfb8(plain,ref.ECB(cipher),False)==ct;assert core.display_encode(ct,m)==display and endpoint5.accepts(plain)
  checked.append({"mapping_display_to_nibble":list(m),"plaintext_hex":plain.hex(),"plaintext_sha256":hashlib.sha256(plain).hexdigest(),"ciphertext_sha256":hashlib.sha256(ct).hexdigest(),"independent_python_decrypt_reencrypt":True,"mapping_bijection":True,"exact_display_reconstruction":True,"endpoint_terminal_state":0})
 return checked
def stats(n):
 cert=n["certificate_weight"];complete=not n["aborted_at_node_limit"]
 if complete:assert cert==FULL
 else:assert n["nodes"]==LIMIT and cert<FULL
 return {**{k:n[k] for k in RAW},"node_limit":LIMIT,"certificate_weight":cert,"expected_factorial_weight":FULL,"certificate_complete":complete and cert==FULL,"search_status":"complete" if complete else "capped","unaccounted_mapping_weight":FULL-cert,"elapsed_seconds":n["elapsed_seconds"],"capped_interpretation":None if complete else "partial elimination only; uncovered weight remains"}
def initial(gate_sha,text_sha):return {"identity":IDENTITY,"target_evaluated":True,"status":"running","configuration":{**scope(),"ciphertext_sha256":text_sha,"gate_sha256":gate_sha,"driver_sha256":sha(Path(__file__)),"artifact_hashes":EXPECTED},"cells":[]}
def run(output,checkpoint,resume):
 if output.exists():raise SystemExit(f"refusing existing output: {output}")
 _g,gate_sha=require_gate();value,oriented=extract();config=initial(gate_sha,hashlib.sha256(value.encode()).hexdigest())["configuration"]
 if checkpoint.exists():
  if not resume:raise SystemExit(f"refusing checkpoint without --resume: {checkpoint}")
  result=json.loads(checkpoint.read_text());assert result["configuration"]==config
 else:
  if resume:raise SystemExit("--resume requested without checkpoint")
  result=initial(gate_sha,config["ciphertext_sha256"])
 done={(x["cipher"],x["orientation"]) for x in result["cells"]}
 for cipher in CIPHERS:
  for orientation in ORIENTATIONS:
   if (cipher,orientation) in done:continue
   display=oriented[orientation];n=native(cipher,display);survivors=validate(cipher,display,n["solutions"]);row={"identity":IDENTITY,"cipher":cipher,"orientation":orientation,"display_sha256":hashlib.sha256(display.encode()).hexdigest(),"stats":stats(n),"survivor_count":len(survivors),"survivors":survivors,"all_survivors_independently_verified":True};result["cells"].append(row);atomic(checkpoint,result);print(json.dumps({"cipher":cipher,"orientation":orientation,"status":row["stats"]["search_status"],"nodes":row["stats"]["nodes"],"weight":row["stats"]["certificate_weight"],"survivors":len(survivors),"seconds":row["stats"]["elapsed_seconds"]}),flush=True)
 assert len(result["cells"])==8;result["status"]="complete";result["summary"]={"complete_cells":sum(x["stats"]["certificate_complete"] for x in result["cells"]),"capped_cells":sum(not x["stats"]["certificate_complete"] for x in result["cells"]),"survivors":sum(x["survivor_count"] for x in result["cells"]),"total_elapsed_seconds":sum(x["stats"]["elapsed_seconds"] for x in result["cells"])};atomic(checkpoint,result);os.replace(checkpoint,output);print(json.dumps({"identity":IDENTITY,"output":str(output),"sha256":sha(output),"summary":result["summary"]},indent=2))
def main():
 p=argparse.ArgumentParser();a=p.add_mutually_exclusive_group(required=True);a.add_argument("--selftest",action="store_true");a.add_argument("--run-target",action="store_true");p.add_argument("--target-output",type=Path,default=HERE/"target_results.json");p.add_argument("--checkpoint",type=Path,default=HERE/"target_checkpoint.json");p.add_argument("--resume",action="store_true");x=p.parse_args()
 if x.selftest:
  if x.resume:p.error("--resume is target-only")
  z=preflight.validate();print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"rev7_handling":z["rev7_handling"],"gate_present":GATE.exists(),"driver_sha256":sha(Path(__file__)),"scope":scope()},indent=2,sort_keys=True))
 else:run(x.target_output,x.checkpoint,x.resume)
if __name__=="__main__":main()

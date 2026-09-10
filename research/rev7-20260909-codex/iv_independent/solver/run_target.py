#!/usr/bin/env python3
"""Frozen DES CFB8 IV-independent suffix target driver."""
from __future__ import annotations
import argparse,hashlib,json,math,os,subprocess,sys
from pathlib import Path
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[3];HEX_CFB=HERE.parents[1]/"hex_cfb"
sys.path[:0]=[str(HERE),str(HEX_CFB)]
import solver
import prototype as core
IDENTITY="ASTRA";LIMIT=1_000_000_000;FULL=math.factorial(16);KEY=b"Zombies\0";BS=8
ORIENTATIONS=("forward","reverse","byte_reverse","nibble_swap");NATIVE=HERE/"native";GATE=HERE/"target_gate.json";REV7=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx";TEXT_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
EXPECTED={"README.md":"801d2b96c3afa904532fa2ecf4de56702a20055af32ede9aac5f81dda4dfbb1f","solver.py":"23b8755b61276f9a3fc30b1ab385dd7296cffd95407eed9663f505553f949343","controls.py":"e897b6645511098c419695049bab34b676b11bda3ddd3e25190ebabc8329723f","controls.json":"8656075b2f0495444b82439d582f075e28030189d9985489301b9c030159926b","native.cpp":"77b169a90041f57eb506134fdcdfdde0c255377c9fad60117e158132078ea1cc","native":"f205a6493ead64be879b24e308c28839aab2bc3db383bb9e743cab24f8de1574","native_controls.py":"475f63bde26cd2bcca1defff8491a7af2e515f911866d18436ffeb2211b28020","native_controls.json":"9eb64df3639e671f2371ccd274306ee0c0af0bfed5bc1c416c6ecd996c5d211d","NATIVE_README.md":"cb59f73f55e1042315f61e443107d77d201a041862aec4484c0e3b82e602ddcc","prototype.py":"416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b","rev7_mdx":"085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def paths():
 d={k:HERE/k for k in EXPECTED if k not in ("prototype.py","rev7_mdx")};d["prototype.py"]=HEX_CFB/"prototype.py";d["rev7_mdx"]=REV7;return d
def hashes():return {k:sha(v) for k,v in paths().items()}
def atomic(p,v):t=p.with_name(p.name+".tmp");t.write_text(json.dumps(v,indent=2,sort_keys=True)+"\n");os.replace(t,p)
def scope():return {"identity":IDENTITY,"cipher":"DES","key_hex":KEY.hex(),"mode":"CFB8","external_iv":"arbitrary eight bytes; not recovered or searched","constraint":"for i>=8, P_i=C_i XOR DES_key(C[i-8:i])[0]","unknown_representation":"global bijection of 16 displayed hex symbols to nibbles","relaxed_window_bytes":{"count":105,"ascii":"TAB LF CR and 32..126","additional_hex":["80","93","94","98","99","a6","e2"]},"strict_suffix":{"initial_state_set":[0,1,2],"terminal_state":0,"utf8":["e28093","e28094","e28098","e28099","e280a6"]},"orientations":list(ORIENTATIONS),"cells":4,"node_limit_per_cell":LIMIT,"order":"default frozen greedy geometry order; no explicit override","search_semantics":"fresh root per cell; caps are not additive","certificate":"16! mapping weight when complete"}
def require_gate():
 assert hashes()==EXPECTED
 for f in ("controls.json","native_controls.json"):
  c=json.loads((HERE/f).read_text());assert c["identity"]==IDENTITY and c["target_evaluated"] is False and c["rev7_read"] is False and c["assertions"]["all_passed"]
 g=json.loads(GATE.read_text());assert g["identity"]==IDENTITY and g["target_evaluated"] is False and g["scope"]==scope() and g["artifact_hashes"]==EXPECTED and g["driver_sha256"]==sha(Path(__file__));return g,sha(GATE)
def extract():
 text=REV7.read_text();a=text.index("`83 B57B2")+1;b=text.index("`",a);v="".join(text[a:b].split()).upper();assert len(v)==1092 and hashlib.sha256(v.encode()).hexdigest()==TEXT_SHA;o=core.orientations(v);assert tuple(o)==ORIENTATIONS;return v,o
def native(display):
 n=json.loads(subprocess.check_output([str(NATIVE),str(LIMIT),display,"-"],text=True));assert n["identity"]==IDENTITY and n["cipher"]=="des" and n["node_limit"]==LIMIT and n["seeded_entries"]==0 and n["expected_completion_weight"]==FULL;assert n["certificate_weight"]==n["stats"]["rejected_completion_weight"]+n["stats"]["terminal_completion_weight"] and n["ecb_calls"]>=0 and n["geometry"]["explicit_order_override"] is False;return n
def geometry(display):
 s=solver.Solver(display,1);return s.geometry
def decode(display,m):return bytes((m[solver.HEX.index(display[i])]<<4)|m[solver.HEX.index(display[i+1])] for i in range(0,len(display),2))
def suffix_formula(ct):
 e=DES.new(KEY,DES.MODE_ECB);return bytes(ct[i]^e.encrypt(ct[i-BS:i])[0] for i in range(BS,len(ct)))
def validate(display,solutions):
 out=[];ivs=(bytes.fromhex("0001020304050607"),b"0"*8)
 for s in solutions:
  m=tuple(s["mapping"]);suffix=bytes.fromhex(s["plaintext_suffix_hex"]);assert len(m)==16 and sorted(m)==list(range(16));ct=decode(display,m);assert len(ct)==546 and suffix==suffix_formula(ct) and solver.Solver.strict_suffix_ok(suffix) and core.display_encode(ct,m)==display
  full_hashes=[]
  for iv in ivs:
   full=DES.new(KEY,DES.MODE_CFB,iv=iv,segment_size=8).decrypt(ct);assert full[8:]==suffix and DES.new(KEY,DES.MODE_CFB,iv=iv,segment_size=8).encrypt(full)==ct;full_hashes.append({"iv_hex":iv.hex(),"first_block_hex":full[:8].hex(),"full_decryption_sha256":hashlib.sha256(full).hexdigest(),"suffix_equals_native":True,"full_library_reencryption_exact":True})
  out.append({"mapping_display_to_nibble":list(m),"ciphertext_sha256":hashlib.sha256(ct).hexdigest(),"plaintext_suffix_hex":suffix.hex(),"plaintext_suffix_sha256":hashlib.sha256(suffix).hexdigest(),"suffix_length":len(suffix),"strict_suffix_terminal_state":0,"display_reconstruction_exact":True,"two_arbitrary_iv_library_checks":full_hashes,"note":"Only bytes i>=8 are IV-independent; first blocks differ and are not claimed as recovered plaintext."})
 return out
def record(n):
 cert=n["certificate_weight"];complete=not n["stats"]["aborted_at_node_limit"]
 if complete:assert cert==FULL
 else:assert n["stats"]["nodes"]==LIMIT and cert<FULL
 return {**n["stats"],"node_limit":LIMIT,"ecb_calls":n["ecb_calls"],"elapsed_seconds":n["elapsed_seconds"],"certificate_weight":cert,"expected_factorial_weight":FULL,"certificate_complete":complete and cert==FULL,"search_status":"complete" if complete else "capped","unaccounted_mapping_weight":FULL-cert,"capped_interpretation":None if complete else "partial eliminated mapping weight only; reported remainder remains uncovered"}
def initial(gate_sha,text_sha):return {"identity":IDENTITY,"target_evaluated":True,"status":"running","configuration":{**scope(),"ciphertext_sha256":text_sha,"gate_sha256":gate_sha,"driver_sha256":sha(Path(__file__)),"artifact_hashes":EXPECTED},"cells":[]}
def run(output,checkpoint,resume):
 if output.exists():raise SystemExit(f"refusing existing output: {output}")
 _g,gate_sha=require_gate();v,oriented=extract();config=initial(gate_sha,hashlib.sha256(v.encode()).hexdigest())["configuration"]
 if checkpoint.exists():
  if not resume:raise SystemExit(f"refusing checkpoint without --resume: {checkpoint}")
  result=json.loads(checkpoint.read_text());assert result["configuration"]==config
 else:
  if resume:raise SystemExit("--resume requested without checkpoint")
  result=initial(gate_sha,config["ciphertext_sha256"])
 done={x["orientation"] for x in result["cells"]}
 for orientation in ORIENTATIONS:
  if orientation in done:continue
  display=oriented[orientation];n=native(display);pyg=geometry(display)
  for k in ("anchor_window_suffix_index","anchor_unique_symbols","symbol_order","fully_bound_window_counts"):assert n["geometry"][k]==pyg[k]
  survivors=validate(display,n["solutions"]);row={"identity":IDENTITY,"orientation":orientation,"display_sha256":hashlib.sha256(display.encode()).hexdigest(),"geometry":n["geometry"],"python_geometry_exact_match":True,"stats":record(n),"survivor_count":len(survivors),"survivors":survivors,"all_survivors_independently_validated":True};result["cells"].append(row);atomic(checkpoint,result);print(json.dumps({"orientation":orientation,"status":row["stats"]["search_status"],"nodes":row["stats"]["nodes"],"ecb_calls":row["stats"]["ecb_calls"],"certificate_weight":row["stats"]["certificate_weight"],"unaccounted":row["stats"]["unaccounted_mapping_weight"],"survivors":len(survivors),"seconds":row["stats"]["elapsed_seconds"]}),flush=True)
 assert len(result["cells"])==4;result["status"]="complete";result["summary"]={"complete_cells":sum(x["stats"]["certificate_complete"] for x in result["cells"]),"capped_cells":sum(not x["stats"]["certificate_complete"] for x in result["cells"]),"survivors":sum(x["survivor_count"] for x in result["cells"]),"total_nodes":sum(x["stats"]["nodes"] for x in result["cells"]),"total_ecb_calls":sum(x["stats"]["ecb_calls"] for x in result["cells"]),"total_elapsed_seconds":sum(x["stats"]["elapsed_seconds"] for x in result["cells"])};atomic(checkpoint,result);os.replace(checkpoint,output);print(json.dumps({"identity":IDENTITY,"output":str(output),"sha256":sha(output),"summary":result["summary"]},indent=2))
def main():
 p=argparse.ArgumentParser();a=p.add_mutually_exclusive_group(required=True);a.add_argument("--selftest",action="store_true");a.add_argument("--run-target",action="store_true");p.add_argument("--target-output",type=Path,default=HERE/"target_results.json");p.add_argument("--checkpoint",type=Path,default=HERE/"target_checkpoint.json");p.add_argument("--resume",action="store_true");x=p.parse_args()
 if x.selftest:
  if x.resume:p.error("--resume is target-only")
  _g,h=require_gate();print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"rev7_handling":"MDX bytes hashed only; ciphertext not extracted, parsed, oriented, or evaluated","driver_sha256":sha(Path(__file__)),"gate_sha256":h,"scope":scope()},indent=2,sort_keys=True))
 else:run(x.target_output,x.checkpoint,x.resume)
if __name__=="__main__":main()

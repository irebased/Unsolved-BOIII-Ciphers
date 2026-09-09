#!/usr/bin/env python3
"""Preregistered native ASCII-plus-historical-punctuation CFB8 extension.

The default self-test hashes control artifacts and Rev7 file bytes only. Rev7
text and the frozen 10M ledger are parsed only with explicit --run-target.
"""
from __future__ import annotations
import argparse,hashlib,json,math,os,subprocess,sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
HEX_CFB=HERE.parent
REPO=HERE.parents[3]
sys.path.insert(0,str(HEX_CFB))
import prototype as core

IDENTITY="ASTRA"
PREFIX_LIMIT=10_000_000
EXTENSION_LIMIT=100_000_000
FULL_WEIGHT=math.factorial(16)
CIPHERS=("aes128","blowfish","des")
ORIENTATIONS=("forward","reverse","byte_reverse","nibble_swap")
NATIVE=HERE/"native_text"
CONTROLS=HERE/"controls.json"
GATE=HERE/"target_gate.json"
OLD_LEDGER=HEX_CFB/"results.json"
VALIDATOR=HEX_CFB/"encoded"/"run_encoded.py"
REV7=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
EXPECTED_REV7_TEXT_SHA256="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
EXPECTED={
 "native_text.cpp":"1d01495a5562a134b1371017e3cf5f0c8726093b9c5a9871030a9652da746591",
 "native_text":"b932d9abaa999d0c85b26c336c43a0940daea7260ebbb1da2b4b0a628e2e8540",
 "controls.py":"ec1d6eb0da0ce15683d90aada96c5b0c8fedd31f68df4edb9e65e8979f7ab93e",
 "controls.json":"75eef218110788722e5127accad1d35cdb461eaee5207b125265377848e53a7d",
 "prototype.py":"416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b",
 "validator_run_encoded.py":"b2359b18171523ee4bc37cab4d6bab6a5633dba72e28f76d6fae98898ac22b3c",
 "old_target_ledger":"8c5567bd7cd3d66e926fddd1a5df39b684c29d7387e63418e26104d0fcaab939",
 "rev7_mdx":"085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91",
}
RAW_STATS=("nodes","rejected_plaintext","complete","maximum_depth","aborted_at_node_limit","rejected_completion_weight","terminal_completion_weight","rejected_unterminated_endpoint")

def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def artifact_hashes():
 return {"native_text.cpp":sha(HERE/"native_text.cpp"),"native_text":sha(NATIVE),"controls.py":sha(HERE/"controls.py"),"controls.json":sha(CONTROLS),"prototype.py":sha(HEX_CFB/"prototype.py"),"validator_run_encoded.py":sha(VALIDATOR),"old_target_ledger":sha(OLD_LEDGER),"rev7_mdx":sha(REV7)}
def atomic(path,value):
 tmp=path.with_name(path.name+".tmp");tmp.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n");os.replace(tmp,path)
def scope():
 return {"identity":IDENTITY,"endpoint":"ascii_utf8_punctuation","endpoint_bytes":{"ascii":"TAB LF CR and 32..126","utf8_sequences":["e28093","e28094","e28098","e28099"],"terminal_state":0},"ciphers":list(CIPHERS),"orientations":list(ORIENTATIONS),"prefix_validation":{"cells":12,"node_limit":PREFIX_LIMIT,"ledger_sha256":EXPECTED["old_target_ledger"]},"extension":{"cells":12,"node_limit":EXTENSION_LIMIT,"restart_semantics":"Fresh root traversal to 100M; prior 10M prefix repeats and is not additive."}}
def require_gate():
 assert artifact_hashes()==EXPECTED
 c=json.loads(CONTROLS.read_text())
 assert c["identity"]==IDENTITY and c["target_evaluated"] is False
 assert c["assertions"]["all_passed"] and c["assertions"]["native_stats_weights_maps_plaintexts_equal_python"]
 assert c["assertions"]["caps_are_incomplete_prefixes_only"]
 g=json.loads(GATE.read_text())
 assert g["identity"]==IDENTITY and g["target_evaluated"] is False
 assert g["scope"]==scope() and g["artifact_hashes"]==EXPECTED
 assert g["driver_sha256"]==sha(Path(__file__))
 return g,sha(GATE)
def extract_rev7():
 text=REV7.read_text(encoding="utf-8");start=text.index("`83 B57B2")+1;end=text.index("`",start)
 value="".join(text[start:end].split()).upper()
 assert len(value)==1092 and hashlib.sha256(value.encode("ascii")).hexdigest()==EXPECTED_REV7_TEXT_SHA256
 oriented=core.orientations(value);assert tuple(oriented)==ORIENTATIONS
 return value,oriented
def native(cipher,cap,display):
 out=json.loads(subprocess.check_output([str(NATIVE),cipher,str(cap),display,"-"],text=True))
 assert out["identity"]==IDENTITY and out["cipher"]==cipher and out["node_limit"]==cap
 assert out["complete"]==len(out["solutions"])
 assert set(RAW_STATS)<=set(out)
 assert out["expected_completion_weight"]==FULL_WEIGHT
 assert out["certificate_weight"]==out["rejected_completion_weight"]+out["terminal_completion_weight"]
 return out
def raw_native(row):return {k:row[k] for k in RAW_STATS}
def raw_old(row):return {k:row["stats"][k] for k in RAW_STATS}
def endpoint_accepts(data):
 state=0
 for value in data:
  nxt=core.historical_utf8_transition(state,0,value)
  if nxt is None:return False
  state=nxt
 return state==0
def decode_display(displayed,mapping):
 return bytes((mapping[core.HEX.index(displayed[i])]<<4)|mapping[core.HEX.index(displayed[i+1])] for i in range(0,len(displayed),2))
def validate_solutions(display,cipher,solutions):
 checked=[]
 for s in solutions:
  mapping=tuple(s["mapping"]);plain=bytes.fromhex(s["plaintext_hex"])
  assert len(mapping)==16 and sorted(mapping)==list(range(16))
  ciphertext=decode_display(display,mapping)
  library_plain=core.library_cfb8(ciphertext,cipher,decrypt=True)
  ecb,_key,iv=core.ecb_oracle(cipher)
  assert plain==library_plain
  assert core.manual_cfb8(ciphertext,ecb,iv,decrypt=True)==plain
  assert core.library_cfb8(plain,cipher,decrypt=False)==ciphertext
  assert core.display_encode(ciphertext,mapping)==display
  assert endpoint_accepts(plain)
  checked.append({"mapping_display_to_nibble":list(mapping),"plaintext_hex":plain.hex(),"plaintext_sha256":hashlib.sha256(plain).hexdigest(),"ciphertext_sha256":hashlib.sha256(ciphertext).hexdigest(),"library_cfb8_validated":True,"manual_cfb8_validated":True,"mapping_reencrypt_validated":True,"exact_display_reconstruction":True,"endpoint_fsa_terminal_state":0})
 return checked
def normalized_valid(rows):
 return sorted((tuple(x["mapping_display_to_nibble"]),x["plaintext_hex"]) for x in rows)
def normalized_old(rows):
 out=[]
 for x in rows:
  mapping=x.get("mapping_display_to_nibble",x.get("mapping"))
  out.append((tuple(mapping),x["plaintext_hex"]))
 return sorted(out)
def record_stats(n,cap):
 cert=n["certificate_weight"];complete=not n["aborted_at_node_limit"]
 if complete:assert cert==FULL_WEIGHT
 else:assert n["nodes"]==cap and cert<FULL_WEIGHT
 return {**raw_native(n),"node_limit":cap,"certificate_weight":cert,"expected_factorial_weight":FULL_WEIGHT,"search_status":"complete" if complete else "capped","certificate_complete":complete and cert==FULL_WEIGHT,"unaccounted_mapping_weight":FULL_WEIGHT-cert,"elapsed_seconds":n["elapsed_seconds"],"capped_weight_interpretation":None if complete else "lower bound on eliminated full mappings; uncovered weight remains"}
def initial_result(gate_sha,cipher_sha):
 return {"identity":IDENTITY,"target_evaluated":True,"configuration":{**scope(),"ciphertext_sha256":cipher_sha,"gate_sha256":gate_sha,"driver_sha256":sha(Path(__file__)),"artifact_hashes":EXPECTED},"phases":{"prefix_validation":{"status":"pending","cells":[]},"extension":{"status":"blocked_until_prefix_match","cells":[]}}}
def run_target(output,checkpoint,resume):
 if output.exists():raise SystemExit(f"refusing existing target output: {output}")
 _gate,gate_sha=require_gate();rev7,oriented=extract_rev7();cipher_sha=hashlib.sha256(rev7.encode("ascii")).hexdigest()
 config=initial_result(gate_sha,cipher_sha)["configuration"]
 if checkpoint.exists():
  if not resume:raise SystemExit(f"refusing checkpoint without --resume: {checkpoint}")
  result=json.loads(checkpoint.read_text());assert result["configuration"]==config
 else:
  if resume:raise SystemExit("--resume requested but checkpoint absent")
  result=initial_result(gate_sha,cipher_sha)
 old=json.loads(OLD_LEDGER.read_text())
 assert old["identity"]==IDENTITY and old["all_cells_finished"] and len(old["cells"])==12
 assert old["scope"]["node_limit_per_cell"]==PREFIX_LIMIT
 old_by={(x["cipher"],x["orientation"]):x for x in old["cells"]}
 phase=result["phases"]["prefix_validation"];done={(x["cipher"],x["orientation"]) for x in phase["cells"]}
 for cipher in CIPHERS:
  for orientation in ORIENTATIONS:
   key=(cipher,orientation)
   if key in done:continue
   n=native(cipher,PREFIX_LIMIT,oriented[orientation]);validated=validate_solutions(oriented[orientation],cipher,n["solutions"]);frozen=old_by[key]
   assert raw_native(n)==raw_old(frozen)
   assert normalized_valid(validated)==normalized_old(frozen["survivors"])
   phase["cells"].append({"identity":IDENTITY,"cipher":cipher,"orientation":orientation,"exact_all_raw_stats_match":True,"exact_survivors_match":True,"stats":record_stats(n,PREFIX_LIMIT),"survivor_count":len(validated),"survivors":validated});atomic(checkpoint,result)
   print(json.dumps({"phase":"prefix_validation","cell":key,"match":True}),flush=True)
 assert len(phase["cells"])==12;phase["status"]="complete_exact_match";result["phases"]["extension"]["status"]="running";atomic(checkpoint,result)
 ext=result["phases"]["extension"];done={(x["cipher"],x["orientation"]) for x in ext["cells"]}
 for cipher in CIPHERS:
  for orientation in ORIENTATIONS:
   key=(cipher,orientation)
   if key in done:continue
   n=native(cipher,EXTENSION_LIMIT,oriented[orientation]);validated=validate_solutions(oriented[orientation],cipher,n["solutions"])
   row={"identity":IDENTITY,"endpoint":"ascii_utf8_punctuation","cipher":cipher,"orientation":orientation,"displayed_sha256":hashlib.sha256(oriented[orientation].encode("ascii")).hexdigest(),"stats":record_stats(n,EXTENSION_LIMIT),"survivor_count":len(validated),"survivors":validated,"independent_pycryptodome_manual_mapping_reencrypt_and_terminal_fsa_validated":True}
   ext["cells"].append(row);atomic(checkpoint,result)
   print(json.dumps({"phase":"extension","cell":key,"status":row["stats"]["search_status"],"nodes":row["stats"]["nodes"],"certificate_weight":row["stats"]["certificate_weight"],"survivors":len(validated)}),flush=True)
 assert len(ext["cells"])==12;ext["status"]="complete"
 result["summary"]={"prefix_cells_exactly_matched":12,"extension_complete_cells":sum(x["stats"]["certificate_complete"] for x in ext["cells"]),"extension_capped_cells":sum(not x["stats"]["certificate_complete"] for x in ext["cells"]),"extension_survivors":sum(x["survivor_count"] for x in ext["cells"]),"total_extension_elapsed_seconds":sum(x["stats"]["elapsed_seconds"] for x in ext["cells"])}
 atomic(checkpoint,result);os.replace(checkpoint,output)
 print(json.dumps({"identity":IDENTITY,"target_results":str(output),"sha256":sha(output),"summary":result["summary"]},indent=2),flush=True)
def main():
 ap=argparse.ArgumentParser();act=ap.add_mutually_exclusive_group(required=True);act.add_argument("--selftest",action="store_true");act.add_argument("--run-target",action="store_true")
 ap.add_argument("--target-output",type=Path,default=HERE/"target_results.json");ap.add_argument("--checkpoint",type=Path,default=HERE/"target_checkpoint.json");ap.add_argument("--resume",action="store_true");a=ap.parse_args()
 if a.selftest:
  if a.resume:ap.error("--resume is target-only")
  _g,d=require_gate()
  print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"rev7_handling":"file bytes hashed only; ciphertext not extracted, parsed, oriented, or evaluated","gate_sha256":d,"driver_sha256":sha(Path(__file__)),"scope":scope()},indent=2,sort_keys=True))
 else:run_target(a.target_output,a.checkpoint,a.resume)
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Preregistered fresh-root 1B extension for six capped native-text cells.

Self-test validates frozen hashes and derives the eligible cell set from the
completed 100M ledger. Rev7 ciphertext is extracted only with --run-target.
"""
from __future__ import annotations
import argparse,hashlib,json,math,os,subprocess
from pathlib import Path
import run_target as base

HERE=Path(__file__).resolve().parent
IDENTITY="ASTRA"
LIMIT=1_000_000_000
PARENT_LIMIT=100_000_000
FULL_WEIGHT=math.factorial(16)
CIPHERS=("aes128","blowfish","des")
ORIENTATIONS=("forward","nibble_swap")
CELLS=tuple((c,o) for c in CIPHERS for o in ORIENTATIONS)
NATIVE=HERE/"native_text"
GATE=HERE/"extend_gate.json"
PARENT_LEDGER=HERE/"target_results.json"
EXPECTED={
 "native_text.cpp":"1d01495a5562a134b1371017e3cf5f0c8726093b9c5a9871030a9652da746591",
 "native_text":"b932d9abaa999d0c85b26c336c43a0940daea7260ebbb1da2b4b0a628e2e8540",
 "controls.py":"ec1d6eb0da0ce15683d90aada96c5b0c8fedd31f68df4edb9e65e8979f7ab93e",
 "controls.json":"75eef218110788722e5127accad1d35cdb461eaee5207b125265377848e53a7d",
 "prototype.py":"416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b",
 "validator_run_encoded.py":"b2359b18171523ee4bc37cab4d6bab6a5633dba72e28f76d6fae98898ac22b3c",
 "rev7_mdx":"085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91",
 "run_target.py":"0307081cd3b230b3c23678bb1337cc5f3ca46b5acee20cc81a348e16348e70b6",
 "target_gate.json":"6c7b50f17c3740eb5e5f512e826f12a361207019f9fbeb3427738e6b111fc5d6",
 "target_results.json":"640a1fb9f2878db0c43d2b4e2dbba7d9b8b3f4a77dd87499244c2bdda9c00fe1",
}
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def artifact_hashes():
 return {"native_text.cpp":sha(HERE/"native_text.cpp"),"native_text":sha(NATIVE),"controls.py":sha(HERE/"controls.py"),"controls.json":sha(HERE/"controls.json"),"prototype.py":sha(base.HEX_CFB/"prototype.py"),"validator_run_encoded.py":sha(base.VALIDATOR),"rev7_mdx":sha(base.REV7),"run_target.py":sha(HERE/"run_target.py"),"target_gate.json":sha(HERE/"target_gate.json"),"target_results.json":sha(PARENT_LEDGER)}
def atomic(path,value):
 tmp=path.with_name(path.name+".tmp");tmp.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n");os.replace(tmp,path)
def scope():
 return {"identity":IDENTITY,"endpoint":"ascii_utf8_punctuation","ciphers":list(CIPHERS),"orientations":list(ORIENTATIONS),"cells":[{"cipher":c,"orientation":o} for c,o in CELLS],"node_limit":LIMIT,"parent_node_limit":PARENT_LIMIT,"parent_ledger_sha256":EXPECTED["target_results.json"],"restart_semantics":"Each cell is a fresh root traversal to 1B; prior 100M work is repeated and not additive."}
def validate_parent():
 data=json.loads(PARENT_LEDGER.read_text())
 assert data["identity"]==IDENTITY and data["target_evaluated"] is True
 assert data["summary"]["prefix_cells_exactly_matched"]==12
 assert data["summary"]["extension_complete_cells"]==6 and data["summary"]["extension_capped_cells"]==6
 rows=data["phases"]["extension"]["cells"];assert len(rows)==12
 eligible=[]
 for row in rows:
  stats=row["stats"]
  if stats["search_status"]=="capped":
   assert stats["nodes"]==PARENT_LIMIT and not stats["certificate_complete"]
   assert stats["certificate_weight"]<FULL_WEIGHT and row["survivor_count"]==0 and row["survivors"]==[]
   eligible.append((row["cipher"],row["orientation"]))
 assert tuple(eligible)==CELLS
 return data
def require_gate():
 assert artifact_hashes()==EXPECTED
 base.require_gate()
 validate_parent()
 g=json.loads(GATE.read_text())
 assert g["identity"]==IDENTITY and g["target_evaluated"] is False
 assert g["scope"]==scope() and g["artifact_hashes"]==EXPECTED
 assert g["driver_sha256"]==sha(Path(__file__))
 return g,sha(GATE)
def native(cipher,display):
 n=base.native(cipher,LIMIT,display)
 assert n["identity"]==IDENTITY and n["cipher"]==cipher and n["node_limit"]==LIMIT
 return n
def initial(gate_sha,cipher_sha):
 return {"identity":IDENTITY,"target_evaluated":True,"configuration":{**scope(),"ciphertext_sha256":cipher_sha,"gate_sha256":gate_sha,"driver_sha256":sha(Path(__file__)),"artifact_hashes":EXPECTED},"status":"running","cells":[]}
def run_target(output,checkpoint,resume):
 if output.exists():raise SystemExit(f"refusing existing extension output: {output}")
 _g,gate_sha=require_gate();rev7,oriented=base.extract_rev7();cipher_sha=hashlib.sha256(rev7.encode("ascii")).hexdigest();config=initial(gate_sha,cipher_sha)["configuration"]
 if checkpoint.exists():
  if not resume:raise SystemExit(f"refusing checkpoint without --resume: {checkpoint}")
  result=json.loads(checkpoint.read_text());assert result["configuration"]==config
 else:
  if resume:raise SystemExit("--resume requested but checkpoint absent")
  result=initial(gate_sha,cipher_sha)
 done={(x["cipher"],x["orientation"]) for x in result["cells"]}
 for cipher,orientation in CELLS:
  if (cipher,orientation) in done:continue
  n=native(cipher,oriented[orientation]);validated=base.validate_solutions(oriented[orientation],cipher,n["solutions"]);stats=base.record_stats(n,LIMIT)
  row={"identity":IDENTITY,"endpoint":"ascii_utf8_punctuation","cipher":cipher,"orientation":orientation,"displayed_sha256":hashlib.sha256(oriented[orientation].encode("ascii")).hexdigest(),"stats":stats,"survivor_count":len(validated),"survivors":validated,"independent_pycryptodome_manual_mapping_reencrypt_and_terminal_fsa_validated":True}
  result["cells"].append(row);atomic(checkpoint,result)
  print(json.dumps({"cell":[cipher,orientation],"status":stats["search_status"],"nodes":stats["nodes"],"certificate_weight":stats["certificate_weight"],"survivors":len(validated)}),flush=True)
 assert len(result["cells"])==6
 result["status"]="complete"
 result["summary"]={"complete_cells":sum(x["stats"]["certificate_complete"] for x in result["cells"]),"capped_cells":sum(not x["stats"]["certificate_complete"] for x in result["cells"]),"survivors":sum(x["survivor_count"] for x in result["cells"]),"total_elapsed_seconds":sum(x["stats"]["elapsed_seconds"] for x in result["cells"])}
 atomic(checkpoint,result);os.replace(checkpoint,output)
 print(json.dumps({"identity":IDENTITY,"extend_results":str(output),"sha256":sha(output),"summary":result["summary"]},indent=2),flush=True)
def main():
 ap=argparse.ArgumentParser();act=ap.add_mutually_exclusive_group(required=True);act.add_argument("--selftest",action="store_true");act.add_argument("--run-target",action="store_true")
 ap.add_argument("--output",type=Path,default=HERE/"extend_results.json");ap.add_argument("--checkpoint",type=Path,default=HERE/"extend_checkpoint.json");ap.add_argument("--resume",action="store_true");a=ap.parse_args()
 if a.selftest:
  if a.resume:ap.error("--resume is target-only")
  _g,d=require_gate()
  print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"rev7_handling":"MDX bytes hash-checked only; ciphertext not extracted, parsed, oriented, or evaluated","parent_ledger_handling":"parsed only to prove the exact six capped 100M contexts","gate_sha256":d,"driver_sha256":sha(Path(__file__)),"scope":scope()},indent=2,sort_keys=True))
 else:run_target(a.output,a.checkpoint,a.resume)
if __name__=="__main__":main()

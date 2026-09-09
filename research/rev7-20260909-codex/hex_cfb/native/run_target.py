#!/usr/bin/env python3
"""Preregistered native extension for six remaining Base64/CFB8 cells.

The default self-test is synthetic/control metadata only. Rev7 and the frozen
3M target ledger are parsed only with explicit --run-target.
"""
from __future__ import annotations
import argparse, hashlib, json, math, os, subprocess, sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
HEX_CFB=HERE.parent
REPO=HERE.parents[3]
sys.path.insert(0,str(HEX_CFB))
sys.path.insert(0,str(HEX_CFB/"encoded"))
import prototype as core
import run_encoded as prior

IDENTITY="ASTRA"
PREFIX_LIMIT=3_000_000
EXTENSION_LIMIT=100_000_000
FULL_WEIGHT=math.factorial(16)
ALLOWED=set(prior.ENDPOINTS["base64"])
ALLOWED_HEX=bytes(sorted(ALLOWED)).hex()
CIPHERS=("aes128","blowfish","des")
ORIENTATIONS=("forward","reverse","byte_reverse","nibble_swap")
EXTEND_ORIENTATIONS=("forward","nibble_swap")
NATIVE=HERE/"native_dfs"
CONTROLS=HERE/"controls.json"
GATE=HERE/"target_gate.json"
OLD_LEDGER=HEX_CFB/"encoded_extend"/"target_results.json"
REV7=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
EXPECTED={
 "native_dfs.cpp":"1d86af5a59e35807400297b8148dad2af41629cd5c23739eb161308e440de11f",
 "native_dfs":"44ab21da1f2ce49ece7a516cf02c3ec88f3ad0f7babfe886a8bc7dba03dcd8c4",
 "controls.py":"62ff2dd3a1a3752832ee8bd81e3ba289a0bb7b8b7fb7cb9340289b1963c8106d",
 "controls.json":"3993296b2c73437d88e07985bb6fc8b99385e599f38ecd045a7ae3f1976c056f",
 "prototype.py":"416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b",
 "run_encoded.py":"b2359b18171523ee4bc37cab4d6bab6a5633dba72e28f76d6fae98898ac22b3c",
 "old_target_ledger":"6db92f9b1f1ddebf34105ec78ec4dd4935661b27fb8d3ef73c870d6447f61cc2",
 "rev7_mdx":"085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91",
}
RAW_STATS=("nodes","rejected_plaintext","complete","maximum_depth","aborted_at_node_limit",
 "rejected_completion_weight","terminal_completion_weight","rejected_unterminated_endpoint")

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def artifact_hashes():
 return {"native_dfs.cpp":sha(HERE/"native_dfs.cpp"),"native_dfs":sha(NATIVE),
  "controls.py":sha(HERE/"controls.py"),"controls.json":sha(CONTROLS),
  "prototype.py":sha(HEX_CFB/"prototype.py"),"run_encoded.py":sha(HEX_CFB/"encoded"/"run_encoded.py"),
  "old_target_ledger":sha(OLD_LEDGER),
  "rev7_mdx":sha(REV7)}
def atomic(path,value):
 tmp=path.with_name(path.name+".tmp")
 tmp.write_text(json.dumps(value,indent=2,sort_keys=True)+"\n")
 os.replace(tmp,path)
def scope():
 return {"identity":IDENTITY,"endpoint":"base64_69","allowed_bytes":sorted(ALLOWED),
  "ciphers":list(CIPHERS),"orientations":list(ORIENTATIONS),
  "prefix_validation":{"cells":12,"node_limit":PREFIX_LIMIT},
  "extension":{"cells":6,"orientations":list(EXTEND_ORIENTATIONS),
               "node_limit":EXTENSION_LIMIT,
               "restart_semantics":"Fresh root traversal to 100M; prior 3M prefix repeats and is not additive."}}

def require_gate():
 assert artifact_hashes()==EXPECTED
 c=json.loads(CONTROLS.read_text())
 assert c["identity"]==IDENTITY and c["target_evaluated"] is False
 assert c["assertions"]["all_passed"] and c["assertions"]["native_stats_weights_solutions_equal_python"]
 g=json.loads(GATE.read_text())
 assert g["identity"]==IDENTITY and g["target_evaluated"] is False
 assert g["scope"]==scope() and g["artifact_hashes"]==EXPECTED
 assert g["driver_sha256"]==sha(Path(__file__))
 return g,sha(GATE)

def extract_rev7():
 text=REV7.read_text();start=text.index("`83 B57B2")+1;end=text.index("`",start)
 value="".join(text[start:end].split()).upper()
 assert len(value)==1092 and sha(Path(REV7))==EXPECTED["rev7_mdx"]
 assert hashlib.sha256(value.encode()).hexdigest()==prior.EXPECTED_REV7_SHA256
 oriented=core.orientations(value);assert tuple(oriented)==ORIENTATIONS
 return value,oriented

def native(cipher,cap,display):
 args=[str(NATIVE),cipher,str(cap),display,ALLOWED_HEX,"-"]
 out=json.loads(subprocess.check_output(args,text=True))
 assert out["identity"]==IDENTITY and out["cipher"]==cipher and out["node_limit"]==cap
 assert out["complete"]==len(out["solutions"])
 return out

def raw_native(row): return {k:row[k] for k in RAW_STATS}
def raw_old(row): return {k:row["stats"][k] for k in RAW_STATS}
def record_stats(n,cap):
 cert=n["rejected_completion_weight"]+n["terminal_completion_weight"]
 assert cert==n["certificate_weight"] and n["expected_completion_weight"]==FULL_WEIGHT
 complete=not n["aborted_at_node_limit"]
 if complete: assert cert==FULL_WEIGHT
 else: assert n["nodes"]==cap and cert<FULL_WEIGHT
 return {**raw_native(n),"node_limit":cap,"certificate_weight":cert,
  "expected_factorial_weight":FULL_WEIGHT,"search_status":"complete" if complete else "capped",
  "certificate_complete":complete and cert==FULL_WEIGHT,"elapsed_seconds":n["elapsed_seconds"],
  "capped_weight_interpretation":None if complete else "lower bound on eliminated full mappings; uncovered weight remains"}

def validate_solutions(display,cipher,solutions):
 out=[]
 for s in solutions:
  mapping=s["mapping"]; plain=bytes.fromhex(s["plaintext_hex"])
  assert sorted(mapping)==list(range(16))
  out.append(prior.validate_solution(display,cipher,ALLOWED,{"mapping":tuple(mapping),"plaintext":plain}))
 return out

def normalized_survivors(rows):
 return sorted((tuple(x["mapping_display_to_nibble"]),x["plaintext_hex"]) for x in rows)

def initial_result(gate_sha,cipher_sha):
 return {"identity":IDENTITY,"target_evaluated":True,
  "configuration":{**scope(),"ciphertext_sha256":cipher_sha,
    "gate_sha256":gate_sha,"driver_sha256":sha(Path(__file__)),"artifact_hashes":EXPECTED},
  "phases":{"prefix_validation":{"status":"pending","cells":[]},"extension":{"status":"blocked_until_prefix_match","cells":[]}}}

def run_target(output,checkpoint,resume):
 if output.exists(): raise SystemExit(f"refusing existing target output: {output}")
 _g,gate_sha=require_gate()
 rev7,oriented=extract_rev7();cipher_sha=hashlib.sha256(rev7.encode()).hexdigest()
 config=initial_result(gate_sha,cipher_sha)["configuration"]
 if checkpoint.exists():
  if not resume: raise SystemExit(f"refusing checkpoint without --resume: {checkpoint}")
  result=json.loads(checkpoint.read_text());assert result["configuration"]==config
 else:
  if resume: raise SystemExit("--resume requested but checkpoint absent")
  result=initial_result(gate_sha,cipher_sha)

 # Phase 1: exact native replay of every frozen 3M target prefix.
 old=json.loads(OLD_LEDGER.read_text())
 assert old["identity"]==IDENTITY and old["target_evaluated"] and len(old["cells"])==12
 old_by={(x["cipher"],x["orientation"]):x for x in old["cells"]}
 phase=result["phases"]["prefix_validation"]
 done={(x["cipher"],x["orientation"]) for x in phase["cells"]}
 for cipher in CIPHERS:
  for orientation in ORIENTATIONS:
   key=(cipher,orientation)
   if key in done: continue
   n=native(cipher,PREFIX_LIMIT,oriented[orientation])
   validated=validate_solutions(oriented[orientation],cipher,n["solutions"])
   frozen=old_by[key]
   assert raw_native(n)==raw_old(frozen)
   assert normalized_survivors(validated)==normalized_survivors(frozen["survivors"])
   row={"identity":IDENTITY,"cipher":cipher,"orientation":orientation,
    "exact_raw_stats_match":True,"exact_survivors_match":True,
    "stats":record_stats(n,PREFIX_LIMIT),"survivors":validated}
   phase["cells"].append(row);atomic(checkpoint,result)
   print(json.dumps({"phase":"prefix_validation","cell":key,"match":True}),flush=True)
 assert len(phase["cells"])==12
 phase["status"]="complete_exact_match"
 result["phases"]["extension"]["status"]="running"
 atomic(checkpoint,result)

 # Phase 2: only the six preregistered capped cells, each fresh from root.
 ext=result["phases"]["extension"]
 done={(x["cipher"],x["orientation"]) for x in ext["cells"]}
 for cipher in CIPHERS:
  for orientation in EXTEND_ORIENTATIONS:
   key=(cipher,orientation)
   if key in done: continue
   n=native(cipher,EXTENSION_LIMIT,oriented[orientation])
   validated=validate_solutions(oriented[orientation],cipher,n["solutions"])
   row={"identity":IDENTITY,"endpoint":"base64_69","cipher":cipher,"orientation":orientation,
    "displayed_sha256":hashlib.sha256(oriented[orientation].encode()).hexdigest(),
    "stats":record_stats(n,EXTENSION_LIMIT),"survivor_count":len(validated),"survivors":validated,
    "independent_pycryptodome_and_reconstruction_validated":True}
   ext["cells"].append(row);atomic(checkpoint,result)
   print(json.dumps({"phase":"extension","cell":key,"status":row["stats"]["search_status"],
    "nodes":row["stats"]["nodes"],"certificate_weight":row["stats"]["certificate_weight"],
    "survivors":len(validated)}),flush=True)
 assert len(ext["cells"])==6
 ext["status"]="complete"
 result["summary"]={"prefix_cells_exactly_matched":12,
  "extension_complete_cells":sum(x["stats"]["certificate_complete"] for x in ext["cells"]),
  "extension_capped_cells":sum(not x["stats"]["certificate_complete"] for x in ext["cells"]),
  "extension_survivors":sum(x["survivor_count"] for x in ext["cells"])}
 atomic(checkpoint,result);os.replace(checkpoint,output)
 print(json.dumps({"identity":IDENTITY,"target_results":str(output),"sha256":sha(output),
  "summary":result["summary"]},indent=2),flush=True)

def main():
 ap=argparse.ArgumentParser()
 act=ap.add_mutually_exclusive_group(required=True)
 act.add_argument("--selftest",action="store_true")
 act.add_argument("--run-target",action="store_true")
 ap.add_argument("--target-output",type=Path,default=HERE/"target_results.json")
 ap.add_argument("--checkpoint",type=Path,default=HERE/"target_checkpoint.json")
 ap.add_argument("--resume",action="store_true")
 a=ap.parse_args()
 if a.selftest:
  if a.resume: ap.error("--resume is target-only")
  _g,d=require_gate()
  print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"gate_sha256":d,
   "driver_sha256":sha(Path(__file__)),"scope":scope()},indent=2,sort_keys=True))
 else: run_target(a.target_output,a.checkpoint,a.resume)
if __name__=="__main__":main()

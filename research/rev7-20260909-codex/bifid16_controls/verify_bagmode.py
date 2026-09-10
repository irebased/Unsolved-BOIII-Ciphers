#!/usr/bin/env python3
import hashlib,json
from pathlib import Path
import bifid16 as b
HERE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 x=json.loads((HERE/"bagmode_controls.json").read_text());assert x["identity"]=="ASTRA" and x["target_evaluated"] is False and x["rev7_read"] is False
 for rel,h in x["source_hashes"].items():
  p=HERE/rel if rel not in ("dependency_json","libz3") else (HERE/"dependency/dependency.json" if rel=="dependency_json" else HERE/"dependency/runtime/z3/lib/libz3.dylib")
  assert sha(p)==h,(rel,sha(p),h)
 assert sha(HERE/"bagmode_prefix128.smt2")==x["smt_dump"]["sha256"]
 bags={int(k):set(v) for k,v in x["bags"].items()}
 for item in x["reduced12_exhaustive"]:
  assert item["complete_sets_equal"] and sorted(item["bruteforce_models"],key=lambda z:z["square"])==sorted(item["smt_models"],key=lambda z:z["square"])
  ct=bytes.fromhex(item["ciphertext_hex"])
  for row in item["smt_models"]:
   plain=b.decrypt_bytes(ct,row["square"],5);assert plain.hex()==row["plaintext_hex"] and all(v in bags[item["bag"]] for v in plain) and b.encrypt_bytes(plain,row["square"],5)==ct
 for row in x["full_fixed_truth"]:
  assert row["status"]=="sat" and row["prefix_bag_valid"] and row["full_concrete_roundtrip"]
 for row in x["unknown_square_states"]:
  assert row["status"] in ("sat","unsat","unknown") and row["classified_as_negative"]==(row["status"]=="unsat")
  if row["status"]=="sat":assert row["prefix_bag_valid"] and row["full_concrete_roundtrip"] and len(row["square"])==16
 print(json.dumps({"ok":True,"identity":"ASTRA","ledger_sha256":sha(HERE/"bagmode_controls.json"),"reduced_model_counts":[x["model_count"] for x in x["reduced12_exhaustive"]],"unknown_square_states":[x["status"] for x in x["unknown_square_states"]],"target_evaluated":False},sort_keys=True))
if __name__=="__main__":main()

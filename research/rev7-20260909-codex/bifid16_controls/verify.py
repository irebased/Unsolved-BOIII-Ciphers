#!/usr/bin/env python3
import hashlib,json,random
from pathlib import Path
import bifid16 as b
HERE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 x=json.loads((HERE/"controls.json").read_text());assert x["identity"]=="ASTRA" and x["target_evaluated"] is False and x["rev7_read"] is False
 for rel,h in x["source_hashes"].items():
  p=HERE/rel if rel not in ("legacy_php","dependency_json","libz3") else {"legacy_php":HERE/"source/functions.bifid.php","dependency_json":HERE/"dependency/dependency.json","libz3":HERE/"dependency/runtime/z3/lib/libz3.dylib"}[rel]
  assert sha(p)==h,(rel,sha(p),h)
 assert sha(HERE/"full_plant.smt2")==x["smt_dump"]["sha256"]
 short=x["frozen12_exhaustive"];assert short["complete"] and short["sets_equal"] and short["model_count"]==len(short["smt_models"])==len(short["bruteforce_models"])==2
 cipher=bytes.fromhex(short["ciphertext_hex"])
 for row in short["smt_models"]:
  plain=b.decrypt_bytes(cipher,row["square"],short["period"]);assert plain.hex()==row["plaintext_hex"] and b.endpoint_accepts(plain) and b.encrypt_bytes(plain,row["square"],short["period"])==cipher
 assert sorted(short["smt_models"],key=lambda z:z["square"])==sorted(short["bruteforce_models"],key=lambda z:z["square"])
 full=x["full_length_period31"];ct=bytes.fromhex(full["ciphertext_hex"]);fp=bytes.fromhex(full["fixed_truth_check"]["plaintext_hex"]);assert len(fp)==546 and b.endpoint_accepts(fp) and b.decrypt_bytes(ct,full["truth_square"],31)==fp and b.encrypt_bytes(fp,full["truth_square"],31)==ct
 assert full["unknown_square_attempt"]["status"]=="unknown" and not full["unknown_square_attempt"]["classified_as_negative"] and full["retained_models"]==[]
 assert all(a["status"] in ("unknown","interrupted") and not a["classified_as_negative"] for a in x["incomplete_attempts"])
 print(json.dumps({"ok":True,"identity":"ASTRA","completed_controls_passed":True,"short_complete_models":2,"full_fixed_roundtrip":True,"unknown_square_period31":"unknown","negative_claim":False,"controls_sha256":sha(HERE/"controls.json")},sort_keys=True))
if __name__=="__main__":main()

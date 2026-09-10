#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,math
from pathlib import Path
import run_target as driver
HERE=Path(__file__).resolve().parent;LEDGER=HERE/"driver_controls.json"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def build():
 mapping=(9,3,14,0,12,5,7,15,2,11,1,13,8,4,10,6)
 plain=("Control:\tASCII – — ‘x’ ’y’ …\r\n".encode("utf-8"))*8
 rows=[]
 for cipher in driver.CIPHERS:
  ct=driver.ref.cfb8(plain,driver.ref.ECB(cipher),False);display=driver.core.display_encode(ct,mapping);assert set(display)==set(driver.core.HEX)
  seed={i:mapping[i] for i in range(12)}
  for orientation in driver.ORIENTATIONS:
   canonical=driver.core.orientations(display)[orientation];selected=driver.core.orientations(canonical)[orientation];assert selected==display
   n=driver.native(cipher,selected,100000,seed);checked=driver.validate(cipher,selected,n["solutions"])
   assert not n["aborted_at_node_limit"] and n["expected_completion_weight"]==math.factorial(4) and n["certificate_weight"]==math.factorial(4)
   assert any(x["mapping_display_to_nibble"]==list(mapping) and x["plaintext_hex"]==plain.hex() for x in checked)
   rows.append({"cipher":cipher,"orientation":orientation,"canonical_sha256":hashlib.sha256(canonical.encode()).hexdigest(),"selected_display_sha256":hashlib.sha256(selected.encode()).hexdigest(),"nodes":n["nodes"],"rejected_plaintext":n["rejected_plaintext"],"complete":n["complete"],"rejected_completion_weight":n["rejected_completion_weight"],"terminal_completion_weight":n["terminal_completion_weight"],"certificate_weight":n["certificate_weight"],"expected_completion_weight":n["expected_completion_weight"],"survivor_digest":hashlib.sha256(json.dumps(checked,sort_keys=True,separators=(",",":")).encode()).hexdigest(),"plant_retained":True})
 return {"identity":"ASTRA","target_evaluated":False,"target_read":False,"scope":"synthetic driver orientation and accounting wiring only","source_hashes":{"run_target.py":sha(HERE/"run_target.py"),"preflight.py":sha(HERE/"preflight.py"),"driver_controls.py":sha(Path(__file__))},"dependency_hashes":driver.preflight.validate()["dependency_hashes"],"rows":rows,"assertions":{"exact_two_by_four_grid":len(rows)==8,"all_seeded_four_unknown_complete":all(x["certificate_weight"]==24 for x in rows),"all_plants_retained":all(x["plant_retained"] for x in rows)}}
def main():
 p=argparse.ArgumentParser();p.add_argument("--regenerate",type=Path);a=p.parse_args();got=build()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit(f"refusing existing output: {a.regenerate}")
  a.regenerate.write_text(json.dumps(got,sort_keys=True,indent=2)+"\n");print(json.dumps({"ok":True,"sha256":sha(a.regenerate)}));return
 assert got==json.loads(LEDGER.read_text());print(json.dumps({"ok":True,"identity":"ASTRA","target_evaluated":False,"ledger_sha256":sha(LEDGER),"rows":len(got["rows"])}))
if __name__=="__main__":main()

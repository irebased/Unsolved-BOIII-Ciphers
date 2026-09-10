#!/usr/bin/env python3
"""Compact target-free orientation/dispatch controls for rectangle driver."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;PARENT=PACKAGE/"even_rectangle_controls";OUT=HERE/"driver_controls.json"
sys.path.insert(0,str(PARENT));import controls as pc
spec=importlib.util.spec_from_file_location("rectangle_target_driver",HERE/"run_target.py");driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,indent=2)+"\n"
def build():
 proof=pc.load_proof();parent=json.loads((PARENT/"controls.json").read_text());rows=[];orients=("forward","reverse","byte_reverse","nibble_swap")
 for i,plant in enumerate(parent["full_546_byte_plants"]):
  plain=pc.plaintext(i);cipher=pc.construct(plain,plant["cipher_square"],plant["plain_square"],plant["period"],proof);orientation=orients[i%4];canonical_input=driver.orient(cipher,orientation);assert driver.orient(canonical_input,orientation)==cipher
  fast=driver.cell(canonical_input,orientation,plant["period"],None,False);slow=driver.cell(canonical_input,orientation,plant["period"],None,True);expected_pairs=list(proof.paired_cipher_symbols(cipher,plant["period"]));expected_stream=bytes((int(x,16)<<4)|int(y,16) for x,y in expected_pairs);assert fast==slow and fast["orientation_sha256"]==plant["ciphertext_hex_sha256"] and fast["pair_stream_sha256"]==hashlib.sha256(expected_stream).hexdigest()
  assert fast["analysis"]==plant["graph"]["analysis"] and not fast["analysis"]["excluded_bag213"]
  rows.append({"plant_index":i,"orientation":orientation,"period":plant["period"],"canonical_input_sha256":hashlib.sha256(canonical_input.encode()).hexdigest(),"orientation_involution":True,"fast_equals_slow_all_1820":True,"matches_parent_pair_graph":True,"known_positive_unresolved":True})
 assert {x["orientation"] for x in rows}==set(orients)
 return {"identity":"ASTRA","target_evaluated":False,"rev7_read":False,"registered_cells":[[o,p] for o,p in driver.CELLS],"plants":rows,"source_hashes":{"run_target.py":sha(HERE/"run_target.py"),"driver_controls.py":sha(Path(__file__)),"parent_controls.py":sha(PARENT/"controls.py"),"parent_controls.json":sha(PARENT/"controls.json")},"assertions":{"all_passed":True,"six_parent_plants":len(rows)==6,"all_four_orientations":True,"fast_slow_exact":all(x["fast_equals_slow_all_1820"] for x in rows),"registered_seven_cells":len(driver.CELLS)==7}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--regenerate",type=Path);a=ap.parse_args();got=build()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit(f"refusing existing output: {a.regenerate}")
  a.regenerate.write_text(canonical(got));print(json.dumps({"identity":"ASTRA","output":str(a.regenerate),"sha256":sha(a.regenerate)}));return
 assert got==json.loads(OUT.read_text());print(json.dumps({"identity":"ASTRA","verified":True,"ledger_sha256":sha(OUT),"plants":6,"orientations":4}))
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Target-free path controls for the inert nibble-additive target harness."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;K44=HERE.parent;PARENT=K44/"nibble_additive_controls";OUT=HERE/"driver_controls.json"
sys.path.insert(0,str(PARENT));import model
sys.path.insert(0,str(K44));import geometry
spec=importlib.util.spec_from_file_location("target_driver",HERE/"run_target.py");driver=importlib.util.module_from_spec(spec);spec.loader.exec_module(driver)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,indent=2)+"\n"
def independent_encrypt(plain,key_nibbles,operation):
 digits=[]
 for value in plain:digits.extend((value>>4,value&15))
 encrypted=[]
 for i,value in enumerate(digits):
  key=key_nibbles[i%len(key_nibbles)];encrypted.append((value+key)&15 if operation=="subtract" else (key-value)&15)
 return bytes((encrypted[i]<<4)|encrypted[i+1] for i in range(0,len(encrypted),2))
def independent_restore(display):
 ranks={column:sorted("ZOMBIES").index(letter) for column,letter in enumerate("ZOMBIES")}
 return "".join(display[ranks[(i//4)%7]*156+(i//28)*4+i%4] for i in range(1092))
def build():
 parent=json.loads((PARENT/"controls.json").read_text());plants={x["hex_key_period"]:bytes.fromhex(x["plaintext_hex"]) for x in parent["plants"]};rows=[]
 for expected in parent["cells"]:
  m=expected["hex_key_period"];op=expected["operation"];q=expected["sufficient_paired_byte_period"];key=tuple(int(x,16) for x in expected["nibble_key_hex"]);cipher=independent_encrypt(plants[m],key,op);display=geometry.encode(cipher.hex().upper());restored=bytes.fromhex(independent_restore(display));assert restored==cipher
  target_row=next(x for x in driver.compute(restored,slow=False) if x["paired_byte_period"]==q and x["operation"]==op)
  slow=model.residue_masks_slow(restored,q,op);fast=model.residue_masks_fast(restored,q,op);assert fast==slow
  expected_masks=[int(x["mask_hex"],16) for x in expected["masks"]];assert list(fast)==expected_masks
  truth=bytes.fromhex(expected["paired_truth_key_hex"]);assert all((fast[r]>>truth[r])&1 for r in range(q))
  assert [x["paired_key_mask_hex"] for x in target_row["residues"]]==[model.mask_hex(x) for x in fast]
  rows.append({"cell_id":expected["cell_id"],"hex_key_period":m,"paired_byte_period":q,"operation":op,"independent_geometry_restored":True,"target_compute_equals_parent_masks":True,"fast_equals_slow":True,"truth_retained":True,"restored_cipher_sha256":hashlib.sha256(restored).hexdigest()})
 return {"identity":"ASTRA","target_evaluated":False,"rev7_read":False,"cells":rows,"source_hashes":{"run_target.py":sha(HERE/"run_target.py"),"driver_controls.py":sha(Path(__file__)),"parent_model.py":sha(PARENT/"model.py"),"parent_controls.json":sha(PARENT/"controls.json"),"geometry.py":sha(K44/"geometry.py")},"assertions":{"all_passed":True,"all_six_parent_cells":len(rows)==6,"all_driver_paths":all(x["target_compute_equals_parent_masks"] for x in rows),"all_truth_retained":all(x["truth_retained"] for x in rows)}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--regenerate",type=Path);args=ap.parse_args();got=build()
 if args.regenerate:
  if args.regenerate.exists():raise SystemExit(f"refusing existing output: {args.regenerate}")
  args.regenerate.write_text(canonical(got));print(json.dumps({"identity":"ASTRA","output":str(args.regenerate),"sha256":sha(args.regenerate)}));return
 assert got==json.loads(OUT.read_text());print(json.dumps({"identity":"ASTRA","verified":True,"ledger_sha256":sha(OUT),"cells":6}))
if __name__=="__main__":main()

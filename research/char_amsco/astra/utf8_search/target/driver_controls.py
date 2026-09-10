#!/usr/bin/env python3
"""Synthetic-only wiring control for the inert RFC 3629 target driver."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
DRIVER_PATH=HERE/"run_target.py"
LEDGER=HERE/"driver_controls.json"
PACKAGE=HERE.parent
IDENTITY="ASTRA"

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;assert spec.loader;spec.loader.exec_module(module);return module

class ZeroBackend:
 block_size=1
 def __init__(self,name):self.name=name
 def encrypt_block(self,value):assert len(value)==1;return bytes(1)
 def encrypt_cfb8(self,data,iv):assert len(iv)==1;return bytes(data)
 def decrypt_cfb8(self,data,iv):assert len(iv)==1;return bytes(data)

def regenerate(output):
 if output.exists():raise SystemExit("refusing existing output")
 driver=load("astra_utf8_driver_control",DRIVER_PATH);core=load("astra_utf8_core_control",driver.CORE_PATH);geometry=load("astra_utf8_geometry_control",driver.GEOM_PATH);controls=load("astra_utf8_controls_control",driver.CONTROLS_PATH)
 natural=b"X"+b"ASCII\x00\t\n"+bytes.fromhex("c2a2e282acf09f9880")+b" END"
 assert controls.strict(natural[1:])
 order=(0,1,2);processed="".join(geometry.forward(list(natural.hex().upper()),order,driver.START)[0])
 orientation="nibble_swap";canonical=driver.orient(geometry,processed,orientation)
 assert driver.orient(geometry,canonical,orientation)==processed
 objects={name:ZeroBackend(name) for name in driver.BACKENDS}
 cell=driver.scan_cell(core,geometry,processed,canonical,orientation,3,objects,controls,order_limit=2)
 assert cell["orders_examined"]==2 and cell["expected_orders"]==6 and cell["unexamined_orders"]==4
 assert cell["backend_contexts_examined"]==20 and cell["unexamined_backend_contexts"]==40
 assert cell["totals"]["rejected"]+cell["totals"]["retained"]==20
 assert cell["totals"]["retained"]>=10 and len(cell["survivor_order_rows"])==len(cell["independent_survivor_replays"])>=1
 first=cell["survivor_order_rows"][0];assert first["order"]==[0,1,2] and len(first["retained"])==10
 assert all(len(row["retained"])==10 and all(len(item["two_iv_replays"])==2 for item in row["retained"]) for row in cell["independent_survivor_replays"])
 result={
  "identity":IDENTITY,"target_evaluated":False,"rev7_file_read":False,
  "scope":"Synthetic run-limited control through the exact target scan_cell, witness-digest and survivor-replay path.",
  "fixture":{"natural_hex":natural.hex(),"natural_sha256":hashlib.sha256(natural).hexdigest(),"width":3,"start":"21","orientation":orientation,"true_order":list(order),"order_limit":2,"backend_model":"ten named one-byte zero-block CFB8 identity mocks"},
  "cell":cell,
  "artifact_hashes":{"run_target.py":sha(DRIVER_PATH),"core.py":sha(driver.CORE_PATH),"controls.py":sha(driver.CONTROLS_PATH),"controls.json":sha(driver.LEDGER_PATH),"geometry.py":sha(driver.GEOM_PATH)},
  "assertions":{"all_passed":True,"same_scan_cell_path":True,"run_limiter_exact":True,"factorial_and_context_accounting":True,"positive_survivor_replay_path":True,"two_iv_replays_per_survivor":True,"row_and_witness_digests_present":True,"no_target_read_or_evaluation":True},
 }
 output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n")
 print(json.dumps({"identity":IDENTITY,"output":str(output),"sha256":sha(output),"bytes":output.stat().st_size,"target_evaluated":False},indent=2))

def verify(path):
 d=json.loads(path.read_text());driver=load("astra_utf8_driver_verify",DRIVER_PATH)
 assert d["identity"]==IDENTITY and d["target_evaluated"] is False and d["rev7_file_read"] is False and all(d["assertions"].values())
 expected={"run_target.py":sha(DRIVER_PATH),"core.py":sha(driver.CORE_PATH),"controls.py":sha(driver.CONTROLS_PATH),"controls.json":sha(driver.LEDGER_PATH),"geometry.py":sha(driver.GEOM_PATH)}
 assert d["artifact_hashes"]==expected and d["fixture"]["order_limit"]==2
 cell=d["cell"];assert cell["orders_examined"]==2 and cell["expected_orders"]==6 and cell["backend_contexts_examined"]==20 and cell["unexamined_backend_contexts"]==40
 assert cell["totals"]["rejected"]+cell["totals"]["retained"]==20 and len(cell["order_rows_ndjson_sha256"])==len(cell["first_witness_rows_ndjson_sha256"])==64
 assert len(cell["survivor_order_rows"])==len(cell["independent_survivor_replays"])>=1
 print(json.dumps({"identity":IDENTITY,"verified":True,"read_only":True,"ledger_sha256":sha(path),"target_evaluated":False},indent=2))

def main():
 parser=argparse.ArgumentParser();parser.add_argument("--regenerate",type=Path);parser.add_argument("--ledger",type=Path,default=LEDGER);args=parser.parse_args()
 if args.regenerate:regenerate(args.regenerate.resolve())
 else:verify(args.ledger)
if __name__=="__main__":main()

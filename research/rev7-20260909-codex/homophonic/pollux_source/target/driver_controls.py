#!/usr/bin/env python3
"""Synthetic wiring controls for the inert 16-context Pollux target driver."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
DRIVER=HERE/"run_target.py"
PACKAGE=HERE.parent
LEDGER=HERE/"driver_controls.json"
IDENTITY="ASTRA"

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;assert spec.loader;spec.loader.exec_module(module);return module

def regenerate(output):
 if output.exists():raise SystemExit("refusing existing output")
 driver=load("astra_pollux_driver_control",DRIVER);controls=load("astra_pollux_controls_for_driver",driver.CONTROLS_PATH);source=json.loads(driver.CONTROL_LEDGER.read_text())
 fixture_rows=[row for row in source["synthetic_roundtrips"]["rows_data"] if row["input"]=="HELLO WORLD"]
 assert len(fixture_rows)==16
 replays=[]
 for fixture in fixture_rows:
  row=driver.evaluate_context(fixture["hex"],fixture["board"],fixture["decimal_orientation"],fixture["hex_orientation"],controls)
  assert row["decimal_digits"]==fixture["digits"] and row["morse"]==fixture["morse"] and row["necessary_language_accepted"] and row["witness"] is None and row["exact_integer_reencryption"]
  replays.append({"id":row["id"],"fixture_hex_sha256":hashlib.sha256(fixture["hex"].encode()).hexdigest(),"digits_sha256":row["decimal_digits_sha256"],"morse_sha256":row["morse_sha256"],"accepted":True,"exact_integer_reencryption":True})
 witness_inputs=(("","", "empty_stream"),(" .","06","head_separator"),(". ","60","tail_separator"),(".  .","6006","empty_token"),("......","666666","invalid_token"))
 witnesses=[]
 for morse,digits,kind in witness_inputs:
  accepted,witness=driver.validate_morse(morse,controls.CODEWORDS,digits);assert not accepted and witness["kind"]==kind and isinstance(witness["offset"],int);witnesses.append({"morse":morse,"digits":digits,"expected_kind":kind,"witness":witness})
 result={"identity":IDENTITY,"target_evaluated":False,"rev7_read":False,"scope":"Existing synthetic control fixture through exact target evaluate_context plus all witness classes.","replays":replays,"witness_controls":witnesses,"artifact_hashes":{"run_target.py":sha(DRIVER),"controls.py":sha(driver.CONTROLS_PATH),"controls.json":sha(driver.CONTROL_LEDGER)},"assertions":{"all_passed":True,"all16_registered_context_shapes":True,"full_digits_and_morse_exact":True,"all_witness_kinds_and_offsets":True,"no_parity_zero":True,"no_target":True}}
 output.write_text(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n")
 print(json.dumps({"identity":IDENTITY,"output":str(output),"sha256":sha(output),"target_evaluated":False},indent=2))

def verify(path):
 data=json.loads(path.read_text());driver=load("astra_pollux_driver_verify",DRIVER)
 assert data["identity"]==IDENTITY and data["target_evaluated"] is False and data["rev7_read"] is False and all(data["assertions"].values())
 assert data["artifact_hashes"]=={"run_target.py":sha(DRIVER),"controls.py":sha(driver.CONTROLS_PATH),"controls.json":sha(driver.CONTROL_LEDGER)}
 assert len(data["replays"])==16 and all(row["accepted"] and row["exact_integer_reencryption"] for row in data["replays"])
 assert [row["expected_kind"] for row in data["witness_controls"]]==["empty_stream","head_separator","tail_separator","empty_token","invalid_token"]
 print(json.dumps({"identity":IDENTITY,"verified":True,"read_only":True,"ledger_sha256":sha(path),"synthetic_contexts":16,"target_evaluated":False},indent=2))

def main():
 parser=argparse.ArgumentParser();parser.add_argument("--regenerate",type=Path);parser.add_argument("--ledger",type=Path,default=LEDGER);args=parser.parse_args()
 if args.regenerate:regenerate(args.regenerate.resolve())
 else:verify(args.ledger)
if __name__=="__main__":main()

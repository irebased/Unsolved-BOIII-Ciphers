#!/usr/bin/env python3
"""Create the reviewed hash-only RFC 3629 character-AMSCO target gate after public preregistration."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
DRIVER=HERE/"run_target.py"
OUTPUT=HERE/"target_gate.json"
EXPECTED={
 "run_target.py":"99bf55ea5e422bd3dce7a8cd64af484399bbcf010b2064bb9d82188ec8ada45f",
 "driver_controls.py":"4a89ed30cba5be094937fb866ff1c7fc3bd8c619b08d94d7674f0413e3c257e3",
 "driver_controls.json":"f73aab636e2a18efb35c5f5b5af498932f300b7ac19f2999689a3e454f90be05",
 "README.md":"9ba110f83b206b51ebb09412c17c31ecf80e1c99f87188d951c70aa9e9631a93",
}

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;assert spec.loader;spec.loader.exec_module(module);return module

def main():
 parser=argparse.ArgumentParser();parser.add_argument("--fable-reference",required=True);parser.add_argument("--review-evidence",required=True);args=parser.parse_args()
 assert not OUTPUT.exists()
 for name,want in EXPECTED.items():assert sha(HERE/name)==want,(name,sha(HERE/name),want)
 driver=load("astra_utf8_gate_driver",DRIVER);controls=load("astra_utf8_gate_controls",driver.CONTROLS_PATH)
 assert sha(driver.MDX)==driver.MDX_SHA and sha(driver.DATASET)==driver.DATASET_SHA
 ledger=driver.frozen_sources(controls);artifacts={label:sha(path) for label,path in driver.ARTIFACTS.items()}
 control=json.loads((HERE/"driver_controls.json").read_text())
 assert control["identity"]=="ASTRA" and control["target_evaluated"] is False and control["rev7_file_read"] is False and all(control["assertions"].values())
 gate={
  "identity":"ASTRA","target_evaluated":False,
  "authorization":"FABLE preregistration plus separate root GO required",
  "fable_reference":args.fable_reference,
  "review_evidence":args.review_evidence,
  "scope":driver.scope(),"driver_sha256":EXPECTED["run_target.py"],
  "driver_controls_source_sha256":EXPECTED["driver_controls.py"],
  "driver_controls_ledger_sha256":EXPECTED["driver_controls.json"],
  "target_readme_sha256":EXPECTED["README.md"],
  "gate_builder_sha256":sha(Path(__file__)),"artifact_hashes":artifacts,
  "controlled_source_hashes":ledger["source_hashes"],
  "mdx_sha256":driver.MDX_SHA,"dataset_sha256":driver.DATASET_SHA,
  "canonical_text_sha256":driver.TEXT_SHA,
 }
 with OUTPUT.open("x") as handle:json.dump(gate,handle,indent=2,sort_keys=True);handle.write("\n")
 print(json.dumps({"identity":"ASTRA","target_evaluated":False,"gate_sha256":sha(OUTPUT),"driver_sha256":EXPECTED["run_target.py"]},indent=2))
if __name__=="__main__":main()

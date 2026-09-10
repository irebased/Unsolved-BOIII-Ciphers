#!/usr/bin/env python3
"""Create the hash-pinned inert Pollux gate for registered FABLE plan 221."""
from __future__ import annotations
import hashlib,importlib.util,json,sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
DRIVER=HERE/"run_target.py"
OUTPUT=HERE/"target_gate.json"
EXPECTED={
 "run_target.py":"4871d10c2339ac27f390dbda79e750c83b893c275f3700007013dbcfed0ba029",
 "driver_controls.py":"b0d494c16d54d384b2eeeb945db790eb0daf3337ffc43a8f80ed1105716da571",
 "driver_controls.json":"1aa1e76338fa128b4403eae16081588ba332c0a5bd2374973a2739e502969d28",
 "README.md":"1e9389605a2f20cefb8325d2ab95b170e4a284bf17ee33f91bcedcb55b0d3c73",
}

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;assert spec.loader;spec.loader.exec_module(module);return module
def main():
 assert not OUTPUT.exists()
 for name,want in EXPECTED.items():assert sha(HERE/name)==want,(name,sha(HERE/name),want)
 driver=load("astra_pollux_gate_driver",DRIVER);controls=load("astra_pollux_gate_controls",driver.CONTROLS_PATH);controls.verify_sources()
 control=json.loads(driver.CONTROL_LEDGER.read_text());wiring=json.loads((HERE/"driver_controls.json").read_text())
 assert control["identity"]==wiring["identity"]=="ASTRA" and control["target_evaluated"] is wiring["target_evaluated"] is False and all(control["assertions"].values()) and all(wiring["assertions"].values())
 assert sha(driver.MDX)==driver.MDX_SHA and sha(driver.DATASET)==driver.DATASET_SHA
 gate={"identity":"ASTRA","target_evaluated":False,"authorization":"FABLE plan 221 registered; separate root GO required","fable_reference":"FABLE message 221","scope":driver.scope(),"driver_sha256":EXPECTED["run_target.py"],"driver_controls_source_sha256":EXPECTED["driver_controls.py"],"driver_controls_ledger_sha256":EXPECTED["driver_controls.json"],"target_readme_sha256":EXPECTED["README.md"],"gate_builder_sha256":sha(Path(__file__)),"artifact_hashes":{name:sha(path) for name,path in driver.ARTIFACTS.items()},"control_source_sha256":sha(driver.CONTROLS_PATH),"control_ledger_sha256":sha(driver.CONTROL_LEDGER),"mdx_sha256":driver.MDX_SHA,"dataset_sha256":driver.DATASET_SHA,"canonical_text_sha256":driver.TEXT_SHA,"review_status":"inert gate only; source and synthetic controls ready for root review before separate GO"}
 with OUTPUT.open("x") as handle:json.dump(gate,handle,indent=2,sort_keys=True);handle.write("\n")
 print(json.dumps({"identity":"ASTRA","target_evaluated":False,"gate_sha256":sha(OUTPUT),"driver_sha256":EXPECTED["run_target.py"]},indent=2))
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Create a reviewed inert target gate after public preregistration."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
DRIVER=HERE/"run_target.py"
OUTPUT=HERE/"target_gate.json"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;assert spec.loader;spec.loader.exec_module(module);return module
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--fable-reference",required=True)
    ap.add_argument("--review-evidence",required=True)
    args=ap.parse_args()
    if OUTPUT.exists():raise SystemExit("refusing existing gate")
    driver=load("astra_lossy2013_gate_driver",DRIVER)
    control=json.loads(driver.CONTROL_LEDGER.read_text())
    wiring=json.loads((HERE/"driver_controls.json").read_text())
    assert control["identity"]==wiring["identity"]=="ASTRA"
    assert not control["target_evaluated"] and not wiring["target_evaluated"]
    assert all(control["assertions"].values()) and all(wiring["assertions"].values())
    assert wiring["driver_sha256"]==sha(DRIVER)
    assert sha(driver.MDX)==driver.MDX_SHA and sha(driver.DATASET)==driver.DATASET_SHA
    gate={"identity":"ASTRA","target_evaluated":False,"authorization":"public preregistration recorded; separate root GO required","fable_reference":args.fable_reference,"review_evidence":args.review_evidence,"scope":driver.scope(),"driver_sha256":sha(DRIVER),"control_source_sha256":sha(driver.CONTROLS_PATH),"control_ledger_sha256":sha(driver.CONTROL_LEDGER),"dependency_hashes":{k:sha(v) for k,v in driver.DEPENDENCIES.items()},"target_artifact_hashes":{k:sha(v) for k,v in driver.TARGET_ARTIFACTS.items()},"mdx_sha256":driver.MDX_SHA,"dataset_sha256":driver.DATASET_SHA,"canonical_text_sha256":driver.TEXT_SHA,"gate_builder_sha256":sha(Path(__file__))}
    OUTPUT.write_text(json.dumps(gate,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"identity":"ASTRA","target_evaluated":False,"gate_sha256":sha(OUTPUT),"driver_sha256":sha(DRIVER)},indent=2))
if __name__=="__main__":main()

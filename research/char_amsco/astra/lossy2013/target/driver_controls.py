#!/usr/bin/env python3
"""Synthetic wiring controls for the inert lossy-2013 target driver."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
DRIVER=HERE/"run_target.py"
LEDGER=HERE/"driver_controls.json"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module;assert spec.loader;spec.loader.exec_module(module);return module
def plaintext(n=655):
    seed="Mixed CASE target wiring 2013: punctuation !?.,;[]{}() digits 0123456789 / | "
    return (seed*((n+len(seed)-1)//len(seed)))[:n].encode()
def generate():
    driver=load("astra_lossy2013_driver_control",DRIVER)
    core=load("astra_lossy2013_driver_core",driver.CORE_PATH)
    controls=load("astra_lossy2013_driver_parent_controls",driver.CONTROLS_PATH)
    legacy=controls.source_port()
    plain=plaintext()
    rows=[]
    for cipher in driver.CIPHERS:
        for iv_name in driver.IVS:
            iv=driver.iv_for(cipher,iv_name)
            ct=core.encrypt_cfb8(cipher,iv,plain)
            raw=core.emit(ct.hex().upper(),"2013")
            assert legacy.legacy_encode(ct.hex().upper().encode(),"2014")["raw"].decode()==raw
            for orientation in driver.ORIENTATIONS:
                canonical=driver.orient(raw,orientation)
                row=driver.evaluate_context(canonical,cipher,iv_name,orientation,core,legacy)
                exact=any(bytes.fromhex(sol["plaintext_hex"])==plain and bytes.fromhex(sol["ciphertext_hex"])==ct for sol in row["solutions"])
                assert row["complete"] and exact and row["all_retained_solutions_independently_validated"] and row["all_reoriented_emissions_equal_input"]
                rows.append({"id":row["id"],"canonical_sha256":hashlib.sha256(canonical.encode()).hexdigest(),"plaintext_sha256":hashlib.sha256(plain).hexdigest(),"ciphertext_sha256":hashlib.sha256(ct).hexdigest(),"complete":row["complete"],"solution_count":row["solution_count"],"exact_plaintext_ciphertext_pair_retained":exact,"accepted_states":row["accepted_states"],"block_calls":row["block_calls"],"seconds":row["seconds"],"solutions":row["solutions"]})
    assert len(rows)==16 and len({x["id"] for x in rows})==16
    return {"identity":"ASTRA","target_evaluated":False,"rev7_read":False,"scope":"Mixed-case printable punctuation/digit 655-byte plant through exact target context path for all 16 registered contexts.","driver_sha256":sha(DRIVER),"core_sha256":sha(driver.CORE_PATH),"parent_control_source_sha256":sha(driver.CONTROLS_PATH),"parent_control_ledger_sha256":sha(driver.CONTROL_LEDGER),"rows":rows,"assertions":{"all16_contexts_exercised":True,"all_complete":True,"all_exact_plaintext_ciphertext_pairs_retained":True,"all_retained_solutions_source_and_library_validated":True,"all_orientations_reconstruct_exactly":True,"no_target":True},"source_sha256":sha(Path(__file__))}
def stable(x):
    if isinstance(x,dict):return {k:stable(v) for k,v in x.items() if k!="seconds"}
    if isinstance(x,list):return [stable(v) for v in x]
    return x
def verify():
    old=json.loads(LEDGER.read_text());fresh=generate();assert stable(old)==stable(fresh)
    assert all(old["assertions"].values()) and len(old["rows"])==16
    print(json.dumps({"identity":"ASTRA","verified":True,"ledger_sha256":sha(LEDGER),"contexts":16,"target_evaluated":False},indent=2))
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--regenerate",type=Path);a=ap.parse_args()
    if a.regenerate:
        if a.regenerate.exists():raise SystemExit("refusing existing output")
        a.regenerate.write_text(json.dumps(generate(),indent=2,sort_keys=True)+"\n")
        print(json.dumps({"identity":"ASTRA","output":str(a.regenerate),"sha256":sha(a.regenerate),"target_evaluated":False},indent=2))
    else:verify()
if __name__=="__main__":main()

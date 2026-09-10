#!/usr/bin/env python3
"""ASTRA target-free driver replay of the six planted cases."""
from pathlib import Path
import importlib.util, json, hashlib
HERE=Path(__file__).resolve().parent

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

def main():
    c=load("plants",HERE/"controls.py");d=load("driver",HERE/"run_target.py")
    assert d.ROOT==HERE.parents[4] and d.MODEL.resolve()==c.PBC/"model.py"
    checked=[]
    for period,op in d.CELLS:
        plain=c.plant(period);key=c.key_for(period,op);cipher=c.encrypt(plain,key,op)
        fast=d.compute(cipher);slow=d.compute(cipher,slow=True);assert fast==slow
        row=next(x for x in fast if x["period_bytes"]==period and x["operation"]==op)
        assert row["status"]=="bag_compatible_unresolved"
        for r,item in enumerate(row["residues"]):assert (int(item["key_mask_hex"],16)>>key[r])&1
        checked.append(row["id"])
    result={"identity":"ASTRA","target_read":False,"driver_six_plants_fast_slow_all_cells_equal":True,"truth_preserved_for":checked,"driver_sha256":hashlib.sha256((HERE/"run_target.py").read_bytes()).hexdigest()}
    assert result==json.loads((HERE/"driver_controls.json").read_text())
    print(json.dumps({"identity":"ASTRA","target_read":False,"status":"PASS","verified_cells":len(checked)}))

if __name__=="__main__":main()

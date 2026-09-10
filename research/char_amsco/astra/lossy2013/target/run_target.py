#!/usr/bin/env python3
"""Inert gated target driver for the source-equivalent lossy 2013/2014 emission."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PACKAGE=HERE.parent
ROOT=HERE.parents[4]
CORE_PATH=PACKAGE/"core.py"
CONTROLS_PATH=PACKAGE/"controls.py"
CONTROL_LEDGER=PACKAGE/"controls.json"
MDX=ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
DATASET=ROOT/"lavender/src/data/ciphers/revelations.json"
GATE=HERE/"target_gate.json"
MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
DATASET_SHA="68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e"
TEXT_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
ORIENTATIONS=("forward","full_hex_reverse","byte_reverse","nibble_swap")
CIPHERS=("des","aes128")
IVS=("nul","ascii0")
MAX_FRONTIER=100000
MAX_ACCEPTED=5000000
DEPENDENCIES={
 "lossy2013/core.py":CORE_PATH,
 "lossy2013/controls.py":CONTROLS_PATH,
 "lossy2013/controls.json":CONTROL_LEDGER,
 "lossy2013/README.md":PACKAGE/"README.md",
 "lossy2013/REPORT.md":PACKAGE/"REPORT.md",
 "cryptool_bug/analyze.py":ROOT/"research/char_amsco/astra/cryptool_bug/analyze.py",
 "cryptool_bug/amsco_geometry.py":ROOT/"research/char_amsco/astra/amsco_geometry.py",
 "cryptool_bug/source/class.amsco.php.base64":ROOT/"research/char_amsco/astra/cryptool_bug/source/class.amsco.php.base64",
 "cryptool_bug/source/default_tool.php":ROOT/"research/char_amsco/astra/cryptool_bug/source/default_tool.php",
 "cryptool_bug/source/infobox.template":ROOT/"research/char_amsco/astra/cryptool_bug/source/infobox.template",
}
TARGET_ARTIFACTS={
 "target/README.md":HERE/"README.md",
 "target/driver_controls.py":HERE/"driver_controls.py",
 "target/driver_controls.json":HERE/"driver_controls.json",
 "target/prepare_gate.py":HERE/"prepare_gate.py",
}
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module
    assert spec.loader
    spec.loader.exec_module(module)
    return module
def orient(value,name):
    if name=="forward":return value
    if name=="full_hex_reverse":return value[::-1]
    pairs=[value[i:i+2] for i in range(0,len(value),2)]
    if name=="byte_reverse":return "".join(reversed(pairs))
    if name=="nibble_swap":return "".join(x[::-1] for x in pairs)
    raise ValueError(name)
def iv_for(cipher,name):
    bs=8 if cipher=="des" else 16
    return bytes(bs) if name=="nul" else b"0"*bs
def scope():
    return {"identity":"ASTRA","equivalent_emission_model":"literal keys 2013 and 2014 counted once","natural_ciphertext_bytes":655,"observed_hex_characters":1092,"orientations":list(ORIENTATIONS),"ciphers":list(CIPHERS),"ivs":list(IVS),"contexts":16,"plaintext_bytes":"printable ASCII 32..126 inclusive","max_frontier":MAX_FRONTIER,"max_accepted_states":MAX_ACCEPTED,"cap_semantics":"INCOMPLETE; never an exclusion","retention":"every complete plaintext/ciphertext path; no score or language pruning"}
def require_gate():
    if not GATE.exists():raise RuntimeError("target gate absent")
    gate=json.loads(GATE.read_text())
    assert gate["identity"]=="ASTRA" and gate["target_evaluated"] is False
    assert gate["authorization"]=="public preregistration recorded; separate root GO required"
    assert gate["scope"]==scope()
    assert gate["driver_sha256"]==sha(Path(__file__))
    assert gate["mdx_sha256"]==MDX_SHA and gate["dataset_sha256"]==DATASET_SHA and gate["canonical_text_sha256"]==TEXT_SHA
    assert gate["dependency_hashes"]=={k:sha(v) for k,v in DEPENDENCIES.items()}
    assert gate["target_artifact_hashes"]=={k:sha(v) for k,v in TARGET_ARTIFACTS.items()}
    controls=load("astra_lossy2013_target_controls",CONTROLS_PATH)
    legacy=controls.source_port()
    ledger=json.loads(CONTROL_LEDGER.read_text())
    assert ledger["identity"]=="ASTRA" and not ledger["target_evaluated"] and not ledger["rev7_read"] and all(ledger["assertions"].values())
    assert gate["control_source_sha256"]==sha(CONTROLS_PATH) and gate["control_ledger_sha256"]==sha(CONTROL_LEDGER)
    assert sha(MDX)==MDX_SHA and sha(DATASET)==DATASET_SHA
    return gate,sha(GATE),load("astra_lossy2013_target_core",CORE_PATH),legacy
def canonical():
    text=MDX.read_text()
    a=text.index(chr(96)+"83 B57B2")+1
    b=text.index(chr(96),a)
    left="".join(text[a:b].split()).upper()
    rows=json.loads(DATASET.read_text())
    row=next(x for x in rows if x.get("id")=="rev7")
    right="".join(row["ciphertext"].split()).upper()
    assert left==right and len(left)==1092 and hashlib.sha256(left.encode()).hexdigest()==TEXT_SHA
    return left,hashlib.sha256(row["ciphertext"].encode()).hexdigest()
def validate_solutions(row,cipher,iv,observed,core,legacy):
    for sol in row["solutions"]:
        pt=bytes.fromhex(sol["plaintext_hex"])
        ct=bytes.fromhex(sol["ciphertext_hex"])
        assert len(pt)==len(ct)==655 and set(pt)<=set(core.ALLOWED)
        assert core.decrypt_cfb8(cipher,iv,ct)==pt and core.encrypt_cfb8(cipher,iv,pt)==ct
        assert core.emit(ct.hex().upper(),"2013")==observed
        assert legacy.legacy_encode(ct.hex().upper().encode(),"2013")["raw"].decode()==observed
        assert legacy.legacy_encode(ct.hex().upper().encode(),"2014")["raw"].decode()==observed
        assert hashlib.sha256(pt).hexdigest()==sol["plaintext_sha256"]
        assert hashlib.sha256(ct).hexdigest()==sol["ciphertext_sha256"]
def evaluate_context(canonical_hex,cipher,iv_name,orientation,core,legacy):
    observed=orient(canonical_hex,orientation)
    iv=iv_for(cipher,iv_name)
    row=core.search(cipher,iv,observed,655,"2013",MAX_FRONTIER,MAX_ACCEPTED)
    validate_solutions(row,cipher,iv,observed,core,legacy)
    reoriented=[]
    for sol in row["solutions"]:
        ct=bytes.fromhex(sol["ciphertext_hex"])
        shown=orient(core.emit(ct.hex().upper(),"2013"),orientation)
        assert shown==canonical_hex
        reoriented.append(hashlib.sha256(shown.encode()).hexdigest())
    return {"id":f"cipher={cipher}|iv={iv_name}|hex={orientation}","cipher":cipher,"iv":iv_name,"iv_hex":iv.hex(),"orientation":orientation,"complete":row["complete"],"capped_reason":row["capped_reason"],"stopped_after_bytes":row["stopped_after_bytes"],"frontier_counts":row["frontier_counts"],"frontier_count_at_stop":row["frontier_count_at_stop"],"accepted_states":row["accepted_states"],"block_calls":row["block_calls"],"seconds":row["seconds"],"solutions":row["solutions"],"solution_count":len(row["solutions"]),"all_retained_solutions_independently_validated":True,"all_reoriented_emissions_equal_input":True,"reoriented_emission_sha256":reoriented}
def evaluate_grid(canonical_hex,core,legacy):
    return [evaluate_context(canonical_hex,c,i,o,core,legacy) for c in CIPHERS for i in IVS for o in ORIENTATIONS]
def run(output):
    gate,gate_sha,core,legacy=require_gate()
    tmp=Path(str(output)+".tmp")
    if output.exists() or tmp.exists():raise SystemExit("refusing existing result or temporary output")
    canonical_hex,dataset_field_sha=canonical()
    rows=evaluate_grid(canonical_hex,core,legacy)
    complete=sum(x["complete"] for x in rows)
    solutions=sum(x["solution_count"] for x in rows)
    result={"identity":"ASTRA","target_evaluated":True,"configuration":{"scope":scope(),"gate_sha256":gate_sha,"driver_sha256":sha(Path(__file__)),"control_source_sha256":sha(CONTROLS_PATH),"control_ledger_sha256":sha(CONTROL_LEDGER),"mdx_sha256":MDX_SHA,"dataset_sha256":DATASET_SHA,"dataset_ciphertext_field_sha256":dataset_field_sha,"canonical_text_sha256":TEXT_SHA,"dependency_hashes":gate["dependency_hashes"]},"rows":rows,"summary":{"contexts":16,"complete":complete,"capped_incomplete":16-complete,"solutions":solutions,"all_full_solutions_retained":True,"all_retained_solutions_independently_validated":True,"no_scoring_or_pruning_except_caps":True}}
    tmp.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    os.replace(tmp,output)
    print(json.dumps({"identity":"ASTRA","result":str(output),"sha256":sha(output),"summary":result["summary"]},indent=2))
def selftest():
    assert sha(MDX)==MDX_SHA and sha(DATASET)==DATASET_SHA
    data=json.loads(CONTROL_LEDGER.read_text())
    assert data["identity"]=="ASTRA" and not data["target_evaluated"] and all(data["assertions"].values())
    print(json.dumps({"identity":"ASTRA","target_evaluated":False,"rev7_handling":"MDX and dataset bytes hashed only; target ciphertext not extracted or evaluated","driver_sha256":sha(Path(__file__)),"scope":scope(),"gate_present":GATE.exists()},indent=2,sort_keys=True))
def main():
    ap=argparse.ArgumentParser()
    group=ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--selftest",action="store_true")
    group.add_argument("--run-target",action="store_true")
    ap.add_argument("--target-output",type=Path,default=HERE/"target_results.json")
    args=ap.parse_args()
    selftest() if args.selftest else run(args.target_output)
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Read-only verifier for the frozen byte-column result; optional scratch replay."""
from __future__ import annotations
import argparse, hashlib, json, math, subprocess, tempfile
from pathlib import Path

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]
RESULTS=HERE/"target_results.json"
GATE=HERE/"target_gate.json"
MDX=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
EXPECTED_RESULT_SHA="90902426dbe074a13098e54f136e3ee43677d6da3fb9b6f0ee525b7958c6d8a9"
COMPARE_FIELDS=("nodes","maximum_depth","rejected_prefix","rejected_full",
 "rejected_unterminated","accepted_complete","rejected_weight","terminal_weight",
 "certificate_weight","expected_weight","capped")
TEXT_ARTIFACTS={name:HERE/name for name in ("core.py","native.cpp","controls.py","controls.json","generate_fable_fixtures.js","run_target.py")}

def sha(path:Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()

def extract()->str:
    text=MDX.read_text(encoding="utf-8")
    start=text.index("`83 B57B2")+1
    end=text.index("`",start)
    value="".join(text[start:end].split()).upper()
    assert hashlib.sha256(value.encode("ascii")).hexdigest()=="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
    return value

def orientations(value:str)->dict[str,str]:
    pairs=[value[i:i+2] for i in range(0,len(value),2)]
    return {"forward":value,"full_hex_reverse":value[::-1],
      "byte_reverse":"".join(reversed(pairs)),
      "nibble_swap":"".join(x[::-1] for x in pairs)}

def verify_metadata()->tuple[dict,dict]:
    assert sha(RESULTS)==EXPECTED_RESULT_SHA
    data=json.loads(RESULTS.read_text()); gate=json.loads(GATE.read_text())
    assert data["identity"]=="ASTRA" and data["target_evaluated"] is True
    assert data["gate_sha256"]==sha(GATE)
    assert data["scope"]==gate["scope"] and len(data["cells"])==16
    assert data["mdx_sha256"]==sha(MDX)==gate["expected_mdx_sha256"]
    for name,path in TEXT_ARTIFACTS.items():
        assert gate["artifact_hashes"][name]==sha(path),(name,sha(path),gate["artifact_hashes"][name])
    seen=set()
    for row in data["cells"]:
        key=(row["orientation"],row["width"],row["variant"])
        assert key not in seen; seen.add(key)
        assert row["rejected_weight"]+row["terminal_weight"]==row["certificate_weight"]
        assert row["expected_weight"]==math.factorial(row["width"])
        assert row["complete"]==(not row["capped"] and row["certificate_weight"]==row["expected_weight"])
        assert row["accepted_complete"]==len(row["solutions"])
    expected_cells={(o,w,v) for o in gate["scope"]["orientations"] for w in gate["scope"]["widths"] for v in gate["scope"]["variants"]}
    assert seen==expected_cells
    assert data["summary"]=={
      "cells":16,"complete_cells":sum(x["complete"] for x in data["cells"]),
      "capped_cells":sum(x["capped"] for x in data["cells"]),
      "survivors":sum(len(x["solutions"]) for x in data["cells"]),
      "elapsed_seconds":sum(x["elapsed_seconds"] for x in data["cells"])}
    return data,gate

def replay_scratch(data:dict)->None:
    canonical=extract(); oriented=orientations(canonical)
    with tempfile.TemporaryDirectory(prefix="byte-column-verify-") as td:
        binary=Path(td)/"native_search"
        command=["clang++","-std=c++17","-O3",
          "-I/opt/homebrew/opt/openssl@3/include",str(HERE/"native.cpp"),
          "-L/opt/homebrew/opt/openssl@3/lib","-lcrypto",
          "-Wl,-rpath,/opt/homebrew/opt/openssl@3/lib","-o",str(binary)]
        subprocess.run(command,check=True)
        for expected in data["cells"]:
            observed=bytes.fromhex(oriented[expected["orientation"]])
            actual=json.loads(subprocess.check_output([
              str(binary),str(expected["width"]),expected["variant"],
              str(expected["node_limit"]),observed.hex()],text=True))
            for field in COMPARE_FIELDS:
                assert actual[field]==expected[field],(expected["orientation"],expected["width"],expected["variant"],field)
            assert [(x["order"],x["plaintext_hex"]) for x in actual["solutions"]] == [(x["order"],x["plaintext_hex"]) for x in expected["solutions"]]
    print(json.dumps({"identity":"ASTRA","scratch_replay":True,
      "cells_equal_excluding_elapsed_seconds":16,"result_sha256":sha(RESULTS)},indent=2))

def main()->None:
    parser=argparse.ArgumentParser()
    parser.add_argument("--replay-scratch",action="store_true",
      help="compile native.cpp in a temporary directory and replay all 16 cells")
    args=parser.parse_args()
    data,gate=verify_metadata()
    if args.replay_scratch: replay_scratch(data)
    else: print(json.dumps({"identity":"ASTRA","metadata_certificate_check":True,
      "cells":len(data["cells"]),"complete_cells":data["summary"]["complete_cells"],
      "survivors":data["summary"]["survivors"],"result_sha256":sha(RESULTS),
      "elapsed_seconds_excluded_from_equality":True},indent=2))

if __name__=="__main__":main()

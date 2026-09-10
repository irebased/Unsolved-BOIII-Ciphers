#!/usr/bin/env python3
"""Freeze the byte-column target gate without parsing or evaluating Rev7."""
from __future__ import annotations
import hashlib, json
from pathlib import Path

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]
MDX=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
OUT=HERE/"target_gate.json"
IDENTITY="ASTRA"
MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
CIPHER_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
ARTIFACTS={
 "core.py":HERE/"core.py","native.cpp":HERE/"native.cpp","native_search":HERE/"native_search",
 "controls.py":HERE/"controls.py","controls.json":HERE/"controls.json",
 "generate_fable_fixtures.js":HERE/"generate_fable_fixtures.js","run_target.py":HERE/"run_target.py",
}

def sha(path:Path)->str: return hashlib.sha256(path.read_bytes()).hexdigest()

def main()->None:
    if OUT.exists(): raise SystemExit(f"refusing existing gate: {OUT}")
    assert sha(MDX)==MDX_SHA
    controls=json.loads((HERE/"controls.json").read_text())
    assert controls["identity"]==IDENTITY and controls["target_evaluated"] is False
    assert controls["rev7_file_read"] is False and controls["assertions"]["all_passed"] is True
    assert controls["endpoint"]["utf8_sequences"]==["e28093","e28094","e28098","e28099","e280a6"]
    assert controls["rev9_endpoint_control"]["five_sequence_fsa_accepts"] is True
    assert controls["rev9_endpoint_control"]["old_four_sequence_fsa_accepts"] is False
    assert len(controls["small_width_3_to_6_exact_comparisons"])==8
    assert len(controls["width_13_14_registered_five_utf8_plants"])==4
    for row in controls["width_13_14_registered_five_utf8_plants"]:
        assert row["certificate_weight"]==row["expected_weight"]
        assert row["truth_recovered"] and row["unique_solution"]
    assert controls["fable_fixed_inverse_fixture"]["A"]["matched"]
    assert controls["fable_fixed_inverse_fixture"]["B"]["matched"]
    for name,path in ARTIFACTS.items():
        if name in controls["source_hashes"]:
            assert controls["source_hashes"][name]==sha(path)
    result={
      "identity":IDENTITY,"target_evaluated":False,
      "mdx_bytes_hashed_only":True,"rev7_ciphertext_parsed":False,
      "expected_mdx_sha256":MDX_SHA,"expected_ciphertext_sha256":CIPHER_SHA,
      "artifact_hashes":{name:sha(path) for name,path in ARTIFACTS.items()},
      "scope":{
        "cipher":"AES-128","key_hex":(b"Zombies"+bytes(9)).hex(),
        "iv_hex":(b"0"*16).hex(),"mode":"CFB8","widths":[13,14],
        "variants":["A","B"],
        "orientations":["forward","full_hex_reverse","byte_reverse","nibble_swap"],
        "node_limit_per_cell":10000000,"cell_count":16,
        "endpoint_utf8_sequences":["e28093","e28094","e28098","e28099","e280a6"],
      },
      "control_gate":{
        "controls_sha256":sha(HERE/"controls.json"),
        "all_control_assertions_passed":True,
        "fable_fixed_fixtures_matched":True,
        "small_naive_reference_native_equal":True,
        "width13_14_plants_unique_and_exhaustive":True,
        "cap_weight_is_lower_bound_when_incomplete":True,
      },
      "limits":"Each cell starts a fresh root and stops at 10,000,000 accepted-prefix DFS entries. A capped certificate is only a lower bound. Widths, variants, cipher, key, IV, orientations, and five UTF-8 punctuation sequences are the entire registered scope."
    }
    OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"identity":IDENTITY,"target_evaluated":False,
      "gate":str(OUT),"sha256":sha(OUT),"driver_sha256":sha(HERE/"run_target.py")},indent=2))

if __name__=="__main__":main()

#!/usr/bin/env python3
"""Freeze stronger all-IV target gate without parsing Rev7 ciphertext."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
MDX=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
OUT=HERE/"stronger_target_gate.json"
IDENTITY="ASTRA"
MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
CIPHER_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
ARTIFACTS={name:HERE/name for name in ("core.py","controls.py","controls.json",
 "stronger.py","stronger_controls.py","stronger_controls.json","run_stronger_target.py")}
def sha(path:Path)->str:return hashlib.sha256(path.read_bytes()).hexdigest()
def main()->None:
    if OUT.exists():raise SystemExit(f"refusing existing gate: {OUT}")
    assert sha(MDX)==MDX_SHA
    old=json.loads((HERE/"controls.json").read_text())
    new=json.loads((HERE/"stronger_controls.json").read_text())
    assert old["identity"]==new["identity"]==IDENTITY
    assert old["target_evaluated"] is False and new["target_evaluated"] is False
    assert old["rev7_file_read"] is False and new["rev7_file_read"] is False
    assert old["assertions"]["all_passed"] and new["assertions"]["all_passed"]
    for name in ("core.py","controls.py"):
        assert old["source_hashes"][name]==sha(HERE/name)
    assert new["source_hashes"]["original_core.py"]==sha(HERE/"core.py")
    assert new["source_hashes"]["original_controls.json"]==sha(HERE/"controls.json")
    assert new["source_hashes"]["stronger.py"]==sha(HERE/"stronger.py")
    assert new["source_hashes"]["stronger_controls.py"]==sha(HERE/"stronger_controls.py")
    result={"identity":IDENTITY,"target_evaluated":False,
      "mdx_bytes_hashed_only":True,"rev7_ciphertext_parsed":False,
      "expected_mdx_sha256":MDX_SHA,"expected_ciphertext_sha256":CIPHER_SHA,
      "artifact_hashes":{name:sha(path) for name,path in ARTIFACTS.items()},
      "scope":{"cipher":"AES-128","key_hex":(b"Zombies"+bytes(9)).hex(),
        "mode":"CFB8","iv_scope":"every external 16-byte IV","widths":[13,14],
        "variant":"B","orientations":["forward","full_hex_reverse","byte_reverse","nibble_swap"],
        "cell_count":8,"endpoint_utf8_sequences":["e28093","e28094","e28098","e28099","e280a6"]},
      "control_gate":{"original_controls_sha256":sha(HERE/"controls.json"),
        "stronger_controls_sha256":sha(HERE/"stronger_controls.json"),
        "all_assertions_passed":True,"two_iv_suffix_and_direct_recurrence":True,
        "boundary_state_set_controls":True,"corrupted_chunk_two_iv_naive_controls":True,
        "original_partial_vs_stronger_full_weight_control":True},
      "claim":"For rectangular variant B, every observed strided rank is an unavoidable contiguous natural ciphertext chunk. One suffix invalid from all FSA boundary states proves no order and no external IV can yield the registered endpoint.",
      "limits":"A cell with no rejected chunk remains unresolved. The scope excludes variant A, ragged columns, prepended-IV framing, other keys/ciphers/modes, and broader endpoints."}
    OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"identity":IDENTITY,"target_evaluated":False,
      "gate":str(OUT),"sha256":sha(OUT),
      "driver_sha256":sha(HERE/"run_stronger_target.py")},indent=2))
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Freeze ragged-B 124-cell target gate without parsing Rev7 ciphertext."""
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[3]
MDX=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
OUT=HERE/"target_gate.json";PRIOR=HERE.parent/"stronger_target_results.json"
IDENTITY="ASTRA";MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
CIPHER_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
    if OUT.exists():raise SystemExit("refusing existing "+str(OUT))
    assert sha(MDX)==MDX_SHA
    c=json.loads((HERE/"controls.json").read_text())
    assert c["identity"]==IDENTITY and c["target_evaluated"] is False and c["rev7_file_read"] is False
    assert c["assertions"]["all_passed"]
    assert c["source_hashes"]["core.py"]==sha(HERE/"core.py")
    assert c["source_hashes"]["controls.py"]==sha(HERE/"controls.py")
    old=json.loads(PRIOR.read_text())
    assert old["identity"]==IDENTITY and old["target_evaluated"] is True
    assert old["ciphertext_sha256"]==CIPHER_SHA and len(old["cells"])==8
    assert all(x["complete_every_iv_every_order_exclusion"] for x in old["cells"])
    artifacts={"core.py":HERE/"core.py","controls.py":HERE/"controls.py",
      "controls.json":HERE/"controls.json","run_target.py":HERE/"run_target.py",
      "prior_stronger_target_results.json":PRIOR}
    result={"identity":IDENTITY,"target_evaluated":False,
      "mdx_bytes_hashed_only":True,"rev7_ciphertext_parsed":False,
      "expected_mdx_sha256":MDX_SHA,"expected_ciphertext_sha256":CIPHER_SHA,
      "artifact_hashes":{name:sha(p) for name,p in artifacts.items()},
      "scope":{"cipher":"AES-128","key_hex":(b"Zombies"+bytes(9)).hex(),
        "mode":"CFB8","iv_scope":"every external 16-byte IV",
        "widths":list(range(2,33)),"variant":"B",
        "ragged_conventions":["first","last"],
        "orientations":["forward","full_hex_reverse","byte_reverse","nibble_swap"],
        "cell_count":124,"prior_covered_cells":8,"new_contexts":116,
        "endpoint_utf8_sequences":["e28093","e28094","e28098","e28099","e280a6"]},
      "control_gate":{"controls_sha256":sha(HERE/"controls.json"),
        "all_assertions_passed":True,"fable_ragged_first_last_exact":True,
        "arbitrary_iv_plants_and_tail_invariance":True,
        "small_width_all_orders_two_iv_controls":True,
        "width32_supported_width33_unsupported":True,
        "prior_stronger_results_sha256":sha(PRIOR),"prior_eight_cells_complete":True},
      "claim":"For ragged variant B, observed[j:q*w:w] is an unavoidable natural ciphertext prefix under either long-column convention. One suffix invalid from all boundary states excludes every order and every external IV for each convention.",
      "limits":"A cell with every examined chunk retained remains unresolved. First/last convention certificates are parallel and are never added. Scope excludes variant A, width 33+, other ciphers, keys, modes, and endpoints."}
    OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"gate":str(OUT),
      "sha256":sha(OUT),"driver_sha256":sha(HERE/"run_target.py")},indent=2))
if __name__=="__main__":main()

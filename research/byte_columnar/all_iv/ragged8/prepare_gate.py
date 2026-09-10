#!/usr/bin/env python3
"""Freeze prospective ragged8 target gate without parsing target ciphertext."""
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];MDX=ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
OUT=HERE/"target_gate.json";NC=ROOT/"research/rev7-20260909-codex/hex_cfb/native_compat"
IDENTITY="ASTRA";MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91";CIPHER_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 if OUT.exists():raise SystemExit("refusing existing "+str(OUT))
 assert sha(MDX)==MDX_SHA
 c=json.loads((HERE/"controls.json").read_text());assert c["identity"]==IDENTITY and c["target_evaluated"] is False and c["rev7_file_read"] is False and c["assertions"]["all_passed"]
 assert c["source_hashes"]["core.py"]==sha(HERE/"core.py") and c["source_hashes"]["controls.py"]==sha(HERE/"controls.py")
 rep=json.loads((NC/"source_check_reproduction.json").read_text());assert rep["identity"]==IDENTITY and rep["actual_standard_and_compat_sources_word_reverse_relationship"]
 arts={"core.py":HERE/"core.py","controls.py":HERE/"controls.py","controls.json":HERE/"controls.json","run_target.py":HERE/"run_target.py",
  "compat_source_check.py":NC/"source_check.py","compat_source_check_reproduction.json":NC/"source_check_reproduction.json",
  "compat_c_source":NC/"source/blowfish-compat.c","compat_library":NC/"source_build/libblowfish_compat.so"}
 result={"identity":IDENTITY,"target_evaluated":False,"mdx_bytes_hashed_only":True,"rev7_ciphertext_parsed":False,
  "expected_mdx_sha256":MDX_SHA,"expected_ciphertext_sha256":CIPHER_SHA,
  "artifact_hashes":{n:sha(p) for n,p in arts.items()},
  "scope":{"ciphers":[{"name":"DES","id":"des","key_hex":(b"Zombies\0").hex()},
   {"name":"Blowfish","id":"blowfish","key_hex":b"Zombies".hex()},
   {"name":"Blowfish-compat","id":"blowfish_compat","key_hex":b"Zombies".hex()}],
   "block_size":8,"mode":"CFB8","iv_scope":"every external 8-byte IV","widths":list(range(2,61)),
   "variant":"B","ragged_conventions":["first","last"],
   "orientations":["forward","full_hex_reverse","byte_reverse","nibble_swap"],"cell_count":708,
   "endpoint_utf8_sequences":["e28093","e28094","e28098","e28099","e280a6"]},
  "control_gate":{"controls_sha256":sha(HERE/"controls.json"),"all_assertions_passed":True,
   "fable_first_last_exact":True,"block_adapter_consistency_and_independent_cfb_modes":True,
   "compat_original_source_reproduction_sha256":sha(NC/"source_check_reproduction.json"),
   "arbitrary_iv_plants_tail_invariance_and_small_exhaustive":True,"width60_supported_width61_unsupported":True},
  "claim":"For each 8-byte-block cipher, one unavoidable ragged-B chunk suffix invalid from every FSA boundary state excludes every order and every external 8-byte IV for each convention.",
  "limits":"No target has run. A cell with all inspected chunks retained remains unresolved. Convention weights are parallel, never added. Other modes, keys, ciphers, variants, widths and endpoints are outside scope."}
 OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"gate_sha256":sha(OUT),"driver_sha256":sha(HERE/"run_target.py")},indent=2))
if __name__=="__main__":main()

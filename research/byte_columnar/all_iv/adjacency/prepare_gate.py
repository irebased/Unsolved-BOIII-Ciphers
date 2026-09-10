#!/usr/bin/env python3
"""Freeze adjacency target gate without parsing target ciphertext."""
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];MDX=ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx";OUT=HERE/"target_gate.json";NC=ROOT/"research/rev7-20260909-codex/hex_cfb/native_compat";R8=HERE.parent/"ragged8/core.py"
MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91";CIPHER_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 if OUT.exists():raise SystemExit("refusing existing "+str(OUT))
 assert sha(MDX)==MDX_SHA;c=json.loads((HERE/"controls.json").read_text());assert c["identity"]=="ASTRA" and c["target_evaluated"] is False and c["rev7_file_read"] is False and c["assertions"]["all_passed"]
 arts={"core.py":HERE/"core.py","controls.py":HERE/"controls.py","controls.json":HERE/"controls.json","run_target.py":HERE/"run_target.py","audited_ragged8_core.py":R8,
  "compat_c_source":NC/"source/blowfish-compat.c","compat_source_check_reproduction.json":NC/"source_check_reproduction.json","compat_library":NC/"source_build/libblowfish_compat.so"}
 result={"identity":"ASTRA","target_evaluated":False,"mdx_bytes_hashed_only":True,"rev7_ciphertext_parsed":False,"expected_mdx_sha256":MDX_SHA,"expected_ciphertext_sha256":CIPHER_SHA,
  "artifact_hashes":{n:sha(p) for n,p in arts.items()},
  "scope":{"cells":[{"cipher":"aes128","block_size":16,"widths":[39,42],"key_hex":(b"Zombies"+bytes(9)).hex()},
   {"cipher":"des","block_size":8,"widths":[78,91],"key_hex":(b"Zombies\0").hex()},
   {"cipher":"blowfish","block_size":8,"widths":[78,91],"key_hex":b"Zombies".hex()},
   {"cipher":"blowfish_compat","block_size":8,"widths":[78,91],"key_hex":b"Zombies".hex()}],
   "mode":"CFB8","iv_scope":"every external block-size IV","variant":"B","rectangular":True,
   "orientations":["forward","full_hex_reverse","byte_reverse","nibble_swap"],"cell_count":32,
   "endpoint_utf8_sequences":["e28093","e28094","e28098","e28099","e280a6"],
   "closure_rules":["at least two zero-indegree vertices","at least two zero-outdegree vertices","weakly disconnected graph"]},
  "control_gate":{"controls_sha256":sha(HERE/"controls.json"),"all_assertions_passed":True,"valid_true_paths_no_false_closure":True,"two_iv_suffix_checks":True,"tiny_full_order_and_graph_enumeration":True,"only_declared_closures":True},
  "limits":"No Hamiltonian search. Any graph not closed by the three rules is unresolved. Rectangular variant B and registered fixed primitives/endpoints only."}
 OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n");print(json.dumps({"identity":"ASTRA","target_evaluated":False,"gate_sha256":sha(OUT),"driver_sha256":sha(HERE/"run_target.py")},indent=2))
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Portable read-only structural verifier for the frozen Blowfish target ledger."""
import argparse,hashlib,json,math
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4]
RESULT=HERE/"target_results.json";GATE=HERE/"target_gate.json";DRIVER=HERE/"run_target.py";MDX=ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
NATIVE_REL="research/rev7-20260909-codex/iv_independent/blowfish_solver/native";BUILD_REL="research/rev7-20260909-codex/iv_independent/blowfish_solver/native_build.json";SOURCE_REL="research/rev7-20260909-codex/iv_independent/blowfish_solver/native.cpp"
EXPECTED_RESULT="dffebff216727736c2b21b58a3dfc75576b7798375603a0d6bc8ee67338d83fc";EXPECTED_GATE="507f5c9d3f0a489ca612bfaf1600c9c3de91f844208540962b8a087274204a2b";EXPECTED_DRIVER="d9b6d343f23c8f343ce0584a20a659d5277d5f40385ec68821e7d1b7ce7e32d9";MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91";TEXT_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c";FULL=math.factorial(16);LIMIT=1_000_000_000
BACKENDS=("blowfish","blowfish_compat");ORIENTATIONS=("forward","full_hex_reverse","byte_reverse","nibble_swap")
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def orientations():
 text=MDX.read_text();start=text.index("`83 B57B2")+1;end=text.index("`",start);canonical="".join(text[start:end].split()).upper();assert len(canonical)==1092 and hashlib.sha256(canonical.encode()).hexdigest()==TEXT_SHA
 pairs=[canonical[i:i+2] for i in range(0,len(canonical),2)]
 return dict(zip(ORIENTATIONS,(canonical,canonical[::-1],"".join(reversed(pairs)),"".join(pair[::-1] for pair in pairs))))
def geometry(display):
 pairs=[(int(display[i],16),int(display[i+1],16)) for i in range(0,len(display),2)]
 windows=[set(x for pair in pairs[i-8:i+1] for x in pair) for i in range(8,len(pairs))]
 freq=[0]*16
 for a,b in pairs:freq[a]+=1;freq[b]+=1
 best=min(range(len(windows)),key=lambda i:(len(windows[i]),-sum(w<=windows[i] for w in windows),i));anchor=windows[best]
 order=sorted(anchor,key=lambda symbol:(-freq[symbol],symbol));selected=set(order);bound=sum(w<=selected for w in windows);counts=[bound]
 while len(order)<16:
  choices=[]
  for symbol in set(range(16))-selected:
   after=selected|{symbol};new=sum(w<=after for w in windows)-bound;contained=sum(symbol in w for w in windows);choices.append((new,contained,-symbol,symbol))
  _,_,_,symbol=max(choices);order.append(symbol);selected.add(symbol);bound=sum(w<=selected for w in windows);counts.append(bound)
 return {"anchor_window_suffix_index":best+8,"anchor_unique_symbols":len(anchor),"symbol_order":order,"fully_bound_window_counts":counts}
def main():
 parser=argparse.ArgumentParser();parser.add_argument("--check-local-binary",action="store_true");args=parser.parse_args()
 assert sha(RESULT)==EXPECTED_RESULT and sha(GATE)==EXPECTED_GATE and sha(DRIVER)==EXPECTED_DRIVER and sha(MDX)==MDX_SHA
 gate=json.loads(GATE.read_text());result=json.loads(RESULT.read_text())
 assert gate["identity"]=="ASTRA" and gate["target_evaluated"] is False and gate["driver_sha256"]==EXPECTED_DRIVER
 for rel,expected in gate["artifact_hashes"].items():
  if rel!=NATIVE_REL:assert sha(ROOT/rel)==expected,rel
 build=json.loads((ROOT/BUILD_REL).read_text())
 assert build["identity"]=="ASTRA" and build["target_evaluated"] is False
 assert build["source_sha256"]==gate["artifact_hashes"][SOURCE_REL]==sha(ROOT/SOURCE_REL)
 assert build["binary_sha256"]==gate["artifact_hashes"][NATIVE_REL]
 local_binary_checked=False
 if args.check_local_binary:
  assert (ROOT/NATIVE_REL).is_file() and sha(ROOT/NATIVE_REL)==build["binary_sha256"]
  local_binary_checked=True
 assert result["identity"]=="ASTRA" and result["target_evaluated"] is True and result["status"]=="complete"
 config=result["configuration"];assert config["gate_sha256"]==EXPECTED_GATE and config["driver_sha256"]==EXPECTED_DRIVER and config["artifact_hashes"]==gate["artifact_hashes"] and config["ciphertext_sha256"]==TEXT_SHA
 for key,value in gate["scope"].items():assert config[key]==value,key
 oriented=orientations();expected={(backend,orientation) for backend in BACKENDS for orientation in ORIENTATIONS};seen=set()
 nodes=ecb_calls=0;elapsed=0.0
 for cell in result["cells"]:
  key=(cell["cipher"],cell["orientation"]);assert key in expected and key not in seen;seen.add(key);display=oriented[key[1]]
  assert cell["identity"]=="ASTRA" and cell["display_sha256"]==hashlib.sha256(display.encode()).hexdigest()
  expected_geometry=geometry(display)
  assert cell["independent_geometry_exact"] is True and cell["native_geometry"]["explicit_order_override"] is False
  for field,value in expected_geometry.items():assert cell["native_geometry"][field]==value,(key,field)
  stats=cell["stats"];assert stats["node_limit"]==LIMIT and 0<stats["nodes"]<LIMIT
  assert stats["aborted_at_node_limit"] is False and stats["certificate_complete"] is True and stats["search_status"]=="complete"
  assert stats["expected_factorial_weight"]==stats["certificate_weight"]==stats["rejected_completion_weight"]==FULL
  assert stats["terminal_completion_weight"]==stats["unaccounted_mapping_weight"]==0 and stats["capped_interpretation"] is None
  assert cell["survivor_count"]==0 and cell["survivors"]==[] and cell["all_survivors_independently_validated"] is True
  nodes+=stats["nodes"];ecb_calls+=stats["ecb_calls"];elapsed+=stats["elapsed_seconds"]
 assert seen==expected and len(result["cells"])==8
 summary=result["summary"];assert summary=={"cells":8,"complete_cells":8,"capped_cells":0,"survivors":0,"total_nodes":nodes,"total_ecb_calls":ecb_calls,"total_native_elapsed_seconds":elapsed}
 print(json.dumps({"identity":"ASTRA","verified":True,"read_only":True,"verification_kind":"hash, source provenance, canonical orientations, deterministic geometry, and stored accounting; no DFS replay","target_rerun":False,"local_binary_checked":local_binary_checked,"recorded_binary_sha256":build["binary_sha256"],"result_sha256":EXPECTED_RESULT,"gate_sha256":EXPECTED_GATE,"cells":8,"complete_cells":8,"capped_cells":0,"survivors":0,"total_nodes":nodes,"total_ecb_calls":ecb_calls,"total_native_elapsed_seconds":elapsed},indent=2))
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Control-gated 72-cell target driver for fixed-keystream CSP."""
import argparse,hashlib,json,math,os,sys,time
from dataclasses import asdict
from pathlib import Path
HERE=Path(__file__).resolve().parent
HEX=HERE.parent/"hex_cfb"; REPO=HERE.parents[2]
sys.path[:0]=[str(HERE),str(HEX)]
import core,prototype
IDENTITY="ASTRA"; LIMIT=1_000_000; FULL=math.factorial(16)
CIPHERS=("aes128","blowfish","des"); MODES=("ofb8","fullblock_ofb")
IVS=("ascii_zero","nul","sha1_prefix")
ORIENT=("forward","reverse","byte_reverse","nibble_swap")
REV7=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
CONTROLS=HERE/"controls.json"; GATE=HERE/"target_gate.json"
CIPHER_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
FROZEN={"core.py":"d92be85a1738d8efb9fe8c9a7b41102f78a659db679334d113384ad3cc9eadb7","controls.py":"fdd921ecff19a287fe0c1689839fed521b2fe0007e6fda3ae5d84f3d5a978c97","controls.json":"4e7535f3e3f3a098211d63811554af360ebd0c50efd58ea34e35efc3298724ea",
"ofb8_results.json":"20d226a76ede6b63a9f6e07675e2733c5bc74b0e5c86f3d960ebf56caeed10f9",
"prototype.py":"416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b",
"rev7_mdx":"085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def hashes():return {"core.py":sha(HERE/"core.py"),"controls.py":sha(HERE/"controls.py"),
"controls.json":sha(CONTROLS),"ofb8_results.json":sha(HERE.parent/"sources"/"ofb8"/"results.json"),
"prototype.py":sha(HEX/"prototype.py"),"rev7_mdx":sha(REV7)}
def scope():return {"identity":IDENTITY,"cells":72,"ciphers":list(CIPHERS),"modes":list(MODES),
"iv_kinds":list(IVS),"orientations":list(ORIENT),"node_limit_per_cell":LIMIT,
"relaxed_bytes":sorted(core.RELAXED),"final_endpoint":"ASCII+TAB/LF/CR or complete E2 80 93/94/98/99 sequences"}
def atomic(p,v):
 t=p.with_name(p.name+".tmp");t.write_text(json.dumps(v,indent=2,sort_keys=True)+"\n");os.replace(t,p)
def require_gate():
 assert hashes()==FROZEN
 c=json.loads(CONTROLS.read_text());r=c["root_pruning_and_cap_controls"]
 assert c["identity"]==IDENTITY and c["target_evaluated"] is False
 assert r["empty_repeated_pair"]["certificate_complete"]
 assert r["singleton_all_different_clash"]["both_relations_nonempty"]
 assert r["singleton_all_different_clash"]["certificate_complete"]
 assert r["cap_one"]["capped"] and not r["cap_one"]["certificate_complete"]
 g=json.loads(GATE.read_text())
 assert g["identity"]==IDENTITY and g["target_evaluated"] is False
 assert g["scope"]==scope() and g["frozen_hashes"]==FROZEN
 assert g["driver_sha256"]==sha(Path(__file__))
 return sha(GATE)
def extract():
 text=REV7.read_text(); tick=chr(96); start=text.index(tick+"83 B57B2")+1;end=text.index(tick,start)
 value="".join(text[start:end].split()).upper()
 assert len(value)==1092 and hashlib.sha256(value.encode()).hexdigest()==CIPHER_SHA
 oriented=prototype.orientations(value);assert tuple(oriented)==ORIENT
 return value,oriented
def rel_summary(rel):
 sizes=[len(v) for v in rel.values()]
 return {"ordered_display_pair_count":len(rel),"minimum_relation_size":min(sizes),
 "maximum_relation_size":max(sizes),"empty_relations":[prototype.HEX[a]+prototype.HEX[b] for (a,b),v in rel.items() if not v]}
def unrestricted(display,ks):
 positions={}
 for i in range(len(ks)):positions.setdefault(display[2*i:2*i+2],[]).append(i)
 for pair,indices in sorted(positions.items()):
  if len(indices)<2:continue
  support=set(range(256));used=[]
  for i in indices:
   support&={p^ks[i] for p in core.RELAXED};used.append(i)
   if not support:return {"display_pair":pair,"positions":used,"keystream_bytes":[ks[j] for j in used],
   "intersection":[],"interpretation":"No fixed ciphertext byte for this repeated displayed pair makes every listed position relaxed-valid."}
 return None
def validate(display,ks,solutions):
 out=[]
 for s in solutions:
  m=list(s["mapping"]);assert sorted(m)==list(range(16))
  ct=core.decode(display,m);plain=bytes(a^b for a,b in zip(ct,ks))
  assert plain==s["plaintext"] and core.display_encode(ct,m)==display
  assert all(x in core.RELAXED for x in plain)
  fsa=core.valid_fsa(plain);assert fsa==s["fsa_valid"]
  assert bytes(a^b for a,b in zip(plain,ks))==ct
  out.append({"mapping_display_to_nibble":m,"plaintext_hex":plain.hex(),
  "plaintext_sha256":hashlib.sha256(plain).hexdigest(),"relaxed_valid":True,
  "fsa_valid":fsa,"exact_inverse_map":True,"full_recipher":True})
 return out
def stat(st):
 d=asdict(st);cert=st.rejected_weight+st.terminal_weight
 if st.capped:assert st.nodes==LIMIT and cert<FULL
 else:assert cert==FULL
 d.update({"node_limit":LIMIT,"certificate_weight":cert,"expected_weight":FULL,
 "certificate_complete":not st.capped and cert==FULL,"status":"capped" if st.capped else "complete"})
 return d
def run(output,checkpoint,resume):
 if output.exists():raise SystemExit("refusing existing output")
 gate=require_gate();canonical,oriented=extract()
 config={**scope(),"ciphertext_sha256":CIPHER_SHA,"gate_sha256":gate,
 "driver_sha256":sha(Path(__file__)),"frozen_hashes":FROZEN}
 if checkpoint.exists():
  if not resume:raise SystemExit("refusing checkpoint without --resume")
  result=json.loads(checkpoint.read_text());assert result["configuration"]==config
 else:
  if resume:raise SystemExit("--resume requested but checkpoint absent")
  result={"identity":IDENTITY,"target_evaluated":True,"configuration":config,"cells":[]}
 done={(x["cipher"],x["mode"],x["iv_kind"],x["orientation"]) for x in result["cells"]}
 for cipher in CIPHERS:
  mod,key_bytes=core.specs()[cipher]
  for mode in MODES:
   for iv_name in IVS:
    ks=core.keystream(cipher,mode,core.ivs(mod.block_size)[iv_name],len(canonical)//2)
    for orient in ORIENT:
     key=(cipher,mode,iv_name,orient)
     if key in done:continue
     display=oriented[orient];t=time.perf_counter();sol,st,rel=core.solve(display,ks,LIMIT);elapsed=time.perf_counter()-t
     checked=validate(display,ks,sol);w=unrestricted(display,ks)
     row={"identity":IDENTITY,"cipher":cipher,"mode":mode,"iv_kind":iv_name,"orientation":orient,
     "key_hex":key_bytes.hex(),"iv_hex":core.ivs(mod.block_size)[iv_name].hex(),
     "keystream_sha256":hashlib.sha256(ks).hexdigest(),
     "displayed_sha256":hashlib.sha256(display.encode()).hexdigest(),"relation_summary":rel_summary(rel),
     "unrestricted_fixed_byte_witness":w,"root_unsat":st.nodes==0,"stats":stat(st),
     "elapsed_seconds":elapsed,"relaxed_survivor_count":len(checked),
     "fsa_survivor_count":sum(x["fsa_valid"] for x in checked),"survivors":checked}
     result["cells"].append(row);atomic(checkpoint,result)
     print(json.dumps({"cell":key,"status":row["stats"]["status"],"nodes":st.nodes,
     "certificate":row["stats"]["certificate_weight"],"relaxed":row["relaxed_survivor_count"],
     "fsa":row["fsa_survivor_count"],"unrestricted_witness":w is not None}),flush=True)
 assert len(result["cells"])==72
 result["summary"]={"complete_cells":sum(x["stats"]["certificate_complete"] for x in result["cells"]),
 "capped_cells":sum(x["stats"]["capped"] for x in result["cells"]),
 "root_unsat_cells":sum(x["root_unsat"] for x in result["cells"]),
 "unrestricted_witness_cells":sum(x["unrestricted_fixed_byte_witness"] is not None for x in result["cells"]),
 "relaxed_survivors":sum(x["relaxed_survivor_count"] for x in result["cells"]),
 "fsa_survivors":sum(x["fsa_survivor_count"] for x in result["cells"])}
 atomic(checkpoint,result);os.replace(checkpoint,output)
 print(json.dumps({"identity":IDENTITY,"result_sha256":sha(output),"summary":result["summary"]},indent=2))
def main():
 ap=argparse.ArgumentParser();g=ap.add_mutually_exclusive_group(required=True)
 g.add_argument("--selftest",action="store_true");g.add_argument("--run-target",action="store_true")
 ap.add_argument("--output",type=Path,default=HERE/"target_results.json")
 ap.add_argument("--checkpoint",type=Path,default=HERE/"target_checkpoint.json")
 ap.add_argument("--resume",action="store_true");a=ap.parse_args()
 if a.selftest:
  if a.resume:ap.error("--resume target-only")
  print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"gate_sha256":require_gate(),"scope":scope()},indent=2))
 else:run(a.output,a.checkpoint,a.resume)
if __name__=="__main__":main()

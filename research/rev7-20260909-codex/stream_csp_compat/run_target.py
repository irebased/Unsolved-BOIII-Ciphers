#!/usr/bin/env python3
"""Control-gated 24-cell Blowfish-compat OFB CSP target driver."""
import argparse,hashlib,json,math,os,sys,time
from dataclasses import asdict
from pathlib import Path
HERE=Path(__file__).resolve().parent;RESEARCH=HERE.parent;REPO=HERE.parents[2]
sys.path[:0]=[str(HERE),str(RESEARCH/"stream_csp"),str(RESEARCH/"hex_cfb")]
import compat_stream,core,prototype
IDENTITY="ASTRA";LIMIT=1_000_000;FULL=math.factorial(16);HEX="0123456789ABCDEF"
KEY=b"Zombies";MODES=("ofb8","fullblock_ofb");IVS=("ascii_zero","nul","sha1_prefix")
ORIENT=("forward","reverse","byte_reverse","nibble_swap")
RELAXED={9,10,13}|set(range(32,127))|{0xE2,0x80,0x93,0x94,0x98,0x99}
REV7=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
GATE=HERE/"target_gate.json";CONTROLS=HERE/"controls.json"
CIPHER_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
FROZEN={"compat_stream.py":"f0f5eab61e2940aada5ee92828d2fc8474b99e4d68ec10b63053190d0bddd38c",
"controls.py":"2d3fb03ce5e4a5eec8a79e2fe111f5a9186a4dad372c7c55c89877c543ee82a7",
"controls.json":"f83b1c9d1dd3f5e0ea31b6231346c3c6c0f24f454cc8ed5e9962de61dfe9c719",
"stream_csp_core.py":"d92be85a1738d8efb9fe8c9a7b41102f78a659db679334d113384ad3cc9eadb7",
"prototype.py":"416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b",
"source_check.py":"3945fbebcc7ae8c8bd8df0b450590e149e7cbd86443bd9d92ddbae90ab91e69d",
"source_check_reproduction.json":"123724d5575fa7c2be2868d8218f774f775a395eae693e2049caa703eee47295",
"libblowfish_compat.so":"62ba2b2d1d104aa16c8a855b8bd29af3f6ed987c0008b3a8ba20c22f12e0a319",
"ofb8_run.py":"66e719b03625b163e4018a3c7531069a2b51dcb69131842721ce6d6a5fef5bf9",
"libofb8.so":"b05f73c87b40ad8e23e6d4ae865167a63329823932b6b38d517b48171def4f48",
"rev7_mdx":"085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def hashes():return {"compat_stream.py":sha(HERE/"compat_stream.py"),"controls.py":sha(HERE/"controls.py"),
"controls.json":sha(CONTROLS),"stream_csp_core.py":sha(RESEARCH/"stream_csp"/"core.py"),
"prototype.py":sha(RESEARCH/"hex_cfb"/"prototype.py"),
"source_check.py":sha(RESEARCH/"hex_cfb"/"native_compat"/"source_check.py"),
"source_check_reproduction.json":sha(RESEARCH/"hex_cfb"/"native_compat"/"source_check_reproduction.json"),
"libblowfish_compat.so":sha(RESEARCH/"hex_cfb"/"native_compat"/"source_build"/"libblowfish_compat.so"),
"ofb8_run.py":sha(RESEARCH/"sources"/"ofb8"/"run.py"),
"libofb8.so":sha(RESEARCH/"sources"/"ofb8"/"build"/"libofb8.so"),"rev7_mdx":sha(REV7)}
def scope():return {"identity":IDENTITY,"cells":24,"cipher":"blowfish_compat","key_hex":KEY.hex(),
"modes":list(MODES),"iv_kinds":list(IVS),"orientations":list(ORIENT),
"node_limit_per_cell":LIMIT,"relaxed_bytes":sorted(RELAXED),
"final_endpoint":"ASCII+TAB/LF/CR or complete E2 80 93/94/98/99 sequences"}
def atomic(p,v):
 t=p.with_name(p.name+".tmp");t.write_text(json.dumps(v,indent=2,sort_keys=True)+"\n");os.replace(t,p)
def require_gate():
 assert RELAXED==core.RELAXED and hashes()==FROZEN
 c=json.loads(CONTROLS.read_text())
 assert c["identity"]==IDENTITY and c["target_evaluated"] is False and c["assertions"]["all_passed"]
 assert len(c["stream_vectors"])==24
 g=json.loads(GATE.read_text())
 assert g["identity"]==IDENTITY and g["target_evaluated"] is False
 assert g["scope"]==scope() and g["frozen_hashes"]==FROZEN and g["driver_sha256"]==sha(Path(__file__))
 return sha(GATE)
def extract():
 text=REV7.read_text();q=chr(96);start=text.index(q+"83 B57B2")+1;end=text.index(q,start)
 value="".join(text[start:end].split()).upper()
 assert len(value)==1092 and hashlib.sha256(value.encode()).hexdigest()==CIPHER_SHA
 o=prototype.orientations(value);assert tuple(o)==ORIENT
 return value,o
def independent_keystream(mode,iv,n,block):
 reg=iv;out=bytearray()
 if mode=="ofb8":
  for _ in range(n):
   transformed=block(reg);k=transformed[0];out.append(k);reg=reg[1:]+bytes([k])
 else:
  while len(out)<n:reg=block(reg);out.extend(reg)
 return bytes(out[:n])
def decode(display,mapping):
 return bytes((mapping[HEX.index(display[i])]<<4)|mapping[HEX.index(display[i+1])] for i in range(0,len(display),2))
def encode(ciphertext,mapping):
 inv=[None]*16
 for displayed,actual in enumerate(mapping):inv[actual]=displayed
 return "".join(HEX[inv[n]] for b in ciphertext for n in (b>>4,b&15))
def fsa(data):
 state=0
 for b in data:
  if state==0:
   if b in {9,10,13} or 32<=b<=126:continue
   if b==226:state=1;continue
   return False
  if state==1:
   if b==128:state=2;continue
   return False
  if b in (147,148,152,153):state=0;continue
  return False
 return state==0
def validate(display,ks,solutions):
 out=[]
 for s in solutions:
  m=list(s["mapping"]);assert sorted(m)==list(range(16))
  ct=decode(display,m);plain=bytes(a^b for a,b in zip(ct,ks))
  assert plain==s["plaintext"] and encode(ct,m)==display and all(x in RELAXED for x in plain)
  endpoint=fsa(plain);assert endpoint==s["fsa_valid"]
  assert bytes(a^b for a,b in zip(plain,ks))==ct
  out.append({"mapping_display_to_nibble":m,"plaintext_hex":plain.hex(),
  "plaintext_sha256":hashlib.sha256(plain).hexdigest(),"relaxed_valid":True,
  "fsa_valid":endpoint,"exact_inverse_map":True,"full_recipher":True})
 return out
def witness(display,ks):
 positions={}
 for i in range(len(ks)):positions.setdefault(display[2*i:2*i+2],[]).append(i)
 for pair,indices in sorted(positions.items()):
  if len(indices)<2:continue
  used=[]
  for i in indices:
   used.append(i)
   surviving=[c for c in range(256) if all((c^ks[j]) in RELAXED for j in used)]
   if not surviving:
    assert sum(1 for c in range(256) if all((c^ks[j]) in RELAXED for j in used))==0
    return {"display_pair":pair,"positions":used,"keystream_bytes":[ks[j] for j in used],
    "direct_ciphertext_bytes_checked":256,"surviving_ciphertext_bytes":[],
    "independent_of_nibble_bijection":True}
 return None
def relation_summary(rel):
 sizes=[len(v) for v in rel.values()]
 return {"ordered_pair_count":len(rel),"minimum_size":min(sizes),"maximum_size":max(sizes),
 "empty_relations":[HEX[a]+HEX[b] for (a,b),v in rel.items() if not v]}
def stats(st):
 d=asdict(st);cert=st.rejected_weight+st.terminal_weight
 if st.capped:assert st.nodes==LIMIT and cert<FULL
 else:assert cert==FULL
 d.update({"node_limit":LIMIT,"status":"capped" if st.capped else "complete"})
 counting={"model":"16-symbol global bijection","full_bijections":FULL,
 "rejected_bijections":st.rejected_weight,"relaxed_terminal_bijections":st.terminal_weight,
 "accounted_bijections":cert,"partition_complete":not st.capped and cert==FULL}
 return d,counting
def run(output,checkpoint,resume):
 if output.exists():raise SystemExit("refusing existing output")
 gate=require_gate();canonical,oriented=extract();block=compat_stream.load_block()
 config={**scope(),"ciphertext_sha256":CIPHER_SHA,"gate_sha256":gate,
 "driver_sha256":sha(Path(__file__)),"frozen_hashes":FROZEN}
 if checkpoint.exists():
  if not resume:raise SystemExit("refusing checkpoint without --resume")
  result=json.loads(checkpoint.read_text());assert result["configuration"]==config
 else:
  if resume:raise SystemExit("--resume requested but checkpoint absent")
  result={"identity":IDENTITY,"target_evaluated":True,"configuration":config,"cells":[]}
 done={(x["mode"],x["iv_kind"],x["orientation"]) for x in result["cells"]}
 for mode in MODES:
  for iv_name,iv in compat_stream.ivs().items():
   ks=compat_stream.keystream(mode,iv,len(canonical)//2,block)
   independent=independent_keystream(mode,iv,len(canonical)//2,block);assert ks==independent
   if mode=="fullblock_ofb":assert ks==compat_stream.fullblock_conjugated(iv,len(ks))
   for orient in ORIENT:
    key=(mode,iv_name,orient)
    if key in done:continue
    display=oriented[orient];t=time.perf_counter();sol,st,rel=core.solve(display,ks,LIMIT);elapsed=time.perf_counter()-t
    checked=validate(display,independent,sol);w=witness(display,independent);raw,counting=stats(st)
    row={"identity":IDENTITY,"cipher":"blowfish_compat","key_hex":KEY.hex(),"mode":mode,
    "iv_kind":iv_name,"iv_hex":iv.hex(),"orientation":orient,
    "keystream_sha256":hashlib.sha256(independent).hexdigest(),
    "actual_compiled_compat_block_independent_recurrence_match":True,
    "standard_fullblock_conjugation_match":True if mode=="fullblock_ofb" else None,
    "relation_summary":relation_summary(rel),"unrestricted_fixed_byte_witness":w,
    "root_unsat":st.nodes==0,"stats":raw,"bijective_mapping_certificate":counting,
    "elapsed_seconds":elapsed,"relaxed_survivor_count":len(checked),
    "fsa_survivor_count":sum(x["fsa_valid"] for x in checked),"survivors":checked}
    result["cells"].append(row);atomic(checkpoint,result)
    print(json.dumps({"cell":key,"status":raw["status"],"nodes":st.nodes,
    "accounted_bijections":counting["accounted_bijections"],"relaxed":len(checked),
    "fsa":row["fsa_survivor_count"],"witness":w is not None}),flush=True)
 assert len(result["cells"])==24
 result["summary"]={"complete_cells":sum(x["bijective_mapping_certificate"]["partition_complete"] for x in result["cells"]),
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

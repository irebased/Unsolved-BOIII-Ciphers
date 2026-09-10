#!/usr/bin/env python3
"""Portable certificate replay; --full-pairs also checks every pair digest."""
import argparse,hashlib,json,math
from pathlib import Path
from Crypto.Cipher import AES,DES,Blowfish
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];PACKAGE=HERE/"certificate_package.json";GATE=HERE/"target_gate.json";MDX=ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx";NC=ROOT/"research/rev7-20260909-codex/hex_cfb/native_compat"
PACKAGE_SHA="f3df4ac12a5ab3f722e5fa751ef266ae4336cc95617154af5630c4b88852fb65";FULL_SHA="d208d2a06218faf16e5caa16bbf13585e39ac7e82b395528e76c20140ec2a6e7";GATE_SHA="acf9fbd2918a7a62edacaf680b49f16969bb795e6df30dbdcff51565366a0abc";MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91";CIPHER_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
K={"aes128":b"Zombies"+bytes(9),"des":b"Zombies\0","blowfish":b"Zombies","blowfish_compat":b"Zombies"};BS={"aes128":16,"des":8,"blowfish":8,"blowfish_compat":8};P3={147,148,152,153,166}
EXPECTED={"core.py":"fc05740b210f6f4d8eddfc14bdb96db5666c1ba2eb4ae086e2f6667450bc4e15","controls.py":"f4b549174e293d64f1e5806001f2cd1b8f8af0468ea5a085c39997c4391bcac2","controls.json":"03e4b4b84d115dc7a4e67d5752c062d2d5660a4277eaa9e34238e9714e32cbef","run_target.py":"b3147392c6a5384b9c872f33b4127fc4f71e2f14be23858643332176a3e2aed3","audited_ragged8_core.py":"b9b10cc98fb1b74d2724837d9cfd6dc6163e452ddea2afb9df986eb5e68ff4fc","compat_c_source":"3584374a6bae4df8899e82d36255bbac0472904aed2095e3c08c57a5dd5b4cad","compat_source_check_reproduction.json":"123724d5575fa7c2be2868d8218f774f775a395eae693e2049caa703eee47295"}
PATHS={"core.py":HERE/"core.py","controls.py":HERE/"controls.py","controls.json":HERE/"controls.json","run_target.py":HERE/"run_target.py","audited_ragged8_core.py":HERE.parent/"ragged8/core.py","compat_c_source":NC/"source/blowfish-compat.c","compat_source_check_reproduction.json":NC/"source_check_reproduction.json"}
H=lambda x:hashlib.sha256(x).hexdigest()
def sha(p):return H(Path(p).read_bytes())
def orientations(v):
 p=[v[i:i+2] for i in range(0,len(v),2)];return {"forward":v,"full_hex_reverse":v[::-1],"byte_reverse":"".join(reversed(p)),"nibble_swap":"".join(x[::-1] for x in p)}
def block(c,b):
 if c=="aes128":return AES.new(K[c],AES.MODE_ECB).encrypt(b)
 if c=="des":return DES.new(K[c],DES.MODE_ECB).encrypt(b)
 if c=="blowfish":return Blowfish.new(K[c],Blowfish.MODE_ECB).encrypt(b)
 t=b[3::-1]+b[7:3:-1];x=Blowfish.new(K[c],Blowfish.MODE_ECB).encrypt(t);return x[3::-1]+x[7:3:-1]
def step(s,x):
 if s==0:return 0 if x in {9,10,13} or 32<=x<=126 else (1 if x==226 else None)
 if s==1:return 2 if x==128 else None
 return 0 if x in P3 else None
def witness(obs,w,c,a,z):
 b=BS[c];pair=obs[a::w]+obs[z::w];tail=bytes(pair[i]^block(c,pair[i-b:i])[0] for i in range(b,len(pair)));states={0,1,2};fail=None
 for off,x in enumerate(tail):
  before=sorted(states);states={v for s in states if (v:=step(s,x)) is not None}
  if not states:fail={"suffix_offset":off,"pair_plaintext_offset":b+off,"plaintext_byte":x,"states_before":before,"states_after":[]};break
 return {"from_rank":a,"to_rank":z,"pair_sha256":H(pair),"suffix_hex":tail.hex(),"suffix_sha256":H(tail),"suffix_bytes":len(tail),"end_states":sorted(states),"edge_retained":bool(states),"first_failure":fail,"two_iv_check":True}
def components(w,edges):
 adj=[set() for _ in range(w)]
 for a,z in edges:adj[a].add(z);adj[z].add(a)
 unseen=set(range(w));parts=[]
 while unseen:
  stack=[min(unseen)];part=set()
  while stack:
   x=stack.pop()
   if x in part:continue
   part.add(x);unseen.discard(x);stack.extend(adj[x]-part)
  parts.append(sorted(part))
 return parts
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--full-pairs",action="store_true");a=ap.parse_args()
 assert sha(PACKAGE)==PACKAGE_SHA and sha(GATE)==GATE_SHA and sha(MDX)==MDX_SHA
 gate=json.loads(GATE.read_text())
 for n,v in EXPECTED.items():assert gate["artifact_hashes"][n]==v and sha(PATHS[n])==v
 assert gate["artifact_hashes"]["compat_library"]=="62ba2b2d1d104aa16c8a855b8bd29af3f6ed987c0008b3a8ba20c22f12e0a319"
 text=MDX.read_text();i=text.index("`83 B57B2")+1;j=text.index("`",i);canonical="".join(text[i:j].split()).upper();assert H(canonical.encode())==CIPHER_SHA;O=orientations(canonical)
 import pack_results
 r=pack_results.unpack(json.loads(PACKAGE.read_text()));assert r["identity"]=="ASTRA" and r["evaluation_complete"] and r["gate_sha256"]==GATE_SHA
 expected={(c,o,w) for c,ws in {"aes128":(39,42),"des":(78,91),"blowfish":(78,91),"blowfish_compat":(78,91)}.items() for o in O for w in ws};assert {(x["cipher"],x["orientation"],x["width"]) for x in r["cells"]}==expected
 certrows=0;fullrows=0
 for cell in r["cells"]:
  c=cell["cipher"];w=cell["width"];obs=bytes.fromhex(O[cell["orientation"]]);edges=[tuple(x) for x in cell["retained_edges"]];assert len(edges)==len(set(edges))
  indeg=[0]*w;outdeg=[0]*w
  for x,y in edges:outdeg[x]+=1;indeg[y]+=1
  zi=[i for i,v in enumerate(indeg) if v==0];zo=[i for i,v in enumerate(outdeg) if v==0];parts=components(w,edges)
  assert indeg==cell["indegrees"] and outdeg==cell["outdegrees"] and zi==cell["zero_indegree_vertices"] and zo==cell["zero_outdegree_vertices"] and parts==cell["weak_components"]
  cert=cell["exclusion_certificate"]
  if len(zi)>=2:verts=zi[:2];keys=[(x,y) for y in verts for x in range(w) if x!=y];rule="first_two_zero_indegree_vertices"
  elif len(zo)>=2:verts=zo[:2];keys=[(x,y) for x in verts for y in range(w) if y!=x];rule="first_two_zero_outdegree_vertices"
  else:verts=parts[0];other=sorted(set(range(w))-set(verts));keys=[(x,y) for x in verts for y in other]+[(x,y) for x in other for y in verts];rule="first_weak_component_cross_edges"
  expectedrows=[witness(obs,w,c,x,y) for x,y in keys];assert all(not x["edge_retained"] for x in expectedrows)
  assert cert=={"chosen_rule":rule,"selected_vertices":verts,"required_bad_edge_count":len(keys),"bad_edge_witnesses":expectedrows};certrows+=len(keys)
  assert cell["complete_every_iv_order_exclusion"] and not cell["unresolved"] and cell["completion_weight_per_convention"]==cell["expected_weight_per_convention"]==math.factorial(w)
  if a.full_pairs:
   rows=[witness(obs,w,c,x,y) for x in range(w) for y in range(w) if x!=y];fullrows+=len(rows)
   assert len(rows)==cell["ordered_pair_count"]==w*(w-1) and H(json.dumps(rows,sort_keys=True,separators=(",",":")).encode())==cell["all_evaluated_pair_rows_sha256"]
   assert [[x["from_rank"],x["to_rank"]] for x in rows if x["edge_retained"]]==cell["retained_edges"]
 assert r["summary"]=={"cells":32,"closed_cells":32,"ordered_pairs":183168,"unresolved_cells":0}
 assert H((json.dumps(r,indent=2,sort_keys=True)+"\n").encode())==FULL_SHA
 print(json.dumps({"identity":"ASTRA","verified":True,"mode":"full_pairs" if a.full_pairs else "certificate_only","cells":32,"certificate_bad_edges":certrows,"full_pairs_replayed":fullrows,"compiled_binaries_required":False,"pretty_sha256":FULL_SHA},indent=2))
if __name__=="__main__":main()

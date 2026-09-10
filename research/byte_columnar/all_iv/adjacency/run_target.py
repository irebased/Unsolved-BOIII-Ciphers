#!/usr/bin/env python3
"""Gated 32-cell ordered-chunk adjacency target driver."""
import argparse,hashlib,json,math,os,sys
from pathlib import Path
from Crypto.Cipher import AES,DES,Blowfish
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];MDX=ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
GATE=HERE/"target_gate.json";OUTPUT=HERE/"target_results.json";CELLDIR=HERE/"target_cells";R8=HERE.parent/"ragged8/core.py"
NC=ROOT/"research/rev7-20260909-codex/hex_cfb/native_compat";IDENTITY="ASTRA"
ORIENTATIONS=("forward","full_hex_reverse","byte_reverse","nibble_swap")
SCOPE={"aes128":(16,(39,42)),"des":(8,(78,91)),"blowfish":(8,(78,91)),"blowfish_compat":(8,(78,91))}
KEYS={"aes128":b"Zombies"+bytes(9),"des":b"Zombies\0","blowfish":b"Zombies","blowfish_compat":b"Zombies"}
MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91";CIPHER_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c";P3={147,148,152,153,166}
ART={"core.py":HERE/"core.py","controls.py":HERE/"controls.py","controls.json":HERE/"controls.json","run_target.py":HERE/"run_target.py","audited_ragged8_core.py":R8,
 "compat_c_source":NC/"source/blowfish-compat.c","compat_source_check_reproduction.json":NC/"source_check_reproduction.json","compat_library":NC/"source_build/libblowfish_compat.so"}
def shab(x):return hashlib.sha256(x).hexdigest()
def sha(p):return shab(Path(p).read_bytes())
def atomic_path(path,x):
 t=path.with_name(path.name+".tmp");t.write_text(json.dumps(x,indent=2,sort_keys=True)+"\n");os.replace(t,path)
def orient(v):
 ps=[v[i:i+2] for i in range(0,len(v),2)]
 return {"forward":v,"full_hex_reverse":v[::-1],"byte_reverse":"".join(reversed(ps)),"nibble_swap":"".join(x[::-1] for x in ps)}
def extract():
 text=MDX.read_text();a=text.index("`83 B57B2")+1;b=text.index("`",a);v="".join(text[a:b].split()).upper();assert len(v)==1092 and shab(v.encode())==CIPHER_SHA;return v
def block(c,b):
 if c=="aes128":return AES.new(KEYS[c],AES.MODE_ECB).encrypt(b)
 if c=="des":return DES.new(KEYS[c],DES.MODE_ECB).encrypt(b)
 if c=="blowfish":return Blowfish.new(KEYS[c],Blowfish.MODE_ECB).encrypt(b)
 t=b[3::-1]+b[7:3:-1];x=Blowfish.new(KEYS[c],Blowfish.MODE_ECB).encrypt(t);return x[3::-1]+x[7:3:-1]
def suffix(pair,c,b):return bytes(pair[i]^block(c,pair[i-b:i])[0] for i in range(b,len(pair)))
def libsuffix(pair,c,b,iv):
 if c=="aes128":mod=AES
 elif c=="des":mod=DES
 elif c=="blowfish":mod=Blowfish
 else:
  reg=iv;out=bytearray()
  for x in pair:out.append(x^block(c,reg)[0]);reg=reg[1:]+bytes([x])
  return bytes(out)[b:]
 return mod.new(KEYS[c],mod.MODE_CFB,iv=iv,segment_size=8).decrypt(pair)[b:]
def step(s,x):
 if s==0:
  if x in {9,10,13} or 32<=x<=126:return 0
  return 1 if x==226 else None
 if s==1:return 2 if x==128 else None
 return 0 if x in P3 else None
def trace(data,b):
 states={0,1,2};fail=None
 for off,x in enumerate(data):
  before=sorted(states);states={v for s in states if (v:=step(s,x)) is not None}
  if not states:fail={"suffix_offset":off,"pair_plaintext_offset":b+off,"plaintext_byte":x,"states_before":before,"states_after":[]};break
 return sorted(states),fail
def components(w,edges):
 adj=[set() for _ in range(w)]
 for a,z in edges:adj[a].add(z);adj[z].add(a)
 unseen=set(range(w));out=[]
 while unseen:
  stack=[min(unseen)];part=set()
  while stack:
   x=stack.pop()
   if x in part:continue
   part.add(x);unseen.discard(x);stack.extend(adj[x]-part)
  out.append(sorted(part))
 return out
def require_gate():
 if not GATE.exists():raise SystemExit("missing target_gate.json")
 g=json.loads(GATE.read_text());assert g["identity"]==IDENTITY and g["target_evaluated"] is False and sha(MDX)==MDX_SHA
 assert g["expected_mdx_sha256"]==MDX_SHA and g["expected_ciphertext_sha256"]==CIPHER_SHA
 for n,p in ART.items():assert g["artifact_hashes"][n]==sha(p),(n,sha(p))
 c=json.loads((HERE/"controls.json").read_text());assert c["identity"]==IDENTITY and c["target_evaluated"] is False and c["rev7_file_read"] is False and c["assertions"]["all_passed"]
 scope=g["scope"]
 assert [(x["cipher"],x["block_size"],x["widths"],x["key_hex"]) for x in scope["cells"]]==[(c,b,list(ws),KEYS[c].hex()) for c,(b,ws) in SCOPE.items()]
 assert scope["mode"]=="CFB8" and scope["iv_scope"]=="every external block-size IV"
 assert scope["variant"]=="B" and scope["rectangular"] is True and scope["orientations"]==list(ORIENTATIONS) and scope["cell_count"]==32
 assert scope["endpoint_utf8_sequences"]==["e28093","e28094","e28098","e28099","e280a6"]
 assert scope["closure_rules"]==["at least two zero-indegree vertices","at least two zero-outdegree vertices","weakly disconnected graph"]
 return g,sha(GATE)
def selftest():
 g,gh=require_gate()
 for c,(b,_) in SCOPE.items():
  pair=bytes(range(2*((b//2)+1)));s=suffix(pair,c,b)
  assert s==libsuffix(pair,c,b,bytes(b))==libsuffix(pair,c,b,bytes(range(b)))
 print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"gate_sha256":gh,"artifact_hashes_verified":True,"mdx_hashed_ciphertext_unparsed":True,"selftest_passed":True},indent=2))
def run():
 if OUTPUT.exists() or CELLDIR.exists():raise SystemExit("refusing existing output or target_cells")
 CELLDIR.mkdir();g,gh=require_gate();canonical=extract();oriented=orient(canonical);sys.path.insert(0,str(HERE));import core
 result={"identity":IDENTITY,"target_evaluated":True,"scope":g["scope"],"gate_sha256":gh,"mdx_sha256":sha(MDX),"ciphertext_sha256":CIPHER_SHA,"cells":[],"evaluation_complete":False}
 for c,(b,widths) in SCOPE.items():
  for oname in ORIENTATIONS:
   oh=oriented[oname];obs=bytes.fromhex(oh);assert orient(oh)[oname]==canonical
   for w in widths:
    raw=core.evaluate(obs,w,c);q=546//w;assert raw["supported"] and q<=b<2*q
    witnesses=[];edges=[]
    for row in raw["ordered_pair_witnesses"]:
     a=row["from_rank"];z=row["to_rank"];A=obs[a::w];B=obs[z::w];pair=A+B;s=suffix(pair,c,b)
     assert row["pair_sha256"]==shab(pair) and row["suffix_hex"]==s.hex() and row["suffix_sha256"]==shab(s)
     assert s==libsuffix(pair,c,b,bytes(b))==libsuffix(pair,c,b,bytes(range(b)))
     states,fail=trace(s,b);assert states==row["end_states"] and fail==row["first_failure"] and bool(states)==row["edge_retained"]
     if states:edges.append((a,z))
     witnesses.append({"from_rank":a,"to_rank":z,"pair_sha256":shab(pair),"suffix_hex":s.hex(),"suffix_sha256":shab(s),"suffix_bytes":len(s),"end_states":states,"edge_retained":bool(states),"first_failure":fail,"two_iv_check":True})
    indeg=[0]*w;outdeg=[0]*w
    for a,z in edges:outdeg[a]+=1;indeg[z]+=1
    zi=[i for i,x in enumerate(indeg) if x==0];zo=[i for i,x in enumerate(outdeg) if x==0];parts=components(w,edges);reasons=[]
    if len(zi)>=2:reasons.append("at_least_two_zero_indegree_vertices")
    if len(zo)>=2:reasons.append("at_least_two_zero_outdegree_vertices")
    if len(parts)>=2:reasons.append("weakly_disconnected")
    assert reasons==raw["closure_reasons"] and indeg==raw["indegrees"] and outdeg==raw["outdegrees"] and parts==raw["weak_components"]
    assert len(witnesses)==w*(w-1) and len({(x["from_rank"],x["to_rank"]) for x in witnesses})==w*(w-1)
    all_pairs_sha=shab(json.dumps(witnesses,sort_keys=True,separators=(",",":")).encode())
    closed=bool(reasons);weight=math.factorial(w) if closed else 0;wm={(x["from_rank"],x["to_rank"]):x for x in witnesses}
    certificate=None
    if len(zi)>=2:
     vertices=zi[:2];keys=[(a,z) for z in vertices for a in range(w) if a!=z];rule="first_two_zero_indegree_vertices"
    elif len(zo)>=2:
     vertices=zo[:2];keys=[(a,z) for a in vertices for z in range(w) if z!=a];rule="first_two_zero_outdegree_vertices"
    elif len(parts)>=2:
     vertices=parts[0];other=sorted(set(range(w))-set(vertices));keys=[(a,z) for a in vertices for z in other]+[(a,z) for a in other for z in vertices];rule="first_weak_component_cross_edges"
    else:keys=[];rule=None
    if closed:
     certrows=[wm[k] for k in keys];assert len(keys)==len(set(keys)) and all(not x["edge_retained"] and x["first_failure"] for x in certrows)
     certificate={"chosen_rule":rule,"selected_vertices":vertices,"required_bad_edge_count":len(keys),"bad_edge_witnesses":certrows}
    cell={"cipher":c,"orientation":oname,"width":w,"q":q,"block_size":b,"variant":"B","rectangular":True,"iv_scope":"every external block-size IV",
      "oriented_hex_sha256":shab(oh.encode()),"observed_bytes_sha256":shab(obs),"ordered_pair_count":len(witnesses),"ordered_pair_set_unique_complete":True,
      "all_evaluated_pair_rows_serialization":"JSON sorted keys, separators comma/colon, rows ordered by from_rank then to_rank excluding equality","all_evaluated_pair_rows_sha256":all_pairs_sha,
      "retained_edges":[list(x) for x in edges],"indegrees":indeg,"outdegrees":outdeg,"zero_indegree_vertices":zi,"zero_outdegree_vertices":zo,
      "weak_components":parts,"closure_reasons":reasons,"exclusion_certificate":certificate,"hamiltonian_search_performed":False,
      "completion_weight_per_convention":weight,"expected_weight_per_convention":math.factorial(w),"complete_every_iv_order_exclusion":closed,"unresolved":not closed,
      "canonical_reconstruction_from_orientation":True}
    result["cells"].append(cell);atomic_path(CELLDIR/f"{c}-{oname}-w{w}.json",cell)
 assert len(result["cells"])==32;result["evaluation_complete"]=True
 result["summary"]={"cells":32,"closed_cells":sum(x["complete_every_iv_order_exclusion"] for x in result["cells"]),"unresolved_cells":sum(x["unresolved"] for x in result["cells"]),"ordered_pairs":sum(x["ordered_pair_count"] for x in result["cells"])}
 atomic_path(OUTPUT,result);print(json.dumps({"identity":IDENTITY,"sha256":sha(OUTPUT),"summary":result["summary"]},indent=2))
def main():
 p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True);g.add_argument("--selftest",action="store_true");g.add_argument("--run-target",action="store_true");a=p.parse_args();selftest() if a.selftest else run()
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Gated prospective 708-cell ragged-B all-IV target driver."""
import argparse,hashlib,json,math,os,sys
from pathlib import Path
from Crypto.Cipher import Blowfish,DES
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
MDX=ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
GATE=HERE/"target_gate.json";OUTPUT=HERE/"target_results.json"
IDENTITY="ASTRA";CIPHERS=("des","blowfish","blowfish_compat");WIDTHS=tuple(range(2,61))
ORIENTATIONS=("forward","full_hex_reverse","byte_reverse","nibble_swap")
MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
CIPHER_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
KEYS={"des":b"Zombies\0","blowfish":b"Zombies","blowfish_compat":b"Zombies"}
IVS=(bytes(8),bytes.fromhex("0011223344556677"));P3={147,148,152,153,166}
NC=ROOT/"research/rev7-20260909-codex/hex_cfb/native_compat"
ARTIFACTS={"core.py":HERE/"core.py","controls.py":HERE/"controls.py","controls.json":HERE/"controls.json",
 "run_target.py":HERE/"run_target.py","compat_source_check.py":NC/"source_check.py",
 "compat_source_check_reproduction.json":NC/"source_check_reproduction.json",
 "compat_c_source":NC/"source/blowfish-compat.c","compat_library":NC/"source_build/libblowfish_compat.so"}
def shab(x):return hashlib.sha256(x).hexdigest()
def sha(p):return shab(Path(p).read_bytes())
def atomic(p,x):
 t=p.with_name(p.name+".tmp");t.write_text(json.dumps(x,indent=2,sort_keys=True)+"\n");os.replace(t,p)
def extract():
 text=MDX.read_text();a=text.index("`83 B57B2")+1;b=text.index("`",a);v="".join(text[a:b].split()).upper()
 assert len(v)==1092 and shab(v.encode())==CIPHER_SHA;return v
def orient(v):
 pairs=[v[i:i+2] for i in range(0,len(v),2)]
 return {"forward":v,"full_hex_reverse":v[::-1],"byte_reverse":"".join(reversed(pairs)),
  "nibble_swap":"".join(x[::-1] for x in pairs)}
def iblock(cipher,b):
 if cipher=="des":return DES.new(KEYS[cipher],DES.MODE_ECB).encrypt(b)
 if cipher=="blowfish":return Blowfish.new(KEYS[cipher],Blowfish.MODE_ECB).encrypt(b)
 return compat_block(b)
def compat_block(b):
 t=b[3::-1]+b[7:3:-1];x=Blowfish.new(b"Zombies",Blowfish.MODE_ECB).encrypt(t);return x[3::-1]+x[7:3:-1]
def direct(p,cipher):return bytes(p[i]^iblock(cipher,p[i-8:i])[0] for i in range(8,len(p)))
def library(p,cipher,iv):
 if cipher=="des":return DES.new(KEYS[cipher],DES.MODE_CFB,iv=iv,segment_size=8).decrypt(p)[8:]
 if cipher=="blowfish":return Blowfish.new(KEYS[cipher],Blowfish.MODE_CFB,iv=iv,segment_size=8).decrypt(p)[8:]
 reg=iv;out=bytearray()
 for b in p:
  v=b^compat_block(reg)[0];out.append(v);reg=reg[1:]+bytes([b])
 return bytes(out)[8:]
def step(s,b):
 if s==0:
  if b in {9,10,13} or 32<=b<=126:return 0
  return 1 if b==226 else None
 if s==1:return 2 if b==128 else None
 return 0 if b in P3 else None
def trace(data):
 states={0,1,2};fail=None
 for off,b in enumerate(data):
  before=sorted(states);states={v for s in states if (v:=step(s,b)) is not None}
  if not states:
   fail={"suffix_offset":off,"chunk_plaintext_offset":8+off,"plaintext_byte":b,"states_before":before,"states_after":[]};break
 return sorted(states),fail
def require_gate():
 if not GATE.exists():raise SystemExit("missing target_gate.json")
 g=json.loads(GATE.read_text());assert g["identity"]==IDENTITY and g["target_evaluated"] is False
 expected={"ciphers":[{"name":"DES","id":"des","key_hex":KEYS["des"].hex()},
  {"name":"Blowfish","id":"blowfish","key_hex":KEYS["blowfish"].hex()},
  {"name":"Blowfish-compat","id":"blowfish_compat","key_hex":KEYS["blowfish_compat"].hex()}],
  "block_size":8,"mode":"CFB8","iv_scope":"every external 8-byte IV","widths":list(WIDTHS),
  "variant":"B","ragged_conventions":["first","last"],"orientations":list(ORIENTATIONS),
  "cell_count":708,"endpoint_utf8_sequences":["e28093","e28094","e28098","e28099","e280a6"]}
 assert g["scope"]==expected and g["expected_mdx_sha256"]==MDX_SHA and g["expected_ciphertext_sha256"]==CIPHER_SHA
 assert sha(MDX)==MDX_SHA
 for name,p in ARTIFACTS.items():assert g["artifact_hashes"][name]==sha(p),(name,sha(p))
 c=json.loads((HERE/"controls.json").read_text());assert c["identity"]==IDENTITY and c["target_evaluated"] is False and c["rev7_file_read"] is False and c["assertions"]["all_passed"]
 rep=json.loads((NC/"source_check_reproduction.json").read_text());assert rep["identity"]==IDENTITY and rep["actual_standard_and_compat_sources_word_reverse_relationship"]
 return g,sha(GATE)
def verify(obs,w,cipher,raw):
 rank=raw["rank"];q=len(obs)//w;p=obs[rank:q*w:w];tail=direct(p,cipher)
 assert p.hex()==raw["prefix_hex"] and shab(p)==raw["prefix_sha256"]
 assert tail.hex()==raw["suffix_hex"] and tail==library(p,cipher,IVS[0])==library(p,cipher,IVS[1])
 states,fail=trace(tail);assert states==raw["end_states"] and fail==raw["first_failure"]
 return {"rank":rank,"slice":raw["slice"],"prefix_hex":p.hex(),"prefix_sha256":shab(p),
  "prefix_bytes":len(p),"suffix_hex":tail.hex(),"suffix_sha256":shab(tail),"suffix_bytes":len(tail),
  "two_iv_library_matches_independent_recurrence":True,"end_states":states,"rejected":not states,"first_failure":fail}
def selftest():
 g,gh=require_gate();sample=bytes(range(17))
 for c in CIPHERS:
  x=direct(sample,c);assert x==library(sample,c,IVS[0])==library(sample,c,IVS[1])
 print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"gate_sha256":gh,
  "artifact_hashes_verified":True,"mdx_bytes_hashed_but_ciphertext_not_parsed":True,"selftest_passed":True},indent=2))
def run():
 if OUTPUT.exists():raise SystemExit("refusing existing "+str(OUTPUT))
 g,gh=require_gate();canonical=extract();oriented=orient(canonical);sys.path.insert(0,str(HERE));import core
 result={"identity":IDENTITY,"target_evaluated":True,"scope":g["scope"],"gate_sha256":gh,
  "mdx_sha256":sha(MDX),"ciphertext_sha256":CIPHER_SHA,"cells":[],"evaluation_complete":False}
 for cipher in CIPHERS:
  for oname in ORIENTATIONS:
   oh=oriented[oname];obs=bytes.fromhex(oh);assert orient(oh)[oname]==canonical
   for w in WIDTHS:
    raw=core.evaluate(obs,w,cipher,True);assert raw["supported"] and raw["q"]==546//w
    checks=[verify(obs,w,cipher,x) for x in raw["inspected"]];bad=[x for x in checks if x["rejected"]]
    assert len(checks)==raw["ranks_examined"] and bool(bad)==raw["complete_every_iv_every_order_exclusion"]
    if bad:assert len(bad)==1 and bad[0]["rank"]==raw["rejected_rank"]
    weight=math.factorial(w) if bad else 0
    cell={"cipher":cipher,"orientation":oname,"oriented_hex_sha256":shab(oh.encode()),
     "observed_bytes_sha256":shab(obs),"width":w,"q":raw["q"],"r":raw["r"],"variant":"B",
     "ragged_conventions":["first","last"],"conventions_alias":raw["conventions_alias"],
     "iv_scope":"every external 8-byte IV","ranks_examined":len(checks),"examined_chunks":checks,
     "rejected_rank":raw["rejected_rank"],"completion_weight_per_convention":weight,
     "expected_weight_per_convention":math.factorial(w),"weights_across_conventions_not_added":True,
     "complete_every_iv_every_order_exclusion":bool(bad),"unresolved":not bad,
     "canonical_reconstruction_from_orientation":True}
    result["cells"].append(cell);atomic(OUTPUT,result)
 assert len(result["cells"])==708;result["evaluation_complete"]=True
 result["summary"]={"cells":708,"closed_cells":sum(x["complete_every_iv_every_order_exclusion"] for x in result["cells"]),
  "unresolved_cells":sum(x["unresolved"] for x in result["cells"]),"ranks_examined":sum(x["ranks_examined"] for x in result["cells"]),
  "all_cells_closed":all(x["complete_every_iv_every_order_exclusion"] for x in result["cells"])}
 atomic(OUTPUT,result);print(json.dumps({"identity":IDENTITY,"output":str(OUTPUT),"sha256":sha(OUTPUT),"summary":result["summary"]},indent=2))
def main():
 p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True);g.add_argument("--selftest",action="store_true");g.add_argument("--run-target",action="store_true")
 a=p.parse_args();selftest() if a.selftest else run()
if __name__=="__main__":main()

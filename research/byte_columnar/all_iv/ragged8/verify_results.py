#!/usr/bin/env python3
"""Portable read-only verifier for the frozen compact ragged8 result."""
import hashlib,json,math
from pathlib import Path
from Crypto.Cipher import DES,Blowfish
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
COMPACT=HERE/"target_results_compact.json";GATE=HERE/"target_gate.json";CONTROLS=HERE/"controls.json"
MDX=ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
NC=ROOT/"research/rev7-20260909-codex/hex_cfb/native_compat"
IDENTITY="ASTRA";COMPACT_SHA="f7b53f894c0fe9748d7fed6bbd861ebdaa7affde39c5a1ccf30ff1c7db70086e"
FULL_SHA="a985c8008c285763e5001470957e1d9788bac3df21a95260f274ad6c35ab0a83"
GATE_SHA="3abaf463714cd066546effb01a50d6653c2794bb11b9fd9e316218d07ad82fca"
MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
CIPHER_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
KEYS={"des":b"Zombies\0","blowfish":b"Zombies","blowfish_compat":b"Zombies"}
ORIENTATIONS=("forward","full_hex_reverse","byte_reverse","nibble_swap");P3={147,148,152,153,166}
SOURCE_EXPECTED={"core.py":"b9b10cc98fb1b74d2724837d9cfd6dc6163e452ddea2afb9df986eb5e68ff4fc",
 "controls.py":"d3d198a2cceed5110f9885317ae03b0dae3098c2a8b4359fcf04d11359f22c9c",
 "controls.json":"526ebeb27636c559d972f5e4bf29805f8962f8d54e70385da7956d396a644afa",
 "run_target.py":"6e1ec59968e2f14e19dd4ebbefc468ab3efe59e4df27e2c763f0213278a178bd",
 "compat_source_check.py":"3945fbebcc7ae8c8bd8df0b450590e149e7cbd86443bd9d92ddbae90ab91e69d",
 "compat_source_check_reproduction.json":"123724d5575fa7c2be2868d8218f774f775a395eae693e2049caa703eee47295",
 "compat_c_source":"3584374a6bae4df8899e82d36255bbac0472904aed2095e3c08c57a5dd5b4cad"}
PATHS={"core.py":HERE/"core.py","controls.py":HERE/"controls.py","controls.json":CONTROLS,
 "run_target.py":HERE/"run_target.py","compat_source_check.py":NC/"source_check.py",
 "compat_source_check_reproduction.json":NC/"source_check_reproduction.json",
 "compat_c_source":NC/"source/blowfish-compat.c"}
def sha_bytes(x):return hashlib.sha256(x).hexdigest()
def sha(p):return sha_bytes(Path(p).read_bytes())
def orientations(v):
 ps=[v[i:i+2] for i in range(0,len(v),2)]
 return {"forward":v,"full_hex_reverse":v[::-1],"byte_reverse":"".join(reversed(ps)),
  "nibble_swap":"".join(x[::-1] for x in ps)}
def block(c,b):
 if c=="des":return DES.new(KEYS[c],DES.MODE_ECB).encrypt(b)
 if c=="blowfish":return Blowfish.new(KEYS[c],Blowfish.MODE_ECB).encrypt(b)
 t=b[3::-1]+b[7:3:-1];x=Blowfish.new(KEYS[c],Blowfish.MODE_ECB).encrypt(t);return x[3::-1]+x[7:3:-1]
def suffix(p,c):return bytes(p[i]^block(c,p[i-8:i])[0] for i in range(8,len(p)))
def cfb_suffix(p,c,iv):
 if c=="des":return DES.new(KEYS[c],DES.MODE_CFB,iv=iv,segment_size=8).decrypt(p)[8:]
 if c=="blowfish":return Blowfish.new(KEYS[c],Blowfish.MODE_CFB,iv=iv,segment_size=8).decrypt(p)[8:]
 reg=iv;out=bytearray()
 for x in p:
  out.append(x^block(c,reg)[0]);reg=reg[1:]+bytes([x])
 return bytes(out)[8:]
def step(s,b):
 if s==0:
  if b in {9,10,13} or 32<=b<=126:return 0
  return 1 if b==226 else None
 if s==1:return 2 if b==128 else None
 return 0 if b in P3 else None
def trace(data):
 states={0,1,2};failure=None
 for off,b in enumerate(data):
  before=sorted(states);states={v for s in states if (v:=step(s,b)) is not None}
  if not states:
   failure={"plaintext_byte":b,"states_after":[],"states_before":before,
    "suffix_offset":off,"chunk_plaintext_offset":8+off};break
 return sorted(states),failure
def main():
 assert sha(COMPACT)==COMPACT_SHA and sha(GATE)==GATE_SHA and sha(MDX)==MDX_SHA
 gate=json.loads(GATE.read_text());controls=json.loads(CONTROLS.read_text())
 assert gate["identity"]==controls["identity"]==IDENTITY and gate["target_evaluated"] is False and controls["target_evaluated"] is False
 assert controls["assertions"]["all_passed"] and gate["expected_ciphertext_sha256"]==CIPHER_SHA
 for name,want in SOURCE_EXPECTED.items():
  assert gate["artifact_hashes"][name]==want and sha(PATHS[name])==want,(name,sha(PATHS[name]))
 # The compiled compat_library provenance hash remains in the gate, but this portable verifier does not load or require it.
 assert gate["artifact_hashes"]["compat_library"]=="62ba2b2d1d104aa16c8a855b8bd29af3f6ed987c0008b3a8ba20c22f12e0a319"
 text=MDX.read_text();a=text.index("`83 B57B2")+1;b=text.index("`",a);canonical="".join(text[a:b].split()).upper()
 assert len(canonical)==1092 and sha_bytes(canonical.encode())==CIPHER_SHA;oriented=orientations(canonical)
 result=json.loads(COMPACT.read_text())
 assert result["identity"]==IDENTITY and result["evaluation_complete"] and result["gate_sha256"]==GATE_SHA
 assert result["scope"]==gate["scope"] and result["ciphertext_sha256"]==CIPHER_SHA
 expected={(c,o,w) for c in KEYS for o in ORIENTATIONS for w in range(2,61)}
 assert {(x["cipher"],x["orientation"],x["width"]) for x in result["cells"]}==expected and len(result["cells"])==708
 checked=0
 for cell in result["cells"]:
  c=cell["cipher"];w=cell["width"];oh=oriented[cell["orientation"]];obs=bytes.fromhex(oh)
  assert orientations(oh)[cell["orientation"]]==canonical
  assert cell["oriented_hex_sha256"]==sha_bytes(oh.encode()) and cell["observed_bytes_sha256"]==sha_bytes(obs)
  assert cell["q"]==546//w and cell["r"]==546%w and cell["conventions_alias"]==(546%w==0)
  assert cell["ranks_examined"]==len(cell["examined_chunks"]) and cell["weights_across_conventions_not_added"]
  rejected=[]
  for row in cell["examined_chunks"]:
   rank=row["rank"];q=546//w;p=obs[rank:q*w:w]
   assert row["slice"]=={"start":rank,"stop":q*w,"stride":w}
   assert row["prefix_hex"]==p.hex() and row["prefix_sha256"]==sha_bytes(p) and row["prefix_bytes"]==q
   tail=suffix(p,c);assert row["suffix_hex"]==tail.hex() and row["suffix_sha256"]==sha_bytes(tail)
   assert row["suffix_bytes"]==len(tail)
   assert tail==cfb_suffix(p,c,bytes(8))==cfb_suffix(p,c,bytes.fromhex("0011223344556677"))
   states,failure=trace(tail);assert row["end_states"]==states and row["first_failure"]==failure
   assert row["rejected"]==(not states)
   if row["rejected"]:rejected.append(rank)
   checked+=1
  assert len(rejected)==1 and rejected[0]==cell["rejected_rank"] and cell["examined_chunks"][-1]["rejected"]
  assert cell["complete_every_iv_every_order_exclusion"] and not cell["unresolved"]
  assert cell["completion_weight_per_convention"]==cell["expected_weight_per_convention"]==math.factorial(w)
 assert checked==767 and result["summary"]=={"all_cells_closed":True,"cells":708,"closed_cells":708,"ranks_examined":767,"unresolved_cells":0}
 pretty=(json.dumps(result,indent=2,sort_keys=True)+"\n").encode()
 assert sha_bytes(pretty)==FULL_SHA
 print(json.dumps({"identity":IDENTITY,"verified":True,"compact_sha256":COMPACT_SHA,
  "reconstructed_pretty_sha256":sha_bytes(pretty),"cells":708,"prefixes":checked,
  "compiled_binaries_required":False},indent=2))
if __name__=="__main__":main()

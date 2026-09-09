#!/usr/bin/env python3
"""Synthetic/source controls for Blowfish-compat OFB CSP; no Rev7 access."""
import hashlib,importlib.util,itertools,json,math,random,sys,time
from dataclasses import asdict
from pathlib import Path
from Crypto import __version__ as crypto_version
HERE=Path(__file__).resolve().parent;RESEARCH=HERE.parent
sys.path[:0]=[str(HERE),str(RESEARCH/"stream_csp")]
import compat_stream as compat
import core
OFB_RUN=RESEARCH/"sources"/"ofb8"/"run.py"
spec=importlib.util.spec_from_file_location("ofb8_source_run",OFB_RUN)
ofbmod=importlib.util.module_from_spec(spec);spec.loader.exec_module(ofbmod)
OUT=HERE/"controls.json";LENGTHS=(1,7,8,9,15,16,17,546)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
class ECB:
 def __init__(self,block):self.block=block
 def encrypt(self,data):
  assert len(data)%8==0
  return b"".join(self.block(data[i:i+8]) for i in range(0,len(data),8))
class Module:
 block_size=8;MODE_ECB=1
 def __init__(self,block):self.block=block
 def new(self,key,mode):
  assert key==compat.KEY and mode==self.MODE_ECB
  return ECB(self.block)
def direct(display,ks,mapping):
 ct=core.decode(display,mapping);plain=bytes(x^y for x,y in zip(ct,ks))
 return plain,all(x in core.RELAXED for x in plain),core.valid_fsa(plain)
def naive(display,ks,seed):
 unknown=sorted(set(range(16))-set(seed));unused=sorted(set(range(16))-set(seed.values()))
 assert len(unknown)==len(unused)==4
 out={}
 for vals in itertools.permutations(unused):
  m=[-1]*16
  for k,v in seed.items():m[k]=v
  for k,v in zip(unknown,vals):m[k]=v
  p,r,f=direct(display,ks,m)
  if r:out[tuple(m)]=(p,f)
 return out
def packed(sol):return {tuple(x["mapping"]):(x["plaintext"],x["fsa_valid"]) for x in sol}
def plant():
 u=b"BF compat CSP en"+bytes.fromhex("e28093")+b" em"+bytes.fromhex("e28094")+b" left"+bytes.fromhex("e28098")+b" right"+bytes.fromhex("e28099")+b" ASCII 019+/=\r\n"
 return u*(546//len(u))+b"A"*(546%len(u))
def main():
 block=compat.load_block();module=Module(block)
 vectors=[]
 for iv_name,iv in compat.ivs().items():
  for n in LENGTHS:
   data=bytes(i%256 for i in range(n))
   k8=compat.ofb8_keystream(block,iv,n);expected=bytes(x^y for x,y in zip(data,k8))
   actual=ofbmod.actual_ofb8(data,module,compat.KEY,iv,False)
   assert actual==expected and ofbmod.actual_ofb8(actual,module,compat.KEY,iv,True)==data
   rec=compat.fullblock_recurrence(block,iv,n);conj=compat.fullblock_conjugated(iv,n)
   assert rec==conj
   cipher=bytes(x^y for x,y in zip(data,rec))
   assert bytes(x^y for x,y in zip(cipher,rec))==data
   vectors.append({"iv_kind":iv_name,"length":n,
    "ofb8_ciphertext_sha256":hashlib.sha256(actual).hexdigest(),
    "ofb8_actual_historical_c_mode_matches":True,"ofb8_roundtrip":True,
    "fullblock_keystream_sha256":hashlib.sha256(rec).hexdigest(),
    "fullblock_actual_compat_c_recurrence_matches_standard_conjugation":True,
    "fullblock_roundtrip":True,
    "fullblock_generation":"ceil(n/8)*8 standard bytes, word-reverse each complete 8-byte block, then clip"})

 rng=random.Random(20260910);mapping=list(range(16));rng.shuffle(mapping);plain=plant()
 full=[];seeded=[]
 for mode in ("ofb8","fullblock_ofb"):
  iv=compat.ivs()["sha1_prefix"];ks=compat.keystream(mode,iv,len(plain),block)
  display=core.display_encode(bytes(x^y for x,y in zip(plain,ks)),mapping)
  assert set(display)==set(core.HEX) and core.valid_fsa(plain)
  t=time.perf_counter();sol,stats,_=core.solve(display,ks,1_000_000)
  assert not stats.capped and stats.rejected_weight+stats.terminal_weight==math.factorial(16)
  assert any(tuple(x["mapping"])==tuple(mapping) and x["plaintext"]==plain and x["fsa_valid"] for x in sol)
  full.append({"mode":mode,"iv_kind":"sha1_prefix","nodes":stats.nodes,
   "seconds":time.perf_counter()-t,"certificate":math.factorial(16),
   "relaxed_survivors":stats.relaxed_complete,"fsa_survivors":stats.fsa_complete,
   "plant_recovered":True,"all_16_display_symbols":True})
  sample=(b"BFcompat seeded ASCII 019+/=\r\n"*4)
  sks=compat.keystream(mode,compat.ivs()["ascii_zero"],len(sample),block)
  sd=core.display_encode(bytes(x^y for x,y in zip(sample,sks)),mapping)
  seed={i:v for i,v in enumerate(mapping) if i<12}
  expected=naive(sd,sks,seed);ss,st,_=core.solve(sd,sks,1_000_000,seed)
  assert packed(ss)==expected and not st.capped
  assert st.rejected_weight+st.terminal_weight==24 and tuple(mapping) in expected
  seeded.append({"mode":mode,"naive_distinct_mappings":24,"exact_sets_match":True,
   "certificate":24,"relaxed_survivors":len(expected),
   "fsa_survivors":sum(x[1] for x in expected.values()),"plant_recovered":True,"nodes":st.nodes})

 result={"identity":"ASTRA","target_evaluated":False,
 "scope":{"cipher":"blowfish_compat","key_hex":compat.KEY.hex(),"modes":["ofb8","fullblock_ofb"],
 "iv_kinds":list(compat.ivs()),"lengths":list(LENGTHS),"future_target_cells":24,
 "csp_node_limit":1000000,"relaxed_bytes":sorted(core.RELAXED)},
 "stream_vectors":vectors,"full16_mixed_utf8_plants":full,
 "seeded_four_unknown_naive_controls":seeded,
 "assertions":{"all_passed":True,"vector_rows":len(vectors),
 "actual_historical_c_ofb8_used":True,"fullblock_boundary_lengths_include_7_8_9_15_16_17":True},
 "runtime":{"python":sys.version,"pycryptodome":crypto_version},
 "source_hashes":{"compat_stream.py":sha(HERE/"compat_stream.py"),"controls.py":sha(Path(__file__)),
 "stream_csp_core.py":sha(RESEARCH/"stream_csp"/"core.py"),
 "source_check.py":sha(RESEARCH/"hex_cfb"/"native_compat"/"source_check.py"),
 "source_check_reproduction.json":sha(RESEARCH/"hex_cfb"/"native_compat"/"source_check_reproduction.json"),
 "libblowfish_compat.so":sha(RESEARCH/"hex_cfb"/"native_compat"/"source_build"/"libblowfish_compat.so"),
 "ofb8_run.py":sha(OFB_RUN),"libofb8.so":sha(RESEARCH/"sources"/"ofb8"/"build"/"libofb8.so")}}
 if OUT.exists():raise SystemExit("refusing existing controls.json")
 OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(json.dumps({"identity":"ASTRA","target_evaluated":False,"controls_sha256":sha(OUT),
 "vector_rows":len(vectors),"full":full,"seeded":seeded},indent=2))
if __name__=="__main__":main()

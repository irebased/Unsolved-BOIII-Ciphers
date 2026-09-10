#!/usr/bin/env python3
from __future__ import annotations
import base64,ctypes,hashlib,itertools,json,math,platform,random,re,subprocess,sys,time
from pathlib import Path
from Crypto.Cipher import ARC2,Blowfish
HERE=Path(__file__).resolve().parent
HEX_CFB=HERE.parent
REPO=HERE.parents[3]
sys.path.insert(0,str(HEX_CFB))
import prototype as core
IDENTITY="ASTRA"; KEY=b"Zombies"; BIN=HERE/"native_siblings"
FIELDS=("nodes","rejected_plaintext","complete","maximum_depth","aborted_at_node_limit","rejected_completion_weight","terminal_completion_weight","rejected_unterminated_endpoint")
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class SourceECB:
 def __init__(self,name,key=KEY):
  assert name in ("rc2","loki97");self.name=name;self.block=8 if name=="rc2" else 16
  self.lib=ctypes.CDLL(str(HERE/"source_build"/("librc2.so" if name=="rc2" else "libloki97.so")))
  pre="rc2" if name=="rc2" else "loki97"
  gs=getattr(self.lib,pre+"_LTX__mcrypt_get_size");gb=getattr(self.lib,pre+"_LTX__mcrypt_get_block_size")
  self.sk=getattr(self.lib,pre+"_LTX__mcrypt_set_key");self.en=getattr(self.lib,pre+"_LTX__mcrypt_encrypt")
  gs.restype=gb.restype=ctypes.c_int;self.size=gs();assert gb()==self.block
  self.sk.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint];self.sk.restype=ctypes.c_int
  self.en.argtypes=[ctypes.c_void_p,ctypes.c_void_p];self.en.restype=None
  self.ctx=ctypes.create_string_buffer(self.size)
  if name=="rc2":memory=key;declared=len(key)
  else:
   declared=next(x for x in (16,24,32) if len(key)<=x);memory=key+b"\0"*(32-len(key))
  self.key_memory=ctypes.create_string_buffer(memory,len(memory));self.declared_key_length=declared
  assert self.sk(self.ctx,self.key_memory,declared)==0
 def encrypt(self,block):
  assert len(block)==self.block;b=ctypes.create_string_buffer(block,len(block));self.en(self.ctx,b);return b.raw
def cfb8(data,ecb,iv,decrypt):
 reg=iv;out=bytearray()
 for value in data:
  transformed=value^ecb.encrypt(reg)[0];ct=value if decrypt else transformed
  out.append(transformed);reg=reg[1:]+bytes([ct])
 return bytes(out)
def accepted(data):
 state=0
 for value in data:
  nxt=core.historical_utf8_transition(state,0,value)
  if nxt is None:return False
  state=nxt
 return state==0
def native(name,cap,display,seed=None):
 a=[str(BIN),name,str(cap),display,"-" if seed is None else ",".join(f"{k}:{v}" for k,v in sorted(seed.items()))]
 return json.loads(subprocess.check_output(a,text=True))
def compare(name,cap,display,seed=None):
 e=SourceECB(name);iv=b"0"*e.block
 ps,pst=core.backtrack(display,e,iv,core.historical_utf8_transition,node_limit=cap,seed_mapping=seed)
 py_stats={k:getattr(pst,k) for k in FIELDS};py_sol=[{"mapping":list(x["mapping"]),"plaintext_hex":x["plaintext"].hex()} for x in ps]
 n=native(name,cap,display,seed);ns={k:n[k] for k in FIELDS}
 assert ns==py_stats and n["solutions"]==py_sol
 expected=math.factorial(16-len(seed or {}));cert=n["certificate_weight"]
 assert n["expected_completion_weight"]==expected and cert==ns["rejected_completion_weight"]+ns["terminal_completion_weight"]
 if not ns["aborted_at_node_limit"]:assert cert==expected
 return {"node_limit":cap,"stats":ns,"solutions":py_sol,"solution_count":len(py_sol),"expected_completion_weight":expected,"certificate_weight":cert,"certificate_complete":cert==expected,"native_seconds":n["elapsed_seconds"]}
def naive(name,display,seed):
 unknown=sorted(set(range(16))-set(seed));remaining=sorted(set(range(16))-set(seed.values()));out=[];e=SourceECB(name);iv=b"0"*e.block
 for perm in itertools.permutations(remaining):
  m=[None]*16
  for k,v in seed.items():m[k]=v
  for k,v in zip(unknown,perm):m[k]=v
  ct=bytes((m[core.HEX.index(display[i])]<<4)|m[core.HEX.index(display[i+1])] for i in range(0,len(display),2));pt=cfb8(ct,e,iv,True)
  if accepted(pt):out.append({"mapping":m,"plaintext_hex":pt.hex()})
 return out
def normalize(s):return re.sub(r"\s+"," ",s.strip(" \t\r\n\0"))
def rev5_control():
 records=json.loads((REPO/"lavender/src/data/ciphers/revelations.json").read_text());rec=next(x for x in records if x["id"]=="rev5")
 outer=base64.b64decode(re.sub(r"\s+","",rec["ciphertext"]));s1=cfb8(outer,SourceECB("rc2"),b"0"*8,True)
 assert s1.endswith(b"\n") and all(x in b"0123456789abcdef\n" for x in s1)
 stripped=s1.rstrip(b"\n");assert len(stripped)%2==0
 b2=bytes.fromhex(stripped[::-1].decode("ascii"))
 class BF:
  block=8
  def __init__(self):self.c=Blowfish.new(KEY,Blowfish.MODE_ECB)
  def encrypt(self,x):return self.c.encrypt(x)
 s4=cfb8(b2,BF(),b"0"*8,True);b3=base64.b64decode(s4);final=cfb8(b3,SourceECB("loki97"),b"0"*16,True)
 recovered=normalize(final.decode("utf-8"));expected=normalize(rec["plaintext"])
 diffs=[i for i,(a,b) in enumerate(zip(recovered,expected)) if a!=b]
 assert len(recovered)==len(expected) and diffs==[384] and recovered[384]=="’" and expected[384]=="'"
 canonical=recovered.replace("’","'");assert canonical==expected
 return {"input_source":"lavender/src/data/ciphers/revelations.json rev5","outer_bytes":len(outer),"rc2_output_bytes":len(s1),"rc2_trailing_lf_bytes":len(s1)-len(stripped),"reverse_operation":"strip trailing LF bytes, reverse all hex characters, then bytes.fromhex","blowfish_input_bytes":len(b2),"blowfish_output_bytes":len(s4),"loki97_input_bytes":len(b3),"final_bytes":len(final),"hashes":{"outer":hashlib.sha256(outer).hexdigest(),"rc2_output":hashlib.sha256(s1).hexdigest(),"blowfish_input":hashlib.sha256(b2).hexdigest(),"blowfish_output":hashlib.sha256(s4).hexdigest(),"loki97_input":hashlib.sha256(b3).hexdigest(),"final":hashlib.sha256(final).hexdigest()},"strict_utf8":True,"normalized_lengths":{"recovered":len(recovered),"recorded":len(expected)},"only_record_difference":{"index":384,"recovered":"U+2019","recorded":"U+0027"},"full_match_after_explicit_apostrophe_normalization":canonical==expected,"complete_chain_reencryptions":{"loki97":cfb8(final,SourceECB("loki97"),b"0"*16,False)==b3,"blowfish":cfb8(s4,BF(),b"0"*8,False)==b2,"rc2":cfb8(s1,SourceECB("rc2"),b"0"*8,False)==outer}}
def main():
 assert sha(HERE/"source/rc2.c")=="37c9398507cea1685255da9550f5a3a55b529b66e1bbc9a35e1996fecae7dc19"
 assert sha(HERE/"source/loki97.c")=="4e18d184ec55776edab065cee35ac44a9269b4160d7d35ad4ea277da55ae3308"
 kats=[]
 for name,maxkey,want in (("rc2",128,"becbe4c8e6237a14"),("loki97",32,"8cb28c958024bae27a94c698f96f12a9")):
  key=bytes((j*2+10)%256 for j in range(maxkey));plain=bytes(range(8 if name=="rc2" else 16));got=SourceECB(name,key).encrypt(plain).hex();assert got==want
  kats.append({"cipher":name,"key_length":maxkey,"key_formula":"(j*2+10)%256","plaintext_hex":plain.hex(),"ciphertext_hex":got,"matches_source_embedded_KAT":True})
 rc2_rows=[]
 for key in (b"abcde",KEY,bytes(range(16)),bytes(range(128))):
  block=bytes(range(8));actual=SourceECB("rc2",key).encrypt(block);other=ARC2.new(key,ARC2.MODE_ECB,effective_keylen=1024).encrypt(block);assert actual==other
  rc2_rows.append({"key_hex":key.hex(),"key_length":len(key),"ciphertext_hex":actual.hex(),"pycryptodome_effective_keylen":1024,"match":True})
 allbytes=bytes(range(256))+b" source-backed sibling CFB8"
 cfb=[]
 for name in ("rc2","loki97"):
  e=SourceECB(name);iv=b"0"*e.block;ct=cfb8(allbytes,e,iv,False);assert cfb8(ct,SourceECB(name),iv,True)==allbytes
  nct=bytes.fromhex(subprocess.check_output([str(BIN),"--cfb-encrypt",name,allbytes.hex()],text=True).strip());assert nct==ct
  npt=bytes.fromhex(subprocess.check_output([str(BIN),"--cfb-decrypt",name,ct.hex()],text=True).strip());assert npt==allbytes
  cfb.append({"cipher":name,"block_size":e.block,"key_hex":KEY.hex(),"declared_key_length":e.declared_key_length,"iv_hex":iv.hex(),"plaintext_sha256":hashlib.sha256(allbytes).hexdigest(),"ciphertext_hex":ct.hex(),"ciphertext_sha256":hashlib.sha256(ct).hexdigest(),"native_matches_separate_python_recurrence":True,"roundtrip":True})
 rng=random.Random(20260910);mapping=list(range(16));rng.shuffle(mapping);mixed=("ASCII\tline\r\nen–em—left‘right’;".encode("utf-8"))*3
 seeded=[];capped=[]
 for name in ("rc2","loki97"):
  e=SourceECB(name);display=core.display_encode(cfb8(mixed,e,b"0"*e.block,False),mapping);assert len(set(display))==16
  unknown=sorted(set(core.HEX.index(x) for x in display))[-4:];seed={i:v for i,v in enumerate(mapping) if i not in unknown}
  row=compare(name,100000,display,seed);nv=naive(name,display,seed);assert row["certificate_complete"] and row["expected_completion_weight"]==24 and row["solutions"]==nv
  assert any(x["mapping"]==mapping and x["plaintext_hex"]==mixed.hex() for x in nv);row.update({"cipher":name,"unknown_symbols":unknown,"naive_permutations":24,"naive_survivors_equal":True,"plant_recovered":True});seeded.append(row)
  full=(mixed*((546//len(mixed))+1))[:546];fd=core.display_encode(cfb8(full,e,b"0"*e.block,False),mapping)
  for cap in (250000,1000000):
   t=time.perf_counter();z=compare(name,cap,fd);z.update({"cipher":name,"python_plus_native_wall_seconds":time.perf_counter()-t});assert z["stats"]["aborted_at_node_limit"] and not z["certificate_complete"];capped.append(z)
 chain=rev5_control()
 source_hashes={str(p.relative_to(HERE)):sha(p) for p in sorted(list((HERE/"source").glob("*"))+list((HERE/"source_build").glob("*")))}
 result={"identity":IDENTITY,"target_evaluated":False,"rev7_file_read":False,"scope":"source-backed RC2 and Loki97 primitive, CFB8, DFS, and solved Rev5 controls only","source":{"repository":"https://github.com/Distrotech/libmcrypt","commit":"3bd338e2f808e985f5b229a7642d48c26615993f","files":{"rc2.c":"modules/algorithms/rc2.c","rc2.h":"modules/algorithms/rc2.h (empty file)","loki97.c":"modules/algorithms/loki97.c"},"source_hashes":source_hashes,"compiled_sources_unmodified":True},"key_conventions":{"rc2":{"input_key_hex":KEY.hex(),"input_length":7,"source_metadata_supported_count":0,"source_metadata_max_bytes":128,"schedule":"raw seven bytes"},"loki97":{"input_key_hex":KEY.hex(),"input_length":7,"source_metadata_supported_bytes":[16,24,32],"selected_declared_length":16,"schedule_memory":"Zombies followed by 25 NUL bytes because pinned set_key reads eight words; declared length argument is 16 and unused by the algorithm"}},"source_embedded_kats":kats,"rc2_pycryptodome_crosscheck":rc2_rows,"full_byte_cfb8":cfb,"seeded_four_unknown":seeded,"full16_capped_exact_prefix":capped,"rev5_full_chain":chain,"build":{"commands":["clang -shared -fPIC -O2 -Isource_build -Isource source/rc2.c -o source_build/librc2.so","clang -shared -fPIC -O2 -Isource_build -Isource source/loki97.c -o source_build/libloki97.so","clang -O2 -Isource_build -Isource -c source/rc2.c -o source_build/rc2.o","clang -O2 -Isource_build -Isource -c source/loki97.c -o source_build/loki97.o","clang++ -std=c++17 -O3 native_siblings.cpp source_build/rc2.o source_build/loki97.o -o native_siblings"],"compiler":subprocess.check_output(["clang","--version"],text=True).splitlines()[0],"python":sys.version,"platform":platform.platform()},"artifact_hashes":{"native_siblings.cpp":sha(HERE/"native_siblings.cpp"),"native_siblings":sha(BIN),"prototype.py":sha(HEX_CFB/"prototype.py"),"controls.py":sha(Path(__file__))},"assertions":{"all_passed":True,"source_kats":True,"rc2_matches_independent_pycryptodome":True,"native_cfb8_matches_python_recurrence":True,"native_stats_weights_maps_plaintexts_equal_python":True,"seeded_survivors_equal_naive_24":True,"caps_are_incomplete_prefixes_only":True,"rev5_chain_full_except_documented_record_glyph":True}}
 out=HERE/"controls.json"
 if out.exists():raise SystemExit("refusing existing controls.json")
 out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n");print(json.dumps({"identity":IDENTITY,"controls_sha256":sha(out),"rev5":chain,"capped":[{"cipher":x["cipher"],"cap":x["node_limit"],"stats":x["stats"],"wall":x["python_plus_native_wall_seconds"]} for x in capped]},indent=2))
if __name__=="__main__":main()

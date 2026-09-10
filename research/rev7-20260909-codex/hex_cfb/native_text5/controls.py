#!/usr/bin/env python3
from __future__ import annotations
import ctypes,hashlib,itertools,json,math,platform,random,subprocess,sys,time
from pathlib import Path
from Crypto.Cipher import AES,Blowfish,DES
HERE=Path(__file__).resolve().parent
HEX_CFB=HERE.parent
sys.path.insert(0,str(HERE));sys.path.insert(0,str(HEX_CFB))
import endpoint5
import prototype as core
IDENTITY="ASTRA";KEY=b"Zombies";BIN=HERE/"native_text5"
CIPHERS=("aes128","blowfish","des","blowfish_compat","rc2","loki97")
FIELDS=("nodes","rejected_plaintext","complete","maximum_depth","aborted_at_node_limit","rejected_completion_weight","terminal_completion_weight","rejected_unterminated_endpoint")
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def word_reverse(b):return b[3::-1]+b[7:3:-1]
class ECB:
 def __init__(self,name):
  self.name=name
  if name=="aes128":self.block=16;self.c=AES.new(KEY+b"\0"*9,AES.MODE_ECB)
  elif name in ("blowfish","blowfish_compat"):self.block=8;self.c=Blowfish.new(KEY,Blowfish.MODE_ECB)
  elif name=="des":self.block=8;self.c=DES.new(KEY+b"\0",DES.MODE_ECB)
  else:
   self.block=8 if name=="rc2" else 16;fn="librc2.so" if name=="rc2" else "libloki97.so";pre="rc2" if name=="rc2" else "loki97"
   self.lib=ctypes.CDLL(str(HERE/"source_build"/fn));gs=getattr(self.lib,pre+"_LTX__mcrypt_get_size");gs.restype=ctypes.c_int
   self.sk=getattr(self.lib,pre+"_LTX__mcrypt_set_key");self.en=getattr(self.lib,pre+"_LTX__mcrypt_encrypt")
   self.sk.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint];self.en.argtypes=[ctypes.c_void_p,ctypes.c_void_p];self.ctx=ctypes.create_string_buffer(gs())
   memory=KEY if name=="rc2" else KEY+b"\0"*25;declared=7 if name=="rc2" else 16;self.kbuf=ctypes.create_string_buffer(memory,len(memory));assert self.sk(self.ctx,self.kbuf,declared)==0
 def encrypt(self,b):
  if self.name=="blowfish_compat":return word_reverse(self.c.encrypt(word_reverse(b)))
  if self.name in ("aes128","blowfish","des"):return self.c.encrypt(b)
  x=ctypes.create_string_buffer(b,len(b));self.en(self.ctx,x);return x.raw
def cfb8(data,e,decrypt):
 reg=b"0"*e.block;out=bytearray()
 for v in data:
  y=v^e.encrypt(reg)[0];ct=v if decrypt else y;out.append(y);reg=reg[1:]+bytes([ct])
 return bytes(out)
def native(name,cap,display,seed=None):
 a=[str(BIN),name,str(cap),display,"-" if seed is None else ",".join(f"{k}:{v}" for k,v in sorted(seed.items()))]
 return json.loads(subprocess.check_output(a,text=True))
def compare(name,cap,display,seed=None):
 e=ECB(name);ps,pst=core.backtrack(display,e,b"0"*e.block,endpoint5.transition,node_limit=cap,seed_mapping=seed)
 py={k:getattr(pst,k) for k in FIELDS};sol=[{"mapping":list(x["mapping"]),"plaintext_hex":x["plaintext"].hex()} for x in ps];n=native(name,cap,display,seed);ns={k:n[k] for k in FIELDS}
 assert py==ns and sol==n["solutions"] and n["certificate_weight"]==ns["rejected_completion_weight"]+ns["terminal_completion_weight"]
 expected=math.factorial(16-len(seed or {}));assert n["expected_completion_weight"]==expected
 if not ns["aborted_at_node_limit"]:assert n["certificate_weight"]==expected
 return {"cipher":name,"node_limit":cap,"stats":ns,"solutions":sol,"expected_completion_weight":expected,"certificate_weight":n["certificate_weight"],"certificate_complete":n["certificate_weight"]==expected,"native_seconds":n["elapsed_seconds"]}
def naive(name,display,seed):
 unknown=sorted(set(range(16))-set(seed));remaining=sorted(set(range(16))-set(seed.values()));e=ECB(name);out=[]
 for perm in itertools.permutations(remaining):
  m=[None]*16
  for k,v in seed.items():m[k]=v
  for k,v in zip(unknown,perm):m[k]=v
  ct=bytes((m[core.HEX.index(display[i])]<<4)|m[core.HEX.index(display[i+1])] for i in range(0,len(display),2));pt=cfb8(ct,e,True)
  if endpoint5.accepts(pt):out.append({"mapping":m,"plaintext_hex":pt.hex()})
 return out
def old4_accepts(data):
 state=0
 for v in data:
  state=core.historical_utf8_transition(state,0,v)
  if state is None:return False
 return state==0
def main():
 rev9_path=HERE.parents[1]/"sources/rev9_source/controls.json";assert sha(rev9_path)=="8c21ea6e275cf5989616ea9d77a19d910e55431626a83339641421ca59947f10"
 rev9=json.loads(rev9_path.read_text());actual=bytes.fromhex(rev9["rev9_full_chain"]["outputs_hex"]["final"]);assert hashlib.sha256(actual).hexdigest()=="10d049e3b2c0d9840e52e746bc45a9ce0590ec3939a16ccdc258fffa72d1b197"
 assert not old4_accepts(actual) and endpoint5.accepts(actual)
 terminal={"rev9_old4_rejected":True,"rev9_new5_accepted":True,"rev9_plaintext_sha256":hashlib.sha256(actual).hexdigest(),"truncated_e2_rejected":not endpoint5.accepts(b"ok\xe2"),"truncated_e280_rejected":not endpoint5.accepts(b"ok\xe2\x80"),"wrong_third_byte_rejected":not endpoint5.accepts(b"ok\xe2\x80\xa5")};assert all(terminal.values())
 allbytes=bytes(range(256))+b" unified source-backed CFB8";vectors=[]
 for name in CIPHERS:
  e=ECB(name);ct=cfb8(allbytes,e,False);nct=bytes.fromhex(subprocess.check_output([str(BIN),"--cfb-encrypt",name,allbytes.hex()],text=True).strip());assert ct==nct
  assert cfb8(ct,ECB(name),True)==allbytes;assert bytes.fromhex(subprocess.check_output([str(BIN),"--cfb-decrypt",name,ct.hex()],text=True).strip())==allbytes
  vectors.append({"cipher":name,"block_size":e.block,"key_convention":{"aes128":"Zombies+9NUL","blowfish":"raw7","des":"Zombies+NUL","blowfish_compat":"raw7 word_reverse adapter","rc2":"raw7 source","loki97":"selected16 in zeroed32 source backing"}[name],"iv_hex":(b"0"*e.block).hex(),"plaintext_sha256":hashlib.sha256(allbytes).hexdigest(),"ciphertext_hex":ct.hex(),"ciphertext_sha256":hashlib.sha256(ct).hexdigest(),"native_equal_python":True,"roundtrip":True})
 rng=random.Random(20260910);mapping=list(range(16));rng.shuffle(mapping);mixed=("ASCII\tline\r\n–—‘’…;".encode("utf-8"))*3;assert all(x in mixed for x in (bytes.fromhex("e28093"),bytes.fromhex("e28094"),bytes.fromhex("e28098"),bytes.fromhex("e28099"),bytes.fromhex("e280a6")))
 seeded=[];capped=[]
 for name in CIPHERS:
  e=ECB(name);display=core.display_encode(cfb8(mixed,e,False),mapping);assert len(set(display))==16
  unknown=sorted(set(core.HEX.index(x) for x in display))[-4:];seed={i:v for i,v in enumerate(mapping) if i not in unknown};row=compare(name,100000,display,seed);nv=naive(name,display,seed)
  assert row["certificate_complete"] and row["expected_completion_weight"]==24 and row["solutions"]==nv and any(x["mapping"]==mapping and x["plaintext_hex"]==mixed.hex() for x in nv)
  row.update({"unknown_symbols":unknown,"naive_permutations":24,"naive_exact_match":True,"plant_recovered":True});seeded.append(row)
  full=(mixed*((546//len(mixed))+1))[:546];fd=core.display_encode(cfb8(full,e,False),mapping)
  for cap in (250000,1000000):
   t=time.perf_counter();z=compare(name,cap,fd);z["python_plus_native_wall_seconds"]=time.perf_counter()-t;assert z["stats"]["aborted_at_node_limit"] and not z["certificate_complete"];capped.append(z)
 files=[HERE/"native_text5.cpp",BIN,HERE/"endpoint5.py",HEX_CFB/"prototype.py",rev9_path]+sorted((HERE/"source").glob("*"))+sorted((HERE/"source_build").glob("*"))
 result={"identity":IDENTITY,"target_evaluated":False,"rev7_file_read":False,"scope":"Unified six-backend ASCII plus five UTF-8 sequence endpoint controls only","endpoint":{"ascii":"TAB LF CR and 32..126","utf8":["e28093","e28094","e28098","e28099","e280a6"],"terminal_state":0},"rev9_endpoint_fixture":terminal,"full_byte_cfb8":vectors,"mixed_five_sequence_seeded_four_unknown":seeded,"full16_capped_exact_prefix":capped,"artifact_hashes":{str(x.relative_to(HERE) if HERE in x.parents else x):sha(x) for x in files},"source":{"repository":"https://github.com/Distrotech/libmcrypt","commit":"3bd338e2f808e985f5b229a7642d48c26615993f","copied_unmodified":["source/rc2.c","source/rc2.h","source/loki97.c","source/COPYING.LIB"]},"build":{"commands":["clang -O2 -Isource_build -Isource -c source/rc2.c -o source_build/rc2.o","clang -O2 -Isource_build -Isource -c source/loki97.c -o source_build/loki97.o","clang -shared -fPIC -O2 -Isource_build -Isource source/rc2.c -o source_build/librc2.so","clang -shared -fPIC -O2 -Isource_build -Isource source/loki97.c -o source_build/libloki97.so","clang++ -std=c++17 -O3 -Wno-deprecated-declarations native_text5.cpp source_build/rc2.o source_build/loki97.o -o native_text5 -I/opt/homebrew/Cellar/openssl@3/3.6.3/include -L/opt/homebrew/Cellar/openssl@3/3.6.3/lib -lcrypto -Wl,-rpath,/opt/homebrew/Cellar/openssl@3/3.6.3/lib"],"compiler":subprocess.check_output(["clang","--version"],text=True).splitlines()[0],"openssl":subprocess.check_output(["pkg-config","--modversion","openssl"],text=True).strip(),"python":sys.version,"platform":platform.platform()},"assertions":{"all_passed":True,"rev9_endpoint_boundary":True,"terminal_rejections":True,"all_byte_cfb8_native_python_roundtrip":True,"seeded_all24_exact":True,"full16_prefix_stats_solutions_exact":True,"caps_not_completeness_claims":True}}
 out=HERE/"controls.json"
 if out.exists():raise SystemExit("refusing existing controls.json")
 out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n");print(json.dumps({"identity":IDENTITY,"controls_sha256":sha(out),"terminal":terminal,"capped":[{"cipher":x["cipher"],"cap":x["node_limit"],"nodes":x["stats"]["nodes"],"weight":x["certificate_weight"],"wall":x["python_plus_native_wall_seconds"]} for x in capped]},indent=2))
if __name__=="__main__":main()

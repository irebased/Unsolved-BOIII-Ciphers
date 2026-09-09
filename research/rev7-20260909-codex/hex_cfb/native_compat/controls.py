#!/usr/bin/env python3
from __future__ import annotations
import hashlib,itertools,json,math,random,subprocess,sys,time
from pathlib import Path
from Crypto.Cipher import Blowfish
HERE=Path(__file__).resolve().parent
CORE=HERE.parent/"prototype.py"
sys.path.insert(0,str(CORE.parent))
import prototype as p
BIN=HERE/"native_compat"
VECTORS=HERE/"wasm_bfcompat_vectors.json"
FIELDS=("nodes","rejected_plaintext","complete","maximum_depth","aborted_at_node_limit","rejected_completion_weight","terminal_completion_weight","rejected_unterminated_endpoint")
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def word_reverse(b):return b[3::-1]+b[7:3:-1]
def full_reverse(b):return b[::-1]
def half_swap(b):return b[4:]+b[:4]
def bf_key(key):
 if not key:return b"\0"*4
 if len(key)>=4:return key[:56]
 return key*((4+len(key)-1)//len(key))
def compat_block(key,block,transform=word_reverse):
 cipher=Blowfish.new(bf_key(key),Blowfish.MODE_ECB)
 return transform(cipher.encrypt(transform(block)))
class CompatECB:
 def __init__(self,key=b"Zombies"):self.key=key
 def encrypt(self,block):return compat_block(self.key,block)
def cfb8(data,ecb,iv,decrypt):
 reg=iv;out=bytearray()
 for value in data:
  transformed=value^ecb.encrypt(reg)[0];ct=value if decrypt else transformed;out.append(transformed);reg=reg[1:]+bytes([ct])
 return bytes(out)
def accepted(data):
 state=0
 for value in data:
  nxt=p.historical_utf8_transition(state,0,value)
  if nxt is None:return False
  state=nxt
 return state==0
def native(cap,display,seed=None):
 args=[str(BIN),"blowfish_compat",str(cap),display,"-" if seed is None else ",".join(f"{k}:{v}" for k,v in sorted(seed.items()))]
 return json.loads(subprocess.check_output(args,text=True))
def normalize_py(solutions,stats):
 return ({k:getattr(stats,k) for k in FIELDS},[{"mapping":list(x["mapping"]),"plaintext_hex":x["plaintext"].hex()} for x in solutions])
def compare(cap,display,seed=None):
 ecb=CompatECB();iv=b"0"*8
 ps,pst=p.backtrack(display,ecb,iv,p.historical_utf8_transition,node_limit=cap,seed_mapping=seed)
 py_stats,py_solutions=normalize_py(ps,pst);n=native(cap,display,seed);ns={k:n[k] for k in FIELDS}
 assert ns==py_stats and n["solutions"]==py_solutions
 expected=math.factorial(16-len(seed or {}));cert=ns["rejected_completion_weight"]+ns["terminal_completion_weight"]
 assert n["expected_completion_weight"]==expected and n["certificate_weight"]==cert and cert<=expected
 if not ns["aborted_at_node_limit"]:assert cert==expected
 return {"node_limit":cap,"stats":ns,"solutions":py_solutions,"solution_count":len(py_solutions),"expected_completion_weight":expected,"certificate_weight":cert,"certificate_complete":cert==expected,"native_seconds":n["elapsed_seconds"]}
def naive_seeded(display,seed):
 unknown=sorted(set(range(16))-set(seed));remaining=sorted(set(range(16))-set(seed.values()));out=[]
 for perm in itertools.permutations(remaining):
  mapping=[None]*16
  for k,v in seed.items():mapping[k]=v
  for k,v in zip(unknown,perm):mapping[k]=v
  ciphertext=bytes((mapping[p.HEX.index(display[i])]<<4)|mapping[p.HEX.index(display[i+1])] for i in range(0,len(display),2))
  plain=cfb8(ciphertext,CompatECB(),b"0"*8,True)
  if accepted(plain):out.append({"mapping":mapping,"plaintext_hex":plain.hex()})
 return out
def main():
 vector_data=json.loads(VECTORS.read_text());vectors=vector_data["blowfish-compat"]["vectors"];assert len(vectors)==200
 alternatives={"identity":lambda b:b,"full_reverse":full_reverse,"word_reverse":word_reverse,"half_swap":half_swap,"half_swap_then_word_reverse":lambda b:word_reverse(half_swap(b))}
 counts={name:0 for name in alternatives};native_matches=0
 for row in vectors:
  key=bytes.fromhex(row["key"]);block=bytes.fromhex(row["block"]);want=row["enc"]
  for name,transform in alternatives.items():counts[name]+=compat_block(key,block,transform).hex()==want
  got=subprocess.check_output([str(BIN),"--block-encrypt",row["key"],row["block"]],text=True).strip();native_matches+=got==want
 assert counts=={"identity":0,"full_reverse":0,"word_reverse":200,"half_swap":0,"half_swap_then_word_reverse":0}
 assert native_matches==200
 ecb=CompatECB();iv=b"0"*8;vector=bytes(range(256))+b"BF-compat CFB8 full-byte control"
 pyct=cfb8(vector,ecb,iv,False)
 nct=bytes.fromhex(subprocess.check_output([str(BIN),"--cfb-encrypt","blowfish_compat",vector.hex()],text=True).strip())
 assert nct==pyct
 npt=bytes.fromhex(subprocess.check_output([str(BIN),"--cfb-decrypt","blowfish_compat",nct.hex()],text=True).strip())
 assert npt==vector==cfb8(pyct,ecb,iv,True)
 rng=random.Random(20260910);mapping=list(range(16));rng.shuffle(mapping)
 mixed=("ASCII\tline\r\n"+"en\u2013em\u2014left\u2018right\u2019;").encode("utf-8")*4
 display=p.display_encode(cfb8(mixed,ecb,iv,False),mapping);assert len(set(display))==16
 unknown=sorted(set(p.HEX.index(x) for x in display))[-4:];seed={i:v for i,v in enumerate(mapping) if i not in unknown}
 seeded=compare(100000,display,seed);naive=naive_seeded(display,seed)
 assert seeded["expected_completion_weight"]==24 and seeded["certificate_complete"]
 assert seeded["solutions"]==naive
 assert any(x["mapping"]==mapping and x["plaintext_hex"]==mixed.hex() for x in naive)
 seeded.update({"unknown_symbols":unknown,"naive_permutations":24,"naive_survivors_equal_native_and_python":True,"plant_recovered":True})
 full_plain=(mixed*((546//len(mixed))+1))[:546];full_display=p.display_encode(cfb8(full_plain,ecb,iv,False),mapping);assert len(set(full_display))==16
 capped=[]
 for cap in (250000,1000000):
  start=time.perf_counter();row=compare(cap,full_display);row["python_plus_native_wall_seconds"]=time.perf_counter()-start
  assert row["stats"]["aborted_at_node_limit"] and not row["certificate_complete"];capped.append(row)
 result={"identity":"ASTRA","target_evaluated":False,"scope":"synthetic BF-compat controls only; no Rev7 input read","model":{"block_transform":"word_reverse(BF(key, word_reverse(block)))","fixed_key_hex":b"Zombies".hex(),"fixed_key_length":7,"iv_hex":iv.hex(),"mode":"CFB8","endpoint":"TAB LF CR ASCII32..126 plus E28093/E28094/E28098/E28099; terminal state zero"},"wasm_vector_validation":{"source_subset_sha256":sha(VECTORS),"upstream_full_vector_sha256":vector_data["provenance"]["source_sha256"],"vector_count":len(vectors),"key_lengths":sorted(set(len(bytes.fromhex(x["key"])) for x in vectors)),"match_counts":counts,"native_block_matches":native_matches,"establishes":"BF-compat word-reversal transform for the 200 supplied 16-byte-key WASM vectors","does_not_establish":"a direct seven-byte Zombies WASM fixture or the historical frontend key convention"},"fixed_native_cfb8":{"plaintext_sha256":hashlib.sha256(vector).hexdigest(),"ciphertext_sha256":hashlib.sha256(pyct).hexdigest(),"native_matches_separate_python_manual":True,"encrypt_decrypt_roundtrip":True,"interpretation":"internal fixed-key implementation control, not a direct WASM Zombies comparison"},"seeded_four_unknown":seeded,"full16_capped_exact_prefix":capped,"source_hashes":{"prototype.py":sha(CORE),"native_compat.cpp":sha(HERE/"native_compat.cpp"),"native_compat_binary":sha(BIN),"controls.py":sha(Path(__file__))},"environment":{"python":sys.version,"build_command":["clang++","-std=c++17","-O3","-Wno-deprecated-declarations","native_compat.cpp","-o","native_compat","-I/opt/homebrew/Cellar/openssl@3/3.6.3/include","-L/opt/homebrew/Cellar/openssl@3/3.6.3/lib","-lcrypto","-Wl,-rpath,/opt/homebrew/Cellar/openssl@3/3.6.3/lib"],"openssl_version":subprocess.check_output(["pkg-config","--modversion","openssl"],text=True).strip()},"assertions":{"all_passed":True,"wasm_vectors_gate_before_fixed_controls":True,"native_stats_weights_maps_plaintexts_equal_python":True,"seeded_survivors_equal_naive_24_permutations":True,"caps_are_incomplete_prefixes_only":True}}
 out=HERE/"controls.json"
 if out.exists():raise SystemExit("refusing existing controls.json")
 out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(json.dumps({"identity":"ASTRA","controls_sha256":sha(out),"wasm":result["wasm_vector_validation"],"seeded_stats":seeded["stats"],"capped":[{"cap":x["node_limit"],"stats":x["stats"],"wall":x["python_plus_native_wall_seconds"]} for x in capped]},indent=2))
if __name__=="__main__":main()

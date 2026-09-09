#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,math,random,subprocess,sys,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
CORE=HERE.parent/"prototype.py"
sys.path.insert(0,str(CORE.parent))
import prototype as p
BIN=HERE/"native_text"
FIELDS=("nodes","rejected_plaintext","complete","maximum_depth","aborted_at_node_limit","rejected_completion_weight","terminal_completion_weight","rejected_unterminated_endpoint")
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def native(cipher,cap,display,seed=None):
 args=[str(BIN),cipher,str(cap),display,"-" if seed is None else ",".join(f"{k}:{v}" for k,v in sorted(seed.items()))]
 return json.loads(subprocess.check_output(args,text=True))
def normalized_py(solutions,stats):
 return ({k:getattr(stats,k) for k in FIELDS},[{"mapping":list(x["mapping"]),"plaintext_hex":x["plaintext"].hex()} for x in solutions])
def compare(cipher,cap,display,seed=None):
 ecb,_key,iv=p.ecb_oracle(cipher)
 ps,pst=p.backtrack(display,ecb,iv,p.historical_utf8_transition,node_limit=cap,seed_mapping=seed)
 py_stats,py_solutions=normalized_py(ps,pst); n=native(cipher,cap,display,seed)
 native_stats={k:n[k] for k in FIELDS}
 assert native_stats==py_stats,(native_stats,py_stats)
 assert n["solutions"]==py_solutions
 expected=math.factorial(16-len(seed or {})); certificate=native_stats["rejected_completion_weight"]+native_stats["terminal_completion_weight"]
 assert n["expected_completion_weight"]==expected and n["certificate_weight"]==certificate
 assert certificate<=expected
 if not native_stats["aborted_at_node_limit"]:assert certificate==expected
 return {"cipher":cipher,"node_limit":cap,"stats":native_stats,"solutions":py_solutions,"solution_count":len(py_solutions),"expected_completion_weight":expected,"certificate_weight":certificate,"certificate_complete":certificate==expected,"native_seconds":n["elapsed_seconds"]}
def main():
 rng=random.Random(20260910); mapping=list(range(16));rng.shuffle(mapping)
 vector=bytes(range(256))+b"native text CFB8 full-byte control"
 cfb={}
 for cipher in p.cipher_specs():
  ecb,_key,iv=p.ecb_oracle(cipher); pyct=p.manual_cfb8(vector,ecb,iv,False)
  nct=bytes.fromhex(subprocess.check_output([str(BIN),"--cfb-encrypt",cipher,vector.hex()],text=True).strip())
  assert nct==pyct==p.library_cfb8(vector,cipher,False)
  npt=bytes.fromhex(subprocess.check_output([str(BIN),"--cfb-decrypt",cipher,nct.hex()],text=True).strip())
  assert npt==vector==p.library_cfb8(pyct,cipher,True)
  cfb[cipher]={"ciphertext_sha256":hashlib.sha256(pyct).hexdigest(),"native_matches_python_manual_and_library":True,"full_byte_roundtrip":True}
 mixed=("ASCII\tline\r\n"+"en\u2013em\u2014left\u2018right\u2019;").encode("utf-8")*4
 seeded=[]
 for cipher in p.cipher_specs():
  ecb,_key,iv=p.ecb_oracle(cipher); display=p.display_encode(p.manual_cfb8(mixed,ecb,iv,False),mapping);assert len(set(display))==16
  unknown=sorted(set(p.HEX.index(x) for x in display))[-4:];seed={i:v for i,v in enumerate(mapping) if i not in unknown}
  row=compare(cipher,100000,display,seed);assert row["certificate_complete"] and row["expected_completion_weight"]==24
  assert any(x["mapping"]==mapping and x["plaintext_hex"]==mixed.hex() for x in row["solutions"])
  row.update({"unknown_symbols":unknown,"plant_plaintext_hex":mixed.hex(),"expected_mapping_recovered":True});seeded.append(row)
 ecb,_key,iv=p.ecb_oracle("aes128")
 terminal=[]
 for name,plain in (("truncated_e2",b"OK\xe2"),("truncated_e280",b"OK\xe2\x80")):
  display=p.display_encode(p.manual_cfb8(plain,ecb,iv,False),list(range(16)));seed={i:i for i in range(16)}
  row=compare("aes128",1000,display,seed);assert row["solution_count"]==0 and row["stats"]["rejected_unterminated_endpoint"]==1 and row["certificate_complete"]
  row["fixture"]=name;row["plaintext_hex"]=plain.hex();terminal.append(row)
 same=compare("aes128",1000,"0000",{i:i for i in range(1,16)})
 assert same["certificate_complete"];same["display"]="0000";same["unassigned_same_high_low_symbol"]=0
 full_plain=(mixed*((546//len(mixed))+1))[:546]
 full_display=p.display_encode(p.manual_cfb8(full_plain,ecb,iv,False),mapping);assert len(set(full_display))==16
 capped=[]
 for cap in (250000,1000000):
  t=time.perf_counter();row=compare("aes128",cap,full_display);row["python_plus_native_wall_seconds"]=time.perf_counter()-t
  assert row["stats"]["aborted_at_node_limit"] and not row["certificate_complete"];capped.append(row)
 compiler=subprocess.check_output(["clang++","--version"],text=True).splitlines()[0]
 openssl=subprocess.check_output(["pkg-config","--modversion","openssl"],text=True).strip()
 result={"identity":"ASTRA","target_evaluated":False,"scope":"synthetic controls only; no Rev7 input read","endpoint":{"ascii_bytes":"TAB LF CR and 32..126","utf8_sequences":["e28093","e28094","e28098","e28099"],"terminal_state":0},"backend":{"compiler":compiler,"openssl_version":openssl,"build_command":["clang++","-std=c++17","-O3","-Wno-deprecated-declarations","native_text.cpp","-o","native_text","-I/opt/homebrew/Cellar/openssl@3/3.6.3/include","-L/opt/homebrew/Cellar/openssl@3/3.6.3/lib","-lcrypto","-Wl,-rpath,/opt/homebrew/Cellar/openssl@3/3.6.3/lib"],"blowfish_key_hex":b"Zombies".hex(),"blowfish_key_length":7},"source_hashes":{"prototype.py":sha(CORE),"native_text.cpp":sha(HERE/"native_text.cpp"),"native_text_binary":sha(BIN),"controls.py":sha(Path(__file__))},"cfb8_controls":cfb,"seeded_four_unknown_exact_equivalence":seeded,"unterminated_endpoint_controls":terminal,"same_symbol_control":same,"full16_capped_exact_prefix_equivalence":capped,"assertions":{"all_passed":True,"native_stats_weights_maps_plaintexts_equal_python":True,"caps_are_incomplete_prefixes_only":True}}
 out=HERE/"controls.json"
 if out.exists():raise SystemExit("refusing to overwrite controls.json")
 out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
 print(json.dumps({"identity":"ASTRA","sha256":sha(out),"seeded":[{"cipher":x["cipher"],"stats":x["stats"]} for x in seeded],"terminal":[{"fixture":x["fixture"],"stats":x["stats"]} for x in terminal],"capped":[{"node_limit":x["node_limit"],"stats":x["stats"],"wall":x["python_plus_native_wall_seconds"]} for x in capped]},indent=2))
if __name__=="__main__":main()

#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,random,subprocess,sys,time
from pathlib import Path
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import solver
KEY=b"Zombies\0";BIN=HERE/"native"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def display_encode(data,mapping):
 inv=[0]*16
 for shown,actual in enumerate(mapping):inv[actual]=shown
 return "".join(solver.HEX[inv[v>>4]]+solver.HEX[inv[v&15]] for v in data)
def run_native(cap,display,seed=None,order=None):
 a=[str(BIN),str(cap),display,"-" if seed is None else ",".join(f"{k}:{v}" for k,v in sorted(seed.items()))]
 if order is not None:a.append("".join(solver.HEX[x] for x in order))
 return json.loads(subprocess.check_output(a,text=True))
def normalized(x):return sorted((tuple(s["mapping"]),s["plaintext_suffix_hex"]) for s in x)
def comparable(n):return {k:n[k] for k in ("node_limit","seeded_entries","expected_completion_weight","certificate_weight","certificate_complete","unaccounted_mapping_weight","stats")}
def cfb_formula(ct):
 e=DES.new(KEY,DES.MODE_ECB);return bytes(ct[i]^e.encrypt(ct[i-8:i])[0] for i in range(8,len(ct)))
def main():
 block=bytes(range(8));pyblock=DES.new(KEY,DES.MODE_ECB).encrypt(block);nativeblock=bytes.fromhex(subprocess.check_output([str(BIN),"--block",block.hex()],text=True).strip());assert nativeblock==pyblock
 prefix=bytes.fromhex("ff00807f81fea500");unit="IV-independent –—‘’… suffix;\n".encode("utf-8");plain=prefix+unit*12
 cfb=[]
 for iv in (bytes.fromhex("80ff017ec355aa19"),b"0"*8):
  ct=DES.new(KEY,DES.MODE_CFB,iv=iv,segment_size=8).encrypt(plain);native=bytes.fromhex(subprocess.check_output([str(BIN),"--cfb-encrypt",iv.hex(),plain.hex()],text=True).strip());assert ct==native and cfb_formula(ct)==plain[8:]
  cfb.append({"iv_hex":iv.hex(),"ciphertext_hex":ct.hex(),"ciphertext_sha256":hashlib.sha256(ct).hexdigest(),"pycryptodome_mode_cfb8_equals_native":True,"iv_independent_window_formula_equals_plaintext_suffix":True})
 endpoint_fixtures={"ascii_and_all_five":"ok–—‘’…\n".encode("utf-8"),"initial_state1_completion":bytes.fromhex("809341"),"initial_state2_completion":bytes.fromhex("9341"),"truncated_e2":bytes.fromhex("41e2"),"truncated_e280":bytes.fromhex("41e280"),"wrong_third":bytes.fromhex("41e280a5")};want={"ascii_and_all_five":True,"initial_state1_completion":True,"initial_state2_completion":True,"truncated_e2":False,"truncated_e280":False,"wrong_third":False};endpoint={}
 for name,data in endpoint_fixtures.items():
  actual=subprocess.check_output([str(BIN),"--endpoint",data.hex()],text=True).strip()=="true";assert actual==want[name];endpoint[name]={"hex":data.hex(),"expected":want[name],"native":actual}
 rng=random.Random(20260910);mapping=list(range(16));rng.shuffle(mapping);iv=bytes.fromhex("80ff017ec355aa19");e=DES.new(KEY,DES.MODE_CFB,iv=iv,segment_size=8);ct=e.encrypt(plain);display=display_encode(ct,mapping);unknown=sorted(set(solver.HEX.index(x) for x in display))[-4:];seed={s:mapping[s] for s in range(16) if s not in unknown}
 py_seed=solver.solve(display,100000,seed);n_seed=run_native(100000,display,seed);assert comparable(n_seed)==comparable(py_seed) and normalized(n_seed["solutions"])==normalized(py_seed["solutions"]);assert n_seed["geometry"]["symbol_order"]==py_seed["geometry"]["symbol_order"] and n_seed["geometry"]["fully_bound_window_counts"]==py_seed["geometry"]["fully_bound_window_counts"] and n_seed["geometry"]["anchor_window_suffix_index"]==py_seed["geometry"]["anchor_window_suffix_index"] and n_seed["geometry"]["anchor_unique_symbols"]==py_seed["geometry"]["anchor_unique_symbols"]
 n_override=run_native(100000,display,seed,py_seed["geometry"]["symbol_order"]);assert comparable(n_override)==comparable(n_seed) and normalized(n_override["solutions"])==normalized(n_seed["solutions"]) and n_override["geometry"]["explicit_order_override"]
 full=(prefix+unit*((546//len(unit))+2))[:546];fullct=DES.new(KEY,DES.MODE_CFB,iv=iv,segment_size=8).encrypt(full);fd=display_encode(fullct,mapping);prefixes=[]
 for cap in (250000,1000000):
  t=time.perf_counter();py=solver.solve(fd,cap);pysec=time.perf_counter()-t;t=time.perf_counter();native=run_native(cap,fd);wall=time.perf_counter()-t
  assert comparable(native)==comparable(py) and normalized(native["solutions"])==normalized(py["solutions"]);assert native["geometry"]["symbol_order"]==py["geometry"]["symbol_order"] and native["geometry"]["fully_bound_window_counts"]==py["geometry"]["fully_bound_window_counts"]
  assert native["stats"]["aborted_at_node_limit"] and not native["certificate_complete"]
  prefixes.append({"node_limit":cap,"python":py,"native":native,"all_counters_and_survivors_equal":True,"python_seconds":pysec,"native_process_wall_seconds":wall,"native_reported_seconds":native["elapsed_seconds"],"native_ecb_calls":native["ecb_calls"],"native_nodes_per_second":native["stats"]["nodes"]/native["elapsed_seconds"],"native_ecb_calls_per_second":native["ecb_calls"]/native["elapsed_seconds"]})
 result={"identity":"ASTRA","target_evaluated":False,"rev7_read":False,"scope":"Native DES-only IV-independent solver controls","des":{"key_hex":KEY.hex(),"openssl_ecb_block_hex":nativeblock.hex(),"pycryptodome_ecb_block_hex":pyblock.hex(),"match":True},"pycryptodome_cfb8_two_iv_window_formula":cfb,"independent_native_endpoint":endpoint,"seeded_four_unknown":{"python":py_seed,"native":n_seed,"explicit_default_order_native":n_override,"exact_counters_and_survivors":True,"mapping_recovered":any(s["mapping"]==mapping for s in n_seed["solutions"])},"full16_prefixes":prefixes,"explicit_order_interface":{"format":"optional fifth argument: a 16-character hexadecimal permutation after seed","validated_bijection":True,"default_order_replay_exact":True,"note":"No alternate heuristic is selected by these controls."},"artifacts":{"native.cpp":sha(HERE/"native.cpp"),"native":sha(BIN),"solver.py":sha(HERE/"solver.py"),"frozen_python_controls.json":sha(HERE/"controls.json"),"native_controls.py":sha(Path(__file__))},"build":{"command":"clang++ -std=c++17 -O3 -Wno-deprecated-declarations native.cpp -o native -I/opt/homebrew/Cellar/openssl@3/3.6.3/include -L/opt/homebrew/Cellar/openssl@3/3.6.3/lib -lcrypto -Wl,-rpath,/opt/homebrew/Cellar/openssl@3/3.6.3/lib","openssl":subprocess.check_output(["pkg-config","--modversion","openssl"],text=True).strip(),"python":sys.version},"assertions":{"all_passed":True,"openssl_des_matches_pycryptodome":True,"mode_cfb8_two_iv_formula":True,"endpoint_native_independent_boundaries":True,"seeded_exact":True,"full16_250k_exact":True,"full16_1m_exact":True,"cap_semantics":True}}
 out=HERE/"native_controls.json"
 if out.exists():raise SystemExit("refusing existing native_controls.json")
 out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n");print(json.dumps({"identity":"ASTRA","sha256":sha(out),"seeded_nodes":n_seed["stats"]["nodes"],"benchmarks":[{"cap":x["node_limit"],"native_seconds":x["native_reported_seconds"],"nodes_per_second":x["native_nodes_per_second"],"ecb_calls":x["native_ecb_calls"],"ecb_calls_per_second":x["native_ecb_calls_per_second"],"python_seconds":x["python_seconds"]} for x in prefixes]},indent=2))
if __name__=="__main__":main()

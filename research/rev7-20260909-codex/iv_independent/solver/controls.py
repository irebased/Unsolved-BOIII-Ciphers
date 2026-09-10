#!/usr/bin/env python3
from __future__ import annotations
import hashlib,itertools,json,random,sys,time
from pathlib import Path
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import solver
KEY=b"Zombies\0"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def cfb8_encrypt(data,iv):
 e=DES.new(KEY,DES.MODE_ECB);reg=iv;out=bytearray()
 for v in data:y=v^e.encrypt(reg)[0];out.append(y);reg=reg[1:]+bytes([y])
 return bytes(out)
def display_encode(data,mapping):
 inv=[0]*16
 for shown,actual in enumerate(mapping):inv[actual]=shown
 return "".join(solver.HEX[inv[v>>4]]+solver.HEX[inv[v&15]] for v in data)
def decode(display,mapping):return bytes((mapping[solver.HEX.index(display[i])]<<4)|mapping[solver.HEX.index(display[i+1])] for i in range(0,len(display),2))
def suffix_plain(display,mapping):
 ct=decode(display,mapping);e=DES.new(KEY,DES.MODE_ECB)
 return bytes(ct[i]^e.encrypt(ct[i-8:i])[0] for i in range(8,len(ct)))
def naive(display,seed):
 unknown=sorted(set(range(16))-set(seed));remaining=sorted(set(range(16))-set(seed.values()));solutions=[];rejected_relaxed=0;rejected_strict=0
 for perm in itertools.permutations(remaining):
  m=[None]*16
  for k,v in seed.items():m[k]=v
  for k,v in zip(unknown,perm):m[k]=v
  suffix=suffix_plain(display,m)
  if any(v not in solver.RELAXED for v in suffix):rejected_relaxed+=1
  elif not solver.Solver.strict_suffix_ok(suffix):rejected_strict+=1
  else:solutions.append({"mapping":m,"plaintext_suffix_hex":suffix.hex()})
 return {"permutations":len(list(itertools.permutations(remaining))),"rejected_relaxed":rejected_relaxed,"rejected_strict":rejected_strict,"solutions":solutions}
def normalized(x):return sorted((tuple(s["mapping"]),s["plaintext_suffix_hex"]) for s in x)
def main():
 rng=random.Random(20260910);mapping=list(range(16));rng.shuffle(mapping);iv=bytes.fromhex("80ff017ec355aa19")
 prefix=bytes.fromhex("ff00807f81fea500");unit="IV-independent –—‘’… suffix;\n".encode("utf-8");plain=prefix+(unit*12);ct=cfb8_encrypt(plain,iv);display=display_encode(ct,mapping);assert len(set(display))==16
 used=sorted(set(solver.HEX.index(x) for x in display));unknown=used[-4:];seed={s:mapping[s] for s in range(16) if s not in unknown}
 opt=solver.solve(display,100000,seed);ref=solver.solve(display,100000,seed,reference_scan=True);nv=naive(display,seed)
 assert opt["stats"]==ref["stats"] and opt["certificate_weight"]==24 and opt["certificate_complete"] and opt["unaccounted_mapping_weight"]==0
 assert normalized(opt["solutions"])==normalized(ref["solutions"])==normalized(nv["solutions"])
 assert any(x["mapping"]==mapping and x["plaintext_suffix_hex"]==plain[8:].hex() for x in nv["solutions"])
 full=(prefix+unit*((546//len(unit))+2))[:546];full_ct=cfb8_encrypt(full,iv);full_display=display_encode(full_ct,mapping)
 t=time.perf_counter();full_opt=solver.solve(full_display,250000);opt_seconds=time.perf_counter()-t
 t=time.perf_counter();full_ref=solver.solve(full_display,250000,reference_scan=True);ref_seconds=time.perf_counter()-t
 assert full_opt["stats"]==full_ref["stats"] and full_opt["solutions"]==full_ref["solutions"] and full_opt["certificate_weight"]==full_ref["certificate_weight"]
 assert full_opt["stats"]["aborted_at_node_limit"] and not full_opt["certificate_complete"] and full_opt["unaccounted_mapping_weight"]>0
 result={"identity":"ASTRA","target_evaluated":False,"rev7_read":False,"scope":"Synthetic-only DES CFB8 IV-independent suffix constraint solver","model":{"equation":"for i>=8, P_i=C_i XOR DES_key(C[i-8:i])[0]","key_hex":KEY.hex(),"iv_not_a_solver_variable":True,"relaxed_byte_set":{"count":len(solver.RELAXED),"ascii_count":98,"extra_hex":["80","93","94","98","99","a6","e2"]},"strict_suffix_fsa":{"initial_state_set":[0,1,2],"terminal_state":0,"sequences":["e28093","e28094","e28098","e28099","e280a6"]}},"synthetic_plant":{"arbitrary_iv_hex":iv.hex(),"plaintext_prefix_hex":prefix.hex(),"prefix_is_deliberately_nontext":True,"plaintext_sha256":hashlib.sha256(plain).hexdigest(),"ciphertext_sha256":hashlib.sha256(ct).hexdigest(),"display_sha256":hashlib.sha256(display.encode()).hexdigest(),"mapping_display_to_nibble":mapping,"unknown_symbols":unknown,"seeded_entries":len(seed),"suffix_sha256":hashlib.sha256(plain[8:]).hexdigest(),"solver_geometry":opt["geometry"]},"seeded_four_unknown":{"optimized":opt,"reference_rescan":ref,"naive":nv,"all_survivor_maps_and_suffix_bytes_equal":True,"plant_recovered":True},"full16_prefix":{"node_limit":250000,"optimized":full_opt,"reference_rescan":full_ref,"exact_stats_and_survivors_equal":True,"optimized_seconds":opt_seconds,"reference_seconds":ref_seconds,"interpretation":"incomplete deterministic prefix only; no completeness or target claim"},"algorithm":{"anchor":"minimum unique-symbol window; tie by most contained windows then earliest suffix index","order":"anchor symbols by descending occurrence then index; remaining symbols greedily maximize newly fully bound windows, then containment occurrence, then lower index","constraint_activation":"optimized path checks a window once, when its last unseeded symbol is assigned","reference":"separate path rescans every currently fully bound window after each assignment","rejection_weight":"factorial of entries still unassigned after a failed assignment","terminal_weight":"one per complete mapping accepted by strict suffix FSA"},"artifacts":{"solver.py":sha(HERE/"solver.py"),"controls.py":sha(Path(__file__))},"environment":{"python":sys.version},"assertions":{"all_passed":True,"nonascii_prefix_and_arbitrary_iv_plant":True,"seeded_all24_naive_exact":True,"optimized_reference_stats_equal":True,"full16_capped_prefix_exact":True,"cap_not_complete":True}}
 out=HERE/"controls.json"
 if out.exists():raise SystemExit("refusing existing controls.json")
 out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n");print(json.dumps({"identity":"ASTRA","controls_sha256":sha(out),"seeded":{"solutions":len(opt["solutions"]),"nodes":opt["stats"]["nodes"],"geometry":opt["geometry"]},"full16":{"nodes":full_opt["stats"]["nodes"],"certificate_weight":full_opt["certificate_weight"],"unaccounted":full_opt["unaccounted_mapping_weight"],"optimized_seconds":opt_seconds,"reference_seconds":ref_seconds}},indent=2))
if __name__=="__main__":main()

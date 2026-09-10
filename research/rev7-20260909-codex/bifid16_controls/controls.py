#!/usr/bin/env python3
"""ASTRA synthetic controls for arbitrary-square 4x4 Bifid SMT."""
from __future__ import annotations
import argparse,hashlib,itertools,json,random,time
from pathlib import Path
import bifid16 as b
z3=b.z3
HERE=Path(__file__).resolve().parent;OUT=HERE/"controls.json";SEED=20260910
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def plant(n):
 unit=b"ASTRA Bifid 16 control:\tline\r\n"+bytes.fromhex("e28093e28094e28098")+b"x"+bytes.fromhex("e28099e280a6")
 out=bytearray()
 while len(out)+len(unit)<=n:out.extend(unit)
 out.extend(b"Z"*(n-len(out)));assert len(out)==n and b.endpoint_accepts(bytes(out));return bytes(out)
def random_square(rng):
 x=list(range(16));rng.shuffle(x);return x
def solve_one(cipher,period,fixed,timeout):
 s,k,p,be,states=b.build_solver(cipher,period,fixed=fixed,timeout_ms=timeout);t=time.perf_counter();status=s.check();elapsed=time.perf_counter()-t
 row={"status":str(status),"elapsed_seconds":elapsed,"reason_unknown":s.reason_unknown() if status==z3.unknown else None}
 if status==z3.sat:
  m=s.model();sq=b.square_from_model(m,k);plain=b.plaintext_from_model(m,p);row.update({"square":sq,"plaintext_hex":plain.hex(),"plaintext_sha256":hashlib.sha256(plain).hexdigest()})
 return row,s,k,p
def main():
 rng=random.Random(SEED);roundtrips=[]
 periods=(1,2,3,5,16,31);lengths=(1,2,3,7,16,17,31,33)
 for period in periods:
  for n in lengths:
   sq=random_square(rng);plain=bytes(rng.randrange(256) for _ in range(n));ct=b.encrypt_bytes(plain,sq,period);back=b.decrypt_bytes(ct,sq,period);assert back==plain and b.encrypt_bytes(back,sq,period)==ct
   roundtrips.append({"period":period,"bytes":n,"final_symbol_block_length":(2*n)%period or period,"square":sq,"plaintext_sha256":hashlib.sha256(plain).hexdigest(),"ciphertext_sha256":hashlib.sha256(ct).hexdigest(),"roundtrip":True})
 truth=random_square(rng);short_plain="Short – text!\n".encode("utf-8");assert b.endpoint_accepts(short_plain);short_period=5;short_cipher=b.encrypt_bytes(short_plain,truth,short_period);pos=[0]*16
 for i,sym in enumerate(truth):pos[sym]=i
 fixed={s:pos[s] for s in range(12)};remaining_symbols=list(range(12,16));remaining_positions=sorted(set(range(16))-set(fixed.values()));brute=[]
 for perm in itertools.permutations(remaining_positions):
  pmap=dict(fixed);pmap.update(zip(remaining_symbols,perm));sq=[None]*16
  for symbol,position in pmap.items():sq[position]=symbol
  plain=b.decrypt_bytes(short_cipher,sq,short_period)
  if b.endpoint_accepts(plain):brute.append({"square":sq,"plaintext_hex":plain.hex()})
 solver,k,p,be,states=b.build_solver(short_cipher,short_period,fixed=fixed,timeout_ms=30000);smt=[]
 while True:
  status=solver.check()
  if status==z3.unsat:break
  assert status==z3.sat
  m=solver.model();sq=b.square_from_model(m,k);plain=b.plaintext_from_model(m,p);assert b.endpoint_accepts(plain) and b.encrypt_bytes(plain,sq,short_period)==short_cipher
  smt.append({"square":sq,"plaintext_hex":plain.hex()});solver.add(z3.Or(*[k[s]!=m.eval(k[s]).as_long() for s in range(16)]))
 assert sorted(brute,key=lambda x:x["square"])==sorted(smt,key=lambda x:x["square"])
 fixed_solver,fk,fp,fbe,fst=b.build_solver(short_cipher,short_period,fixed={s:pos[s] for s in range(16)},timeout_ms=30000);assert fixed_solver.check()==z3.sat;fm=fixed_solver.model();fixed_plain=b.plaintext_from_model(fm,fp);assert fixed_plain==b.decrypt_bytes(short_cipher,truth,short_period)==short_plain
 bad,_,_,_,_=b.build_solver(short_cipher,short_period,fixed={0:0,1:0},timeout_ms=30000);assert bad.check()==z3.unsat
 full_truth=random_square(rng);full_plain=plant(546);full_period=31;full_cipher=b.encrypt_bytes(full_plain,full_truth,full_period);full_pos=[0]*16
 for i,symbol in enumerate(full_truth):full_pos[symbol]=i
 dump_solver,_,_,_,_=b.build_solver(full_cipher,full_period,timeout_ms=120000);(HERE/"full_plant.smt2").write_text(dump_solver.sexpr())
 full_fixed,full_k,full_p,_,_=b.build_solver(full_cipher,full_period,fixed={s:full_pos[s] for s in range(16)},timeout_ms=30000);t=time.perf_counter();fixed_status=full_fixed.check();fixed_elapsed=time.perf_counter()-t;assert fixed_status==z3.sat
 fmodel=full_fixed.model();fixed_candidate=b.plaintext_from_model(fmodel,full_p);assert fixed_candidate==full_plain==b.decrypt_bytes(full_cipher,full_truth,full_period) and b.encrypt_bytes(fixed_candidate,full_truth,full_period)==full_cipher
 attempts=json.loads((HERE/"attempts.json").read_text());assert attempts["identity"]=="ASTRA" and all(not x["classified_as_negative"] for x in attempts["attempts"])
 assert attempts["attempts"][0]["ciphertext_sha256"]==hashlib.sha256(full_cipher).hexdigest() and attempts["attempts"][0]["status"]=="unknown"
 full={"period":full_period,"bytes":546,"truth_square":full_truth,"plaintext_sha256":hashlib.sha256(full_plain).hexdigest(),"ciphertext_hex":full_cipher.hex(),"ciphertext_sha256":hashlib.sha256(full_cipher).hexdigest(),"unknown_square_attempt":attempts["attempts"][0],"retained_models":[],"exhaustive":False,"conclusion":"unknown; no negative or recovery claim","fixed_truth_check":{"status":"sat","elapsed_seconds":fixed_elapsed,"plaintext_hex":fixed_candidate.hex(),"plaintext_sha256":hashlib.sha256(fixed_candidate).hexdigest(),"equals_concrete":True,"reencrypts_exactly":True}}
 deps=json.loads((HERE/"dependency/dependency.json").read_text());assert deps["runtime_version"]=="4.15.3" and sha(HERE/"dependency/runtime/z3/lib/libz3.dylib")==deps["library_sha256"]
 result={"identity":"ASTRA","target_evaluated":False,"rev7_read":False,"status":"completed_controls_passed; full unknown-square endpoint attempt unresolved","seed":SEED,"model":{"alphabet":"0123456789ABCDEF","square":"arbitrary permutation of 16 symbols at 4x4 coordinates","period_blocks":"reset each block; final short block uses its own length","endpoint":"TAB LF CR, ASCII32..126, and E28093/E28094/E28098/E28099/E280A6; terminal state0","symmetry_breaking":False},"z3":{"version":z3.get_version_string(),"dependency":deps},"source_hashes":{"bifid16.py":sha(HERE/"bifid16.py"),"controls.py":sha(Path(__file__)),"legacy_php":sha(HERE/"source/functions.bifid.php"),"dependency_json":sha(HERE/"dependency/dependency.json"),"libz3":sha(HERE/"dependency/runtime/z3/lib/libz3.dylib"),"attempts.json":sha(HERE/"attempts.json")},"concrete_roundtrips":roundtrips,"frozen12_exhaustive":{"period":short_period,"plaintext_hex":short_plain.hex(),"ciphertext_hex":short_cipher.hex(),"truth_square":truth,"fixed_symbol_positions":fixed,"bruteforce_models":brute,"smt_models":smt,"model_count":len(smt),"complete":True,"sets_equal":True},"fixed_truth_square_short":{"status":"sat","plaintext_hex":fixed_plain.hex(),"equals_concrete":True},"deliberate_contradiction":{"status":"unsat","constraint":"k_0=0 and k_1=0 under AllDifferent"},"full_length_period31":full,"incomplete_attempts":attempts["attempts"],"smt_dump":{"path":"full_plant.smt2","sha256":sha(HERE/"full_plant.smt2"),"checked_unknown_square_status":"unknown"},"assertions":{"completed_controls_passed":True,"roundtrip_cases":len(roundtrips)==48,"frozen12_all24_considered":len(brute)<=24 and len(smt)<=24,"frozen12_complete_sets_equal":True,"fixed_truth_plaintext_equal":True,"contradiction_unsat":True,"full_fixed_truth_plaintext_equal":True,"full_unknown_timeout_not_negative":True}}
 if OUT.exists():raise SystemExit("refusing existing controls.json")
 OUT.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n");print(json.dumps({"identity":"ASTRA","output_sha256":sha(OUT),"frozen12_models":len(smt),"full_unknown":"unknown","full_fixed":str(fixed_status),"attempts":attempts["attempts"]},indent=2))

if __name__=="__main__":main()

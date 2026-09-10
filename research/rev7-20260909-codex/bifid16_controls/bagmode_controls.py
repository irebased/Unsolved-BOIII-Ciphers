#!/usr/bin/env python3
import hashlib,itertools,json,random,time
from pathlib import Path
import bifid16 as b
import bagmode as bm
z3=b.z3;HERE=Path(__file__).resolve().parent;OUT=HERE/"bagmode_controls.json";SEED=20260911
BAGS={165:frozenset([9,10,13,*range(32,127),*range(0x80,0xC0),0xC2,0xC3,0xE2]),213:frozenset([9,10,13,*range(32,127),*range(0x80,0xC0),*range(0xC2,0xF5)])}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def sq(r):x=list(range(16));r.shuffle(x);return x
def plant(n):
 unit=b"Bag mode "+bytes.fromhex("e28093e28094e28098")+b"x"+bytes.fromhex("e28099e280a6")+b"\t\r\n";return (unit*(n//len(unit)+1))[:n]
def modelrow(s,k,p,cipher,period,bag,prefix):
 status=s.check();row={"status":str(status),"reason_unknown":s.reason_unknown() if status==z3.unknown else None,"timeout_ms":10000,"prefix_bytes":prefix,"bag":bag,"classified_as_negative":status==z3.unsat}
 if status==z3.sat:
  m=s.model();square=bm.square(m,k);plain=bm.plaintext(m,p);assert b.decrypt_bytes(cipher,square,period)==plain and b.encrypt_bytes(plain,square,period)==cipher and all(x in BAGS[bag] for x in plain[:prefix]);row.update({"square":square,"plaintext_hex":plain.hex(),"plaintext_sha256":hashlib.sha256(plain).hexdigest(),"prefix_bag_valid":True,"full_concrete_roundtrip":True})
 return row
def main():
 rng=random.Random(SEED);truth=sq(rng);pos=[0]*16
 for i,s in enumerate(truth):pos[s]=i
 fixed={s:pos[s] for s in range(12)};remain_s=list(range(12,16));remain_p=sorted(set(range(16))-set(fixed.values()));short_plain=plant(24);short_period=5;short_cipher=b.encrypt_bytes(short_plain,truth,short_period);reduced=[]
 for bag in (165,213):
  brute=[]
  for perm in itertools.permutations(remain_p):
   pm=dict(fixed);pm.update(zip(remain_s,perm));square=[None]*16
   for symbol,position in pm.items():square[position]=symbol
   plain=b.decrypt_bytes(short_cipher,square,short_period)
   if all(x in BAGS[bag] for x in plain):brute.append({"square":square,"plaintext_hex":plain.hex()})
  solver,k,p,be,limit=bm.build(short_cipher,short_period,bag,fixed=fixed,timeout_ms=10000);models=[]
  while True:
   status=solver.check()
   if status==z3.unsat:break
   assert status==z3.sat
   m=solver.model();square=bm.square(m,k);plain=bm.plaintext(m,p);assert all(x in BAGS[bag] for x in plain) and b.encrypt_bytes(plain,square,short_period)==short_cipher;models.append({"square":square,"plaintext_hex":plain.hex()});solver.add(z3.Or(*[k[s]!=m.eval(k[s]) for s in range(16)]))
  assert sorted(brute,key=lambda x:x["square"])==sorted(models,key=lambda x:x["square"]);reduced.append({"bag":bag,"fixed_positions":fixed,"truth_square":truth,"ciphertext_hex":short_cipher.hex(),"bruteforce_models":brute,"smt_models":models,"model_count":len(models),"all24_considered":True,"complete_sets_equal":True})
 full_truth=sq(rng);full_plain=plant(546);period=31;full_cipher=b.encrypt_bytes(full_plain,full_truth,period);fpos=[0]*16
 for i,s in enumerate(full_truth):fpos[s]=i
 fixed_full=[]
 for bag in (165,213):
  solver,k,p,be,limit=bm.build(full_cipher,period,bag,fixed={s:fpos[s] for s in range(16)},timeout_ms=10000);row=modelrow(solver,k,p,full_cipher,period,bag,546);assert row["status"]=="sat" and bytes.fromhex(row["plaintext_hex"])==full_plain;fixed_full.append(row)
 unknown=[]
 short48_plain=plant(48);short48_truth=sq(rng);short48_cipher=b.encrypt_bytes(short48_plain,short48_truth,5)
 for bag in (165,213):
  solver,k,p,be,limit=bm.build(short48_cipher,5,bag,prefix_bytes=48,timeout_ms=10000);row=modelrow(solver,k,p,short48_cipher,5,bag,48);assert row["status"]=="sat";unknown.append({"fixture":"short48",**row})
 for bag in (165,213):
  for prefix in (64,128):
   solver,k,p,be,limit=bm.build(full_cipher,period,bag,prefix_bytes=prefix,timeout_ms=10000)
   if bag==165 and prefix==128:(HERE/"bagmode_prefix128.smt2").write_text(solver.sexpr())
   row=modelrow(solver,k,p,full_cipher,period,bag,prefix);unknown.append({"fixture":"full546_prefix",**row})
 result={"identity":"ASTRA","target_evaluated":False,"rev7_read":False,"mode":"QF_BV arbitrary-square Bifid byte-bag relaxation","bags":{"165":sorted(BAGS[165]),"213":sorted(BAGS[213])},"semantics":{"unsat":"proof that the constrained prefix cannot satisfy the selected necessary byte bag","sat":"compatible prefix only; not UTF-8 and not plaintext recovery","unknown":"unresolved; never negative","symmetry_breaking":False},"source_hashes":{"bagmode.py":sha(HERE/"bagmode.py"),"bagmode_controls.py":sha(Path(__file__)),"bifid16.py":sha(HERE/"bifid16.py"),"dependency_json":sha(HERE/"dependency/dependency.json"),"libz3":sha(HERE/"dependency/runtime/z3/lib/libz3.dylib")},"reduced12_exhaustive":reduced,"full_fixed_truth":fixed_full,"unknown_square_states":unknown,"smt_dump":{"path":"bagmode_prefix128.smt2","sha256":sha(HERE/"bagmode_prefix128.smt2")},"assertions":{"all_completed_controls_passed":True,"reduced24_complete_sets_equal":all(x["complete_sets_equal"] for x in reduced),"full_fixed_truth_exact":True,"short48_unknown_square_sat":all(x["status"]=="sat" for x in unknown if x["fixture"]=="short48"),"all_states_retained":True}}
 if OUT.exists():raise SystemExit("refusing existing output")
 OUT.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n");print(json.dumps({"identity":"ASTRA","sha256":sha(OUT),"reduced_counts":[x["model_count"] for x in reduced],"unknown_states":[(x["fixture"],x["bag"],x["prefix_bytes"],x["status"]) for x in unknown]},indent=2))
if __name__=="__main__":main()

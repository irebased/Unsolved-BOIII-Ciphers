#!/usr/bin/env python3
"""ASTRA independent fixture/model audit for the frozen Bifid16 ledgers.

This reconstructs deterministic synthetic inputs and checks retained models.  It
never reruns the deliberately unresolved unknown-square searches and never reads
Rev7.
"""
from __future__ import annotations
import argparse, hashlib, itertools, json, random, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import symmetry_probe as probe
import bifid16
import bagmode
z3 = bifid16.z3
IDENTITY = "ASTRA"
BAGS = {
    165: frozenset([9,10,13,*range(32,127),*range(0x80,0xC0),0xC2,0xC3,0xE2]),
    213: frozenset([9,10,13,*range(32,127),*range(0x80,0xC0),*range(0xC2,0xF5)]),
}
PINNED = {
    "controls.json": "b95abb4c6bc3c129e64be79bea69bfa9e812bb62f7451b898bd664cfff0dc899",
    "bagmode_controls.json": "380c7e0573e7e541e19d66331847e5d71c2f8ee6bc735d6b8aa9dbf45ce311bb",
    "attempts.json": "27cdfa1b928d010da9c39ffc0c65fb4b597c9d4c2abeb1ba3b4a1b72d6c1c528",
    "bifid16.py": "a80c5f839511454a11a473cbfa4734bf3452656c8015e15ac759f65f45bf9af7",
    "bagmode.py": "ec21d22691016d2a331a0c8a14c0573306b88ac6db772c8a6c5de64409597e06",
    "controls.py": "670f824070f47d1cc05bf4221e8f45ca152302b880fe56238b6e279a7fae6ead",
    "bagmode_controls.py": "6aa56ea3298ab53b6a862a724b481d9078f529dee569d0b5bb4e438e4326dda8",
    "symmetry_probe.py": "8bf072deccafabe1e98db126178207d9cf3c8eccdcab6902a28b0c0d123a26e0",
    "dependency/dependency.json": "e88e7bf34243264705ca5fcaa66acb5c9db96f289192a862e0e063a915897e4e",
    "dependency/runtime/z3/lib/libz3.dylib": "3164e079c221c23a843396a485a6e912ee423918ee64ea03943e584305439a98",
    "source/functions.bifid.php": "fb4542ac9e3320d83cb41020a8548842e7f8850c24674a1399dc28b210c0234c",
}

def sha_bytes(x: bytes) -> str: return hashlib.sha256(x).hexdigest()
def sha_path(p: Path) -> str: return sha_bytes(p.read_bytes())
def square(rng):
    x=list(range(16)); rng.shuffle(x); return x
def sqs(x): return ''.join(format(v,'X') for v in x)
def bs(x): return bytes.fromhex(x)
def audit_decode(cipher: bytes, square_value, period: int) -> bytes:
    return bytes.fromhex(probe.decode(cipher.hex().upper(), sqs(square_value), period))
def audit_encode(plain: bytes, square_value, period: int) -> bytes:
    return bytes.fromhex(probe.encode(plain.hex().upper(), sqs(square_value), period))
def bag_plant(n):
    unit=b"Bag mode "+bytes.fromhex("e28093e28094e28098")+b"x"+bytes.fromhex("e28099e280a6")+b"\t\r\n"
    return (unit*(n//len(unit)+1))[:n]
def exact_plant(n):
    unit=b"ASTRA Bifid 16 control:\tline\r\n"+bytes.fromhex("e28093e28094e28098")+b"x"+bytes.fromhex("e28099e280a6")
    out=bytearray()
    while len(out)+len(unit)<=n: out.extend(unit)
    out.extend(b"Z"*(n-len(out)))
    return bytes(out)
def square_from_positions(pm):
    out=[None]*16
    for symbol,position in pm.items(): out[position]=symbol
    assert sorted(out)==list(range(16))
    return out

def reconstruct_bag_fixtures():
    rng=random.Random(20260911)
    short_truth=square(rng)
    pos=[0]*16
    for i,s in enumerate(short_truth): pos[s]=i
    fixed={s:pos[s] for s in range(12)}
    short_plain=bag_plant(24)
    short_cipher=audit_encode(short_plain,short_truth,5)
    full_truth=square(rng); full_plain=bag_plant(546)
    full_cipher=audit_encode(full_plain,full_truth,31)
    short48_truth=square(rng); short48_plain=bag_plant(48)
    short48_cipher=audit_encode(short48_plain,short48_truth,5)
    return {
      "short24":{"period":5,"truth_square":short_truth,"plaintext_hex":short_plain.hex(),"ciphertext_hex":short_cipher.hex()},
      "full546":{"period":31,"truth_square":full_truth,"plaintext_hex":full_plain.hex(),"ciphertext_hex":full_cipher.hex()},
      "short48":{"period":5,"truth_square":short48_truth,"plaintext_hex":short48_plain.hex(),"ciphertext_hex":short48_cipher.hex()},
      "fixed_positions":fixed,
    }

def reconstruct_exact_fixtures():
    rng=random.Random(20260910)
    for period in (1,2,3,5,16,31):
      for n in (1,2,3,7,16,17,31,33):
        square(rng)
        for _ in range(n): rng.randrange(256)
    short_truth=square(rng); short_plain="Short – text!\n".encode(); short_cipher=audit_encode(short_plain,short_truth,5)
    pos=[0]*16
    for i,s in enumerate(short_truth): pos[s]=i
    full_truth=square(rng); full_plain=exact_plant(546); full_cipher=audit_encode(full_plain,full_truth,31)
    return {
      "short":{"period":5,"truth_square":short_truth,"plaintext_hex":short_plain.hex(),"ciphertext_hex":short_cipher.hex(),"fixed_positions":{s:pos[s] for s in range(12)}},
      "full546":{"period":31,"truth_square":full_truth,"plaintext_hex":full_plain.hex(),"ciphertext_hex":full_cipher.hex()},
    }

def canon_models(rows):
    return sorted((tuple(x["square"]),x["plaintext_hex"]) for x in rows)

def build_audit():
    for rel,want in PINNED.items(): assert sha_path(HERE/rel)==want,(rel,sha_path(HERE/rel),want)
    bag=json.loads((HERE/'bagmode_controls.json').read_text())
    exact=json.loads((HERE/'controls.json').read_text())
    bf=reconstruct_bag_fixtures(); ef=reconstruct_exact_fixtures()
    # Directly validate the compact QF_BV range predicates against literal bags.
    predicate_checks={}
    for bag_id,allowed_values in BAGS.items():
      got=[]
      for v in range(256):
        e=z3.simplify(bagmode.allowed(z3.BitVecVal(v,8),bag_id))
        if z3.is_true(e): got.append(v)
        else: assert z3.is_false(e)
      assert frozenset(got)==allowed_values
      predicate_checks[str(bag_id)]={"all_256_checked":True,"accepted_count":len(got),"accepted_sha256":sha_bytes(bytes(got))}
    # Independently enumerate all 24 remaining square completions via probe.py.
    reduced=[]; fixed=bf['fixed_positions']; remain_s=list(range(12,16)); remain_p=sorted(set(range(16))-set(fixed.values()))
    short_cipher=bs(bf['short24']['ciphertext_hex'])
    for bag_id in (165,213):
      oracle=[]; fixed_smt=[]
      for perm in itertools.permutations(remain_p):
        pm=dict(fixed);pm.update(zip(remain_s,perm)); sqv=square_from_positions(pm)
        plain=audit_decode(short_cipher,sqv,5)
        if all(v in BAGS[bag_id] for v in plain): oracle.append({"square":sqv,"plaintext_hex":plain.hex()})
        # Fully fixed QF_BV instance checks the actual SMT relation without search.
        solver,k,p,_,_=bagmode.build(short_cipher,5,bag_id,fixed=pm,timeout_ms=10000)
        st=solver.check(); assert st in (z3.sat,z3.unsat)
        assert (st==z3.sat)==all(v in BAGS[bag_id] for v in plain)
        fixed_smt.append(str(st))
      saved=next(x for x in bag['reduced12_exhaustive'] if x['bag']==bag_id)
      assert saved['ciphertext_hex']==bf['short24']['ciphertext_hex']
      assert canon_models(saved['bruteforce_models'])==canon_models(oracle)==canon_models(saved['smt_models'])
      reduced.append({"bag":bag_id,"all24_oracle_count":24,"accepted_count":len(oracle),"complete_saved_sets_equal":True,"fully_fixed_qfbv_sat":fixed_smt.count('sat'),"fully_fixed_qfbv_unsat":fixed_smt.count('unsat'),"accepted_models_sha256":sha_bytes(json.dumps(canon_models(oracle),separators=(',',':')).encode())})
    # Recompute every retained bag-mode SAT plaintext from its recorded square.
    sat_rows=[]
    full_cipher=bs(bf['full546']['ciphertext_hex']); short48_cipher=bs(bf['short48']['ciphertext_hex'])
    for row in bag['full_fixed_truth']:
      assert row['status']=='sat'; plain=audit_decode(full_cipher,row['square'],31)
      assert plain.hex()==row['plaintext_hex'] and audit_encode(plain,row['square'],31)==full_cipher
      assert all(v in BAGS[row['bag']] for v in plain[:row['prefix_bytes']])
      sat_rows.append({"fixture":"full_fixed_truth","bag":row['bag'],"prefix_bytes":row['prefix_bytes'],"square":row['square'],"plaintext_sha256":sha_bytes(plain),"ciphertext_sha256":sha_bytes(full_cipher),"independent_roundtrip":True})
    for row in bag['unknown_square_states']:
      assert row['status']=='sat'
      if row['fixture']=='short48': cipher,period=short48_cipher,5
      else: cipher,period=full_cipher,31
      plain=audit_decode(cipher,row['square'],period)
      assert plain.hex()==row['plaintext_hex'] and audit_encode(plain,row['square'],period)==cipher
      assert all(v in BAGS[row['bag']] for v in plain[:row['prefix_bytes']])
      sat_rows.append({"fixture":row['fixture'],"bag":row['bag'],"prefix_bytes":row['prefix_bytes'],"square":row['square'],"plaintext_sha256":sha_bytes(plain),"ciphertext_sha256":sha_bytes(cipher),"independent_roundtrip":True})
    # Independently reconstruct the older exact-endpoint fixtures and 24 completions.
    old=exact['frozen12_exhaustive']; assert old['ciphertext_hex']==ef['short']['ciphertext_hex'] and old['truth_square']==ef['short']['truth_square']
    fixed=ef['short']['fixed_positions']; remain_p=sorted(set(range(16))-set(fixed.values())); oracle=[]
    cipher=bs(ef['short']['ciphertext_hex'])
    for perm in itertools.permutations(remain_p):
      pm=dict(fixed);pm.update(zip(range(12,16),perm)); sqv=square_from_positions(pm); plain=audit_decode(cipher,sqv,5)
      if bifid16.endpoint_accepts(plain): oracle.append({"square":sqv,"plaintext_hex":plain.hex()})
    assert canon_models(oracle)==canon_models(old['bruteforce_models'])==canon_models(old['smt_models'])
    oldfull=exact['full_length_period31']; fc=bs(ef['full546']['ciphertext_hex']); fp=bs(oldfull['fixed_truth_check']['plaintext_hex'])
    assert oldfull['ciphertext_hex']==ef['full546']['ciphertext_hex']; assert fp==audit_decode(fc,ef['full546']['truth_square'],31)==bs(ef['full546']['plaintext_hex']); assert audit_encode(fp,ef['full546']['truth_square'],31)==fc
    attempts=json.loads((HERE/'attempts.json').read_text()); assert [x['status'] for x in attempts['attempts']]==['unknown','interrupted','unknown']; assert all(not x['classified_as_negative'] for x in attempts['attempts'])
    return {
      "identity":IDENTITY,"target_evaluated":False,"rev7_read":False,
      "purpose":"independent reconstruction and retained-model audit of frozen synthetic ledgers",
      "source_hashes":{**PINNED,"audit_controls.py":sha_path(Path(__file__))},
      "fixtures":{"bag_seed":20260911,"bag":bf,"exact_seed":20260910,"exact":ef},
      "qfbv_allowed_predicates":predicate_checks,
      "bag_reduced24":reduced,"bag_saved_sat_models":sat_rows,
      "exact_endpoint":{"all24_oracle_count":24,"accepted_count":len(oracle),"complete_saved_sets_equal":True,"fixed_full_plaintext_sha256":sha_bytes(fp),"fixed_full_ciphertext_sha256":sha_bytes(fc),"fixed_full_roundtrip":True},
      "unresolved_attempts":[{"period":x['period'],"status":x['status'],"timeout_ms":x.get('timeout_ms'),"classified_as_negative":False} for x in attempts['attempts']],
      "assertions":{"all_source_pins_match":True,"all_256_bag_predicates_match":True,"all_reduced24_independently_enumerated":True,"all_48_fully_fixed_qfbv_checks_match":True,"all_8_saved_bag_sat_models_roundtrip":len(sat_rows)==8,"old_exact_reduced24_matches":True,"old_exact_fixed_full_matches":True,"unknown_searches_not_rerun":True}
    }

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args(); built=build_audit()
    if a.regenerate:
      out=a.regenerate
      if out.exists(): raise SystemExit(f'refusing existing output: {out}')
      out.write_text(json.dumps(built,sort_keys=True,indent=2)+'\n'); print(json.dumps({"identity":IDENTITY,"written":str(out),"sha256":sha_path(out)})); return
    out=HERE/'audit.json'; saved=json.loads(out.read_text()); assert saved==json.loads(json.dumps(built))
    print(json.dumps({"identity":IDENTITY,"ok":True,"audit_sha256":sha_path(out),"bag_model_counts":[x['accepted_count'] for x in built['bag_reduced24']],"saved_sat_models":len(built['bag_saved_sat_models']),"unresolved":[x['status'] for x in built['unresolved_attempts']],"target_evaluated":False},sort_keys=True))
if __name__=='__main__': main()

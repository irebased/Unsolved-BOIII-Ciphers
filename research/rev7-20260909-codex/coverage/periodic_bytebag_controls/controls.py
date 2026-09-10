#!/usr/bin/env python3
"""Synthetic controls and read-only verifier for periodic byte-bag masks."""
from __future__ import annotations
import argparse,hashlib,json,random
from pathlib import Path
import model
HERE=Path(__file__).resolve().parent;LEDGER=HERE/"controls.json";SEED=20260910
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def canonical(o):return (json.dumps(o,sort_keys=True,indent=2)+"\n")
def plant_bytes():
 rng=random.Random(SEED);words=[];n=0
 while n<546:
  word=model.CODEWORDS[rng.randrange(len(model.CODEWORDS))]
  if len(word)>546-n:word=b"X"
  words.append(word);n+=len(word)
 out=b"".join(words);assert len(out)==546 and any(x>=128 for x in out) and any(32<=x<=126 for x in out);return out
def key_for(period):
 out=bytearray();counter=0
 while len(out)<period:
  out.extend(hashlib.sha256(f"ASTRA periodic bytebag key|{period}|{counter}".encode()).digest());counter+=1
 return bytes(out[:period])
def encrypt(plain,key,operation):
 if operation=="xor":return bytes(x^key[i%len(key)] for i,x in enumerate(plain))
 if operation=="subtract":return bytes((x+key[i%len(key)])&255 for i,x in enumerate(plain))
 raise ValueError(operation)
def masks_record(masks):
 return [{"residue":i,"mask_hex":model.mask_hex(m),"candidate_count":bin(m).count("1"),"candidates":model.mask_values(m)} for i,m in enumerate(masks)]
def build():
 assert len(model.CODEPOINTS)==201 and len(model.BYTE_BAG)==165
 expected_bag=set([9,10,13,*range(32,127),*range(128,192),0xc2,0xc3,0xe2]);assert model.BYTE_BAG==expected_bag
 plain=plant_bytes();rows=[]
 for period in (1,2,3,8,31,64):
  key=key_for(period)
  for operation in model.OPERATIONS:
   cipher=encrypt(plain,key,operation)
   base_hex=cipher.hex().upper()
   for orientation in model.ORIENTATIONS:
    canonical_hex=model.orient_hex(base_hex,orientation);recovered=bytes.fromhex(model.orient_hex(canonical_hex,orientation));assert recovered==cipher
    fast=model.residue_masks_fast(recovered,period,operation);slow=model.residue_masks_slow(recovered,period,operation);assert fast==slow
    assert all(fast[r]>>(key[r])&1 for r in range(period))
    shuffled=bytearray(len(recovered))
    for r in range(period):
     vals=list(recovered[r::period]);vals.reverse();shuffled[r::period]=vals
    assert model.residue_masks_fast(bytes(shuffled),period,operation)==fast
    doubled=bytes(x for v in recovered for x in (v,v))
    # Duplication changes residue assignment except period 1, so only test direct column duplicate below.
    for r in range(period):
     col=recovered[r::period];assert model.residue_masks_fast(col+col,1,operation)[0]==fast[r]
    rows.append({"period":period,"operation":operation,"orientation":orientation,"canonical_hex_sha256":hashlib.sha256(canonical_hex.encode()).hexdigest(),"recovered_ciphertext_sha256":hashlib.sha256(recovered).hexdigest(),"truth_key_hex":key.hex(),"masks":masks_record(fast),"all_truth_key_bytes_retained":True,"fast_equals_slow":True,"within_residue_order_invariant":True,"duplicate_observation_invariant":True})
 vacuous=[]
 for q in (1,8):
  for op in model.OPERATIONS:
   masks=model.residue_masks_fast(b"",q,op);assert masks==(model.ALL,)*q and masks==model.residue_masks_slow(b"",q,op);vacuous.append({"period":q,"operation":op,"masks":masks_record(masks)})
 negative=[]
 data=bytes(range(256))
 for op in model.OPERATIONS:
  f=model.residue_masks_fast(data,1,op);s=model.residue_masks_slow(data,1,op);assert f==s==(0,);negative.append({"operation":op,"input_sha256":hashlib.sha256(data).hexdigest(),"mask_hex":model.mask_hex(f[0]),"candidate_count":0})
 counter_cipher=b"AA";counter_key=bytes([0,1]);counter_plain=bytes(x^counter_key[i] for i,x in enumerate(counter_cipher));assert counter_plain==bytes.fromhex("4140") and all(x in model.BYTE_BAG for x in counter_plain)
 result={"identity":"ASTRA","target_evaluated":False,"rev7_read":False,"model":{"codepoint_count":len(model.CODEPOINTS),"codepoints":[f"U+{x:04X}" for x in model.CODEPOINTS],"codeword_hex":[x.hex() for x in model.CODEWORDS],"byte_bag":[*sorted(model.BYTE_BAG)],"byte_bag_count":len(model.BYTE_BAG),"operations":list(model.OPERATIONS),"periods":[1,2,3,8,31,64],"orientations":list(model.ORIENTATIONS)},"plant":{"seed":SEED,"plaintext_hex":plain.hex(),"plaintext_sha256":hashlib.sha256(plain).hexdigest(),"length":len(plain)},"grid":rows,"vacuous_empty_input":vacuous,"negative_full_byte_column":negative,"fixed_mapping_counterexample":{"ciphertext_ascii":"AA","ciphertext_hex":counter_cipher.hex(),"xor_key_hex":counter_key.hex(),"plaintext_hex":counter_plain.hex(),"plaintext_ascii":"A@","meaning":"The same ciphertext byte can map to different allowed plaintext bytes in different key residues."},"source_hashes":{"model.py":sha(HERE/"model.py"),"controls.py":sha(Path(__file__))},"assertions":{"all_passed":True,"literal_201_codewords":True,"byte_union_165":True,"grid_cells":len(rows)==48,"all_masks_equal_slow_reference":all(x["fast_equals_slow"] for x in rows),"truth_keys_retained":all(x["all_truth_key_bytes_retained"] for x in rows),"vacuous_columns_all256":True,"negative_columns_empty":True}}
 return result
def main():
 p=argparse.ArgumentParser();p.add_argument("--regenerate",type=Path);a=p.parse_args();got=build()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit(f"refusing existing output: {a.regenerate}")
  a.regenerate.write_text(canonical(got));print(json.dumps({"ok":True,"output":str(a.regenerate),"sha256":sha(a.regenerate)}));return
 assert got==json.loads(LEDGER.read_text());print(json.dumps({"ok":True,"identity":"ASTRA","target_evaluated":False,"ledger_sha256":sha(LEDGER),"grid_cells":len(got["grid"]),"codewords":201,"byte_bag":165}))
if __name__=="__main__":main()

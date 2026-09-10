#!/usr/bin/env python3
"""Synthetic-only exhaustive controls for nibble-additive masks."""
from __future__ import annotations
import argparse,hashlib,json,random,sys
from pathlib import Path
import model
HERE=Path(__file__).resolve().parent;K44=HERE.parent;LEDGER=HERE/"controls.json"
sys.path.insert(0,str(K44));import geometry
MODEL_BYTEBAG_SHA="bce745611e7a9b91d6471b348587c4f9af84ad39ffddae1c148a2ab5a670a444"
GEOMETRY_SHA="cad6c29e75cc1d43ba9f43d172767c081bed8b0394ce5ae7c8adee3e22427e61"
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,indent=2)+"\n"
def plant(m):
 rng=random.Random(2026091100+m);words=list(model.CODEWORDS);rng.shuffle(words);out=bytearray().join(words)
 while len(out)<546:
  w=model.CODEWORDS[rng.randrange(len(model.CODEWORDS))]
  if len(out)+len(w)>546:w=b"X"
  out.extend(w)
 b=bytes(out);assert len(b)==546 and set(model.CODEPOINTS)<=set(map(ord,b.decode("utf-8")));return b

def nibble_key(m,op):
 out=bytearray();i=0
 while len(out)<m:
  out.extend(hashlib.sha256(f"ASTRA nibble-additive|{m}|{op}|{i}".encode()).digest());i+=1
 return bytes(x&15 for x in out[:m])
def encrypt_hex(plain,key,op):
 digits=[]
 for b in plain:digits.extend((b>>4,b&15))
 enc=[]
 for i,p in enumerate(digits):
  k=key[i%len(key)]
  enc.append((p+k)&15 if op=="subtract" else (k-p)&15)
 return bytes((enc[i]<<4)|enc[i+1] for i in range(0,len(enc),2))
def paired_truth_keys(key,nbytes):
 m=len(key);return tuple((key[(2*j)%m]<<4)|key[(2*j+1)%m] for j in range(nbytes))
def rows_masks(ms):return [{"residue":i,"mask_hex":model.mask_hex(v),"candidate_count":bin(v).count("1"),"candidates":model.mask_values(v)} for i,v in enumerate(ms)]
def build():
 assert sha(model.PBC/"model.py")==MODEL_BYTEBAG_SHA and sha(K44/"geometry.py")==GEOMETRY_SHA
 local=[]
 for op in model.OPERATIONS:
  memberships=0
  digest=hashlib.sha256()
  for c in range(256):
   mask=model.candidate_mask(c,op)
   explicit=0
   for k in range(256):
    allowed=model.decrypt_byte(c,k,op) in model.BYTE_BAG
    if allowed:explicit|=1<<k;memberships+=1
    assert model.decrypt_byte(model.encrypt_byte(model.decrypt_byte(c,k,op),k,op),k,op)==model.decrypt_byte(c,k,op)
   assert mask==explicit
   digest.update(mask.to_bytes(32,"big"))
  local.append({"operation":op,"cipher_values":256,"keys_per_cipher":256,"pairs_checked":65536,"allowed_memberships":memberships,"mask_table_sha256":digest.hexdigest(),"candidate_masks_equal_explicit":True})
 cells=[];plants=[]
 for m in (19,38,57):
  plain=plant(m);plants.append({"hex_key_period":m,"plaintext_hex":plain.hex(),"plaintext_sha256":hashlib.sha256(plain).hexdigest(),"contains_all_201_codepoints":True})
  q=model.paired_period(m)
  for op in model.OPERATIONS:
   key=nibble_key(m,op);cipher=encrypt_hex(plain,key,op);display=geometry.encode(cipher.hex().upper());restored=bytes.fromhex(geometry.decode(display));assert restored==cipher
   truth=paired_truth_keys(key,len(cipher));assert all(truth[j]==truth[j%q] for j in range(len(truth)))
   fast=model.residue_masks_fast(restored,q,op);slow=model.residue_masks_slow(restored,q,op);assert fast==slow
   assert all((fast[r]>>truth[r])&1 for r in range(q))
   cells.append({"cell_id":f"m{m}_{op}","hex_key_period":m,"sufficient_paired_byte_period":q,"operation":op,"nibble_key_hex":"".join(format(x,"x") for x in key),"paired_truth_key_hex":bytes(truth[:q]).hex(),"displayed_sha256":hashlib.sha256(display.encode()).hexdigest(),"restored_cipher_sha256":hashlib.sha256(restored).hexdigest(),"amsco_roundtrip_exact":True,"fast_equals_slow":True,"truth_paired_keys_retained":True,"odd_period_independent_residue_relaxation":m%2==1,"masks":rows_masks(fast)})
 return {"identity":"ASTRA","target_evaluated":False,"rev7_read":False,"scope":{"hex_key_periods":[19,38,57],"operations":list(model.OPERATIONS),"cells":6,"endpoint_codepoints":201,"necessary_byte_bag":165,"period_mapping":"m/gcd(m,2); for odd m, independently choosing paired-byte residue keys is a superset of nibble-key-consistent assignments"},"local_exhaustive":local,"plants":plants,"cells":cells,"source_hashes":{"model.py":sha(HERE/"model.py"),"controls.py":sha(Path(__file__)),"geometry.py":sha(K44/"geometry.py"),"periodic_bytebag_model.py":sha(model.PBC/"model.py")},"assertions":{"all_passed":True,"local_pairs_per_operation_65536":all(x["pairs_checked"]==65536 for x in local),"all_six_cells":len(cells)==6,"fast_slow_equal":all(x["fast_equals_slow"] for x in cells),"truth_retained":all(x["truth_paired_keys_retained"] for x in cells)}}
def main():
 p=argparse.ArgumentParser();p.add_argument("--regenerate",type=Path);a=p.parse_args();got=build()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit(f"refusing existing output: {a.regenerate}")
  a.regenerate.write_text(canonical(got));print(json.dumps({"identity":"ASTRA","output":str(a.regenerate),"sha256":sha(a.regenerate),"cells":6}));return
 assert got==json.loads(LEDGER.read_text());print(json.dumps({"identity":"ASTRA","verified":True,"ledger_sha256":sha(LEDGER),"local_pairs":131072,"cells":6}))
if __name__=="__main__":main()

#!/usr/bin/env python3
"""ASTRA synthetic controls for the exact Kasiski44 periodic-byte follow-up."""
from __future__ import annotations
import argparse,hashlib,json,random,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
K44=HERE.parent
PBC=HERE.parents[1]/"periodic_bytebag_controls"
sys.path.insert(0,str(K44));import geometry
sys.path.insert(0,str(PBC));import model
IDENTITY="ASTRA";PERIODS=(19,38,57);OPERATIONS=("xor","subtract");LEDGER=HERE/"controls.json"
MODEL_SHA="bce745611e7a9b91d6471b348587c4f9af84ad39ffddae1c148a2ab5a670a444"
GEOMETRY_SHA="cad6c29e75cc1d43ba9f43d172767c081bed8b0394ce5ae7c8adee3e22427e61"
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,indent=2)+"\n"
def plant(period):
 rng=random.Random(2026091000+period);words=list(model.CODEWORDS);rng.shuffle(words);out=bytearray().join(words)
 while len(out)<546:
  word=model.CODEWORDS[rng.randrange(len(model.CODEWORDS))]
  if len(out)+len(word)>546:word=b"X"
  out.extend(word)
 result=bytes(out);assert len(result)==546
 assert set(model.CODEPOINTS)<=set(map(ord,result.decode("utf-8")));return result
def key_for(period,operation):
 out=bytearray();counter=0
 while len(out)<period:
  out.extend(hashlib.sha256(f"ASTRA K44 periodic control|{period}|{operation}|{counter}".encode()).digest());counter+=1
 return bytes(out[:period])
def encrypt(plain,key,operation):
 if operation=="xor":return bytes(v^key[i%len(key)] for i,v in enumerate(plain))
 if operation=="subtract":return bytes((v+key[i%len(key)])&255 for i,v in enumerate(plain))
 raise ValueError(operation)
def mask_rows(masks):return [{"residue":i,"mask_hex":model.mask_hex(mask),"candidate_count":bin(mask).count("1"),"candidates":model.mask_values(mask)} for i,mask in enumerate(masks)]
def build():
 assert sha(PBC/"model.py")==MODEL_SHA and sha(K44/"geometry.py")==GEOMETRY_SHA
 assert len(model.CODEPOINTS)==201 and len(model.BYTE_BAG)==165
 rows=[];plants=[]
 for period in PERIODS:
  plain=plant(period);plants.append({"period_bytes":period,"plaintext_hex":plain.hex(),"plaintext_sha256":hashlib.sha256(plain).hexdigest(),"length_bytes":len(plain),"contains_all_201_codepoints":True})
  for operation in OPERATIONS:
   key=key_for(period,operation);cipher=encrypt(plain,key,operation);displayed=geometry.encode(cipher.hex().upper());restored_hex=geometry.decode(displayed);restored=bytes.fromhex(restored_hex)
   assert restored==cipher and geometry.encode(restored_hex)==displayed
   fast=model.residue_masks_fast(restored,period,operation);slow=model.residue_masks_slow(restored,period,operation);assert fast==slow
   assert all((fast[r]>>key[r])&1 for r in range(period))
   rows.append({"cell_id":f"p{period}_{operation}","period_bytes":period,"operation":operation,"truth_key_hex":key.hex(),"displayed_hex_sha256":hashlib.sha256(displayed.encode()).hexdigest(),"restored_ciphertext_sha256":hashlib.sha256(restored).hexdigest(),"amsco_encode_decode_exact":True,"fast_equals_slow":True,"truth_key_retained_all_residues":True,"masks":mask_rows(fast)})
 return {"identity":IDENTITY,"target_evaluated":False,"rev7_read":False,"scope":{"pipeline":"periodic byte encryption, uppercase hex, equal-cut-4 ZOMBIES encode; exact decode restores ciphertext","periods_bytes":list(PERIODS),"operations":list(OPERATIONS),"cells":6,"endpoint_codepoints":201,"necessary_byte_bag_size":165},"plants":plants,"cells":rows,"source_hashes":{"controls.py":sha(Path(__file__)),"geometry.py":sha(K44/"geometry.py"),"periodic_model.py":sha(PBC/"model.py")},"assertions":{"all_passed":True,"all_six_cells":len(rows)==6,"all_plants_length_546":all(x["length_bytes"]==546 for x in plants),"all_plants_contain_201_codepoints":all(x["contains_all_201_codepoints"] for x in plants),"all_amsco_roundtrips":all(x["amsco_encode_decode_exact"] for x in rows),"all_fast_slow_equal":all(x["fast_equals_slow"] for x in rows),"all_truth_keys_retained":all(x["truth_key_retained_all_residues"] for x in rows)}}
def main():
 parser=argparse.ArgumentParser();parser.add_argument("--regenerate",type=Path);args=parser.parse_args();got=build()
 if args.regenerate:
  if args.regenerate.exists():raise SystemExit(f"refusing existing output: {args.regenerate}")
  args.regenerate.write_text(canonical(got));print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"output":str(args.regenerate),"sha256":sha(args.regenerate),"cells":6},sort_keys=True));return
 assert LEDGER.exists(),"controls.json absent; use --regenerate NEW_PATH"
 assert got==json.loads(LEDGER.read_text())
 print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"verified":True,"ledger_sha256":sha(LEDGER),"cells":6},sort_keys=True))
if __name__=="__main__":main()

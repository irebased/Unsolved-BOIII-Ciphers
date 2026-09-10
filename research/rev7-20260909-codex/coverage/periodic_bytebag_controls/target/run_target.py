#!/usr/bin/env python3
"""ASTRA registered periodic byte-bag target grid."""
from __future__ import annotations
import argparse,hashlib,itertools,json,math,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;REPO=HERE.parents[4]
sys.path.insert(0,str(PACKAGE));import model
IDENTITY="ASTRA";PERIODS=tuple(range(1,65));OPS=("xor","subtract");ORIENTS=("forward","reverse","byte_reverse","nibble_swap")
MDX=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx";DATASET=REPO/"lavender/src/data/ciphers/revelations.json";OUTPUT=HERE/"target_results.json"
PINS={"model.py":"bce745611e7a9b91d6471b348587c4f9af84ad39ffddae1c148a2ab5a670a444","controls.py":"b6e42385d64ae4750d4832528aebeb8efc8aa64a900fd8343280e605ec35ca11","controls.json":"8e3c80efc2da2a7dce6a10bdf7f55fa12a6d11b594e73fd872148c29969e6bc4","README.md":"6f66f20cf4f69f511957b2216d471bff80b265f2614872db29ee2e8144472fa8","rev7_mdx":"085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91","dataset":"68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e"}
TEXT_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def source_hashes():return {"model.py":sha(PACKAGE/"model.py"),"controls.py":sha(PACKAGE/"controls.py"),"controls.json":sha(PACKAGE/"controls.json"),"README.md":sha(PACKAGE/"README.md"),"rev7_mdx":sha(MDX),"dataset":sha(DATASET)}
def selftest():
 assert source_hashes()==PINS
 c=json.loads((PACKAGE/"controls.json").read_text());assert c["identity"]==IDENTITY and c["target_evaluated"] is False and c["rev7_read"] is False and c["assertions"]["all_passed"]
 return {"identity":IDENTITY,"target_evaluated":False,"handling":"MDX and dataset bytes hashed only; ciphertext not extracted or evaluated","source_hashes":source_hashes(),"scope":{"periods":[1,64],"operations":list(OPS),"orientations":list(ORIENTS),"labeled_cells":512,"unique_existence_contexts":256,"byte_bag_count":165}}
def extract():
 mdx=MDX.read_text();tick=chr(96);start=mdx.index(tick+"83 B57B2")+1;end=mdx.index(tick,start);a="".join(mdx[start:end].split()).upper()
 rows=json.loads(DATASET.read_text());b="".join(next(x for x in rows if x["id"]=="rev7")["ciphertext"].split()).upper()
 assert a==b and len(a)==1092 and hashlib.sha256(a.encode()).hexdigest()==TEXT_SHA;return a
def witness(data,q,op,residue):
 mask=model.ALL;previous=mask
 for index in range(residue,len(data),q):
  previous=mask;mask&=model.candidate_mask(data[index],op)
  if mask==0:return {"residue":residue,"ciphertext_index":index,"ciphertext_byte":data[index],"previous_mask_hex":model.mask_hex(previous),"observation_mask_hex":model.mask_hex(model.candidate_mask(data[index],op))}
 raise AssertionError("requested empty residue never became empty")
def row_record(q,op,orientation,data):
 fast=model.residue_masks_fast(data,q,op);slow=model.residue_masks_slow(data,q,op);assert fast==slow
 counts=[len(model.mask_values(x)) for x in fast];empty=[i for i,x in enumerate(fast) if x==0]
 return {"cell_id":f"q{q:02d}_{op}_{orientation}","period":q,"operation":op,"orientation":orientation,"oriented_bytes_sha256":hashlib.sha256(data).hexdigest(),"masks":[{"residue":i,"mask_hex":model.mask_hex(x),"candidate_count":counts[i],"candidates":model.mask_values(x)} for i,x in enumerate(fast)],"empty_residues":empty,"empty_residue_witnesses":[witness(data,q,op,i) for i in empty],"exists_necessary_key":not empty,"key_count_product":math.prod(counts) if not empty else None,"fast_equals_slow":True}
def run():
 if OUTPUT.exists() or OUTPUT.with_name(OUTPUT.name+".tmp").exists():raise SystemExit("refusing existing target output")
 pre=selftest();value=extract();oriented={name:bytes.fromhex(model.orient_hex(value,name)) for name in ORIENTS};cells=[]
 for q,op,orientation in itertools.product(PERIODS,OPS,ORIENTS):cells.append(row_record(q,op,orientation,oriented[orientation]))
 by={(x["period"],x["operation"],x["orientation"]):x for x in cells};relations=[]
 for q in PERIODS:
  perm=[(545-r)%q for r in range(q)]
  for op,left,right in ((op,a,b) for op in OPS for a,b in (("forward","byte_reverse"),("nibble_swap","reverse"))):
   lm=by[(q,op,left)]["masks"];rm=by[(q,op,right)]["masks"];assert all(lm[r]["mask_hex"]==rm[perm[r]]["mask_hex"] for r in range(q))
   assert by[(q,op,left)]["exists_necessary_key"]==by[(q,op,right)]["exists_necessary_key"] and by[(q,op,left)]["key_count_product"]==by[(q,op,right)]["key_count_product"]
   relations.append({"period":q,"operation":op,"left":left,"right":right,"residue_map":[{"left":r,"right":perm[r]} for r in range(q)],"all_masks_equal_under_permutation":True,"existence_equal":True,"product_equal":True})
 groups=[]
 for op in OPS:
  for representative,paired in (("forward","byte_reverse"),("nibble_swap","reverse")):
   excluded=[q for q in PERIODS if not by[(q,op,representative)]["exists_necessary_key"]];remaining=[q for q in PERIODS if by[(q,op,representative)]["exists_necessary_key"]]
   groups.append({"operation":op,"representative_orientation":representative,"equivalent_orientation":paired,"excluded_periods":excluded,"remaining_periods":remaining,"excluded_count":len(excluded),"remaining_count":len(remaining)})
 result={"identity":IDENTITY,"target_evaluated":True,"scope":{"periods":[1,64],"operations":list(OPS),"orientations":list(ORIENTS),"labeled_cells":512,"unique_existence_contexts":256,"endpoint_codewords":201,"byte_bag_count":165,"interpretation":"empty residue excludes that exact period/orientation/operation under the necessary byte-bag model; nonempty does not imply valid UTF-8"},"source_hashes":source_hashes(),"driver_sha256":sha(Path(__file__)),"normalized_input_sha256":TEXT_SHA,"cells":cells,"reversal_equivalences":relations,"unique_context_summary":groups,"assertions":{"all_512_cells":len(cells)==512,"fast_slow_all_masks":all(x["fast_equals_slow"] for x in cells),"reversal_relations":len(relations)==256 and all(x["all_masks_equal_under_permutation"] for x in relations)}}
 tmp=OUTPUT.with_name(OUTPUT.name+".tmp");tmp.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n");os.replace(tmp,OUTPUT);print(json.dumps({"identity":IDENTITY,"output":str(OUTPUT),"sha256":sha(OUTPUT),"bytes":OUTPUT.stat().st_size,"summaries":groups},indent=2))
def main():
 p=argparse.ArgumentParser();g=p.add_mutually_exclusive_group(required=True);g.add_argument("--selftest",action="store_true");g.add_argument("--run-target",action="store_true");a=p.parse_args()
 print(json.dumps(selftest(),indent=2,sort_keys=True)) if a.selftest else run()
if __name__=="__main__":main()

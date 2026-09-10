#!/usr/bin/env python3
"""Independent saved-result and slow-mask replay for the 512-cell grid."""
import hashlib,itertools,json,math
from pathlib import Path
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;REPO=HERE.parents[4]
RESULT=HERE/"target_results.json";DRIVER=HERE/"run_target.py";MDX=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx";DATASET=REPO/"lavender/src/data/ciphers/revelations.json"
RESULT_SHA="008966a182ee38ff9ffac569e715d91bab8c05cf37ae5c2c6043dc0d6b1c9acc";DRIVER_SHA="6b14c599a1898cd7fd7f993fe99e94cf573efbf22927e7be166081840bf939af"
OPS=("xor","subtract");ORIENTS=("forward","reverse","byte_reverse","nibble_swap");PERIODS=range(1,65)
CODEPOINTS=(9,10,13,*range(0x20,0x7f),*range(0xa0,0x100),0x2013,0x2014,0x2018,0x2019,0x201c,0x201d,0x2026)
BAG=frozenset(b for cp in CODEPOINTS for b in chr(cp).encode());ALL=(1<<256)-1
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def transform(x,k,op):return x^k if op=="xor" else (x-k)&255
def slow(data,q,op):
 out=[]
 for r in range(q):
  col=data[r::q];m=0
  for k in range(256):
   if all(transform(x,k,op) in BAG for x in col):m|=1<<k
  out.append(m)
 return out
def orient(value,name):
 pairs=[value[i:i+2] for i in range(0,len(value),2)]
 return {"forward":value,"reverse":value[::-1],"byte_reverse":"".join(reversed(pairs)),"nibble_swap":"".join(x[::-1] for x in pairs)}[name]
def main():
 assert len(CODEPOINTS)==201 and len(BAG)==165 and sha(RESULT)==RESULT_SHA and sha(DRIVER)==DRIVER_SHA
 result=json.loads(RESULT.read_text());assert result["identity"]=="ASTRA" and result["target_evaluated"] is True
 for rel,h in result["source_hashes"].items():
  p=MDX if rel=="rev7_mdx" else DATASET if rel=="dataset" else PACKAGE/rel
  assert sha(p)==h,(rel,sha(p),h)
 mdx=MDX.read_text();tick=chr(96);start=mdx.index(tick+"83 B57B2")+1;end=mdx.index(tick,start);value="".join(mdx[start:end].split()).upper()
 ds="".join(next(x for x in json.loads(DATASET.read_text()) if x["id"]=="rev7")["ciphertext"].split()).upper();assert value==ds and len(value)==1092 and hashlib.sha256(value.encode()).hexdigest()==result["normalized_input_sha256"]
 oriented={x:bytes.fromhex(orient(value,x)) for x in ORIENTS};expected=list(itertools.product(PERIODS,OPS,ORIENTS));assert len(result["cells"])==512
 assert [(x["period"],x["operation"],x["orientation"]) for x in result["cells"]]==expected
 by={}
 for row in result["cells"]:
  q,op,o=row["period"],row["operation"],row["orientation"];data=oriented[o];assert row["cell_id"]==f"q{q:02d}_{op}_{o}" and row["oriented_bytes_sha256"]==hashlib.sha256(data).hexdigest()
  masks=slow(data,q,op);stored=[int(x["mask_hex"],16) for x in row["masks"]];assert stored==masks
  assert all(x["residue"]==i and x["candidate_count"]==len(x["candidates"])==len([k for k in range(256) if masks[i]>>k&1]) and x["candidates"]==[k for k in range(256) if masks[i]>>k&1] for i,x in enumerate(row["masks"]))
  empty=[i for i,m in enumerate(masks) if not m];assert row["empty_residues"]==empty and row["exists_necessary_key"]==(not empty)
  assert row["key_count_product"]==(math.prod(x["candidate_count"] for x in row["masks"]) if not empty else None)
  assert len(row["empty_residue_witnesses"])==len(empty)
  for w in row["empty_residue_witnesses"]:
   r=w["residue"];mask=ALL
   for index in range(r,w["ciphertext_index"],q):mask&=sum(1<<k for k in range(256) if transform(data[index],k,op) in BAG)
   obs=sum(1<<k for k in range(256) if transform(data[w["ciphertext_index"]],k,op) in BAG)
   assert mask!=0 and f"{mask:064x}"==w["previous_mask_hex"] and f"{obs:064x}"==w["observation_mask_hex"] and mask&obs==0 and data[w["ciphertext_index"]]==w["ciphertext_byte"] and w["ciphertext_index"]%q==r
  by[(q,op,o)]=row
 assert all(not x["exists_necessary_key"] for x in result["cells"])
 assert len(result["reversal_equivalences"])==256
 for rel in result["reversal_equivalences"]:
  q,op,a,b=rel["period"],rel["operation"],rel["left"],rel["right"];perm=[(545-r)%q for r in range(q)]
  assert rel["residue_map"]==[{"left":r,"right":perm[r]} for r in range(q)]
  assert all(by[(q,op,a)]["masks"][r]["mask_hex"]==by[(q,op,b)]["masks"][perm[r]]["mask_hex"] for r in range(q))
 for s in result["unique_context_summary"]:assert s["excluded_periods"]==list(PERIODS) and s["remaining_periods"]==[] and s["excluded_count"]==64 and s["remaining_count"]==0
 print(json.dumps({"ok":True,"identity":"ASTRA","verification":"independent slow per-key mask replay and saved-result integrity","result_sha256":RESULT_SHA,"labeled_cells":512,"unique_existence_contexts":256,"excluded_unique_contexts":256,"remaining_unique_contexts":0},indent=2,sort_keys=True))
if __name__=="__main__":main()

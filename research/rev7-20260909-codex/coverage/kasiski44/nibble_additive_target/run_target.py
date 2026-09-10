#!/usr/bin/env python3
"""ASTRA inert four-cell nibble-additive byte-bag target harness."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,math,os
from pathlib import Path
HERE=Path(__file__).resolve().parent;K44=HERE.parent;REPO=HERE.parents[4]
MODEL=K44/"nibble_additive_controls/model.py";GEOMETRY=K44/"geometry.py"
DATA=REPO/"lavender/src/data/ciphers/revelations.json";MDX=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
GATE=HERE/"target_gate.json";RESULT=HERE/"target_results.json";CELLS=tuple((q,op) for q in (19,57) for op in ("subtract","beaufort"))
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def require_gate():
 if not GATE.exists():raise SystemExit("inert: reviewed target_gate.json is absent")
 gate=json.loads(GATE.read_text());assert gate["identity"]=="ASTRA" and gate["target_authorized"] is True
 assert gate["cells"]==[[q,op] for q,op in CELLS]
 assert gate["scope"]=="equal-cut-4 ZOMBIES decode-forward; independent hexadecimal-digit arithmetic; bag165"
 assert set(gate["artifact_hashes"])==set(gate["required_artifacts"])
 for rel,digest in gate["artifact_hashes"].items():assert sha(REPO/rel)==digest,rel
 return gate
def extract(gate,independent=False):
 assert sha(DATA)==gate["dataset_sha256"] and sha(MDX)==gate["mdx_sha256"]
 rows=json.loads(DATA.read_text());raw="".join(next(x for x in rows if x["id"]=="rev7")["ciphertext"].split()).upper()
 text=MDX.read_text();a=text.index("`83 B57B")+1;b=text.index("`",a);assert raw=="".join(text[a:b].split()).upper()
 assert len(raw)==1092 and hashlib.sha256(raw.encode()).hexdigest()==gate["canonical_hex_sha256"]
 if independent:
  ranks={column:sorted("ZOMBIES").index(letter) for column,letter in enumerate("ZOMBIES")}
  restored="".join(raw[ranks[(i//4)%7]*156+(i//28)*4+i%4] for i in range(1092))
 else:restored=load("k44_geometry",GEOMETRY).decode(raw)
 assert hashlib.sha256(restored.encode()).hexdigest()==gate["decoded_hex_sha256"]
 return bytes.fromhex(restored)
def compute(cipher,slow=False):
 model=load("nibble_additive_model",MODEL);fn=model.residue_masks_slow if slow else model.residue_masks_fast;rows=[]
 for q,operation in CELLS:
  masks=fn(cipher,q,operation);residues=[]
  for residue,mask in enumerate(masks):
   indices=list(range(residue,len(cipher),q));residues.append({"residue":residue,"byte_indices":indices,"cipher_values":[cipher[i] for i in indices],"paired_key_mask_hex":model.mask_hex(mask),"paired_key_count":bin(mask).count("1")})
  empty=[r for r,m in enumerate(masks) if not m]
  rows.append({"cell_id":f"nibble_q{q}_{operation}","paired_byte_period":q,"operation":operation,"residues":residues,"empty_residues":empty,"compatible_relaxed_paired_key_count":str(math.prod(r["paired_key_count"] for r in residues)),"status":"excluded_bag165" if empty else "relaxed_paired_keys_unresolved","odd_hex_period_note":"q=19 can represent hex periods19 or38; q=57 represents hex period57. Odd-period independent paired residues relax shared nibble dependencies."})
 return rows
def main():
 ap=argparse.ArgumentParser();mode=ap.add_mutually_exclusive_group();mode.add_argument("--selftest",action="store_true");mode.add_argument("--run-target",action="store_true");mode.add_argument("--verify",action="store_true");args=ap.parse_args()
 gate=require_gate()
 if args.selftest or not (args.run_target or args.verify):print(json.dumps({"identity":"ASTRA","target_evaluated":False,"gate":"PASS","cells":4},sort_keys=True));return
 if args.run_target and (RESULT.exists() or RESULT.with_name(RESULT.name+".tmp").exists()):raise SystemExit("refusing existing result/tmp")
 cipher=extract(gate,independent=args.verify);cells=compute(cipher,slow=args.verify)
 result={"identity":"ASTRA","target_evaluated":True,"status":"complete","gate_sha256":sha(GATE),"driver_sha256":sha(Path(__file__)),"decoded_cipher_sha256":hashlib.sha256(cipher).hexdigest(),"cells":cells,"counts":{"total":4,"excluded_bag165":sum(x["status"]=="excluded_bag165" for x in cells),"relaxed_paired_keys_unresolved":sum(x["status"]!="excluded_bag165" for x in cells)},"limits":"Necessary byte-union test for four registered relaxed paired-key cells only. Nonempty is unresolved; odd hexadecimal periods retain untested nibble-consistency constraints."}
 if args.verify:
  assert result==json.loads(RESULT.read_text());print(json.dumps({"identity":"ASTRA","verification_only":True,"independent_geometry_slow_masks":"PASS","result_sha256":sha(RESULT)}));return
 tmp=RESULT.with_name(RESULT.name+".tmp");tmp.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n");os.replace(tmp,RESULT);print(json.dumps({"identity":"ASTRA","result_sha256":sha(RESULT),"counts":result["counts"]},sort_keys=True))
if __name__=="__main__":main()

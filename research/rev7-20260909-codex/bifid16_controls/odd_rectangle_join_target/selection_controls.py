#!/usr/bin/env python3
"""ASTRA selection-only control for the 80 unresolved single-graph cells."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path
IDENTITY='ASTRA';HERE=Path(__file__).resolve().parent;PKG=HERE.parent
PARENT=PKG/'odd_single_graph_target';RESULT=PARENT/'target_results.json';RECEIPT=PARENT/'verification.json'
RESULT_SHA='1c90eaaf17af19b51d20ee29e720e4ee14fb7cd3c15ea9b919ff2ada28b1443d'
RECEIPT_SHA='5552bcbad04d7019c13bd22f32bde1d1f1bba8036262b69a6688fc5784142952'
TYPES=('RR','RC','CR','CC')
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def decode_graph(value):
 if len(value)!=64 or any(c not in '0123456789abcdef' for c in value):raise ValueError(value)
 bits=int(value,16);return {(i//16,i%16) for i in range(256) if bits>>i&1}
def graph_hex(edges):return format(sum(1<<(16*a+b) for a,b in edges),'064x')
def build():
 assert sha(RESULT)==RESULT_SHA and sha(RECEIPT)==RECEIPT_SHA
 receipt=json.loads(RECEIPT.read_text());assert receipt['result_sha256']==RESULT_SHA and receipt['cells']==2184 and receipt['status_counts']=={'excluded':2104,'unresolved':80}
 d=json.loads(RESULT.read_text());assert d['status']=='complete' and d['summary']['cells']==2184 and d['summary']['status_counts']=={'excluded':2104,'unresolved':80}
 rows=[r for r in d['cells'] if r['status']=='unresolved'];assert len(rows)==80 and len({r['id'] for r in rows})==80
 selected=[]
 for r in rows:
  assert r['excluded_two_square_bag213'] is False and r['impossible_types']==[]
  graphs={}
  for tr in r['types']:
   assert tr['kind'] in TYPES and tr['classification'] in ('feasible_unresolved','no_constraints')
   edges=decode_graph(tr['graph_hex']);assert len(edges)==tr['edge_count'] and graph_hex(edges)==tr['graph_hex'];graphs[tr['kind']]=tr['graph_hex']
  assert set(graphs)==set(TYPES)
  selected.append({'id':r['id'],'orientation':r['orientation'],'period':r['period'],'source_index_metadata_sha256':r['source_index_metadata_sha256'],'graphs':graphs,'edge_counts':{tr['kind']:tr['edge_count'] for tr in r['types']}})
 return {'identity':IDENTITY,'target_evaluated':False,'prior_target_ledger_read':True,'new_target_search':False,'source_hashes':{'prior_result':RESULT_SHA,'prior_receipt':RECEIPT_SHA,'selection_controls.py':sha(Path(__file__))},'selected_count':len(selected),'ordered_ids':[x['id'] for x in selected],'selection_sha256':hashlib.sha256(json.dumps(selected,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'selected':selected,'assertions':{'exact_prior_counts':True,'exact_80_unique_unresolved_rows':True,'all_four_graph_masks_roundtrip':True,'no_single_graph_exclusion_in_selected_rows':True},'limits':['This control selects completed prior evidence only and performs no new ciphertext transform or join search.','Final join-model and gate hashes are intentionally absent until root accepts the model.']}
def deterministic(x):return x
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();got=build();out=HERE/'selection_controls.json'
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(got,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate),'selected':80},sort_keys=True));return
 assert out.exists() and json.loads(out.read_text())==got
 print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(out),'selected':80,'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Synthetic complete-grid controls for the byte-AMSCO target driver."""
from __future__ import annotations
import argparse,hashlib,json,platform,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;SEARCH=HERE.parent;BASE=SEARCH.parent;RUNTIME=HERE.parents[3]/'rev7-20260909-codex/iv_independent/cascade/runtime';LEDGER=HERE/'controls.json'
sys.path[:0]=[str(HERE),str(SEARCH),str(BASE),str(RUNTIME)]
import run_target as driver
import engine,core,runtime
IDENTITY='ASTRA'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def plain(n=120):
 phrase='DRIVER – — ‘ ’ … CONTROL. '.encode();tail=b'END.\n';room=n-len(tail);return phrase*(room//len(phrase))+b'A'*(room%len(phrase))+tail
def make_cell(objects,cipher,width,start,order,orientation):
 text=plain();obj=objects[cipher];iv=bytes((i*29+width*17+start)&255 for i in range(obj.block_size));ct=driver.reference_cfb(cipher,obj,text,iv,False);transposed=core.amsco_forward(ct,width,order,start);displayed=core.canonical_for_orientation(transposed,orientation);observed=core.orient_bytes(displayed,orientation);assert observed==transposed
 cell=driver.scan_cell(observed,orientation,width,start,objects);correct=[x for x in cell['retained'] if x['cipher']==cipher and x['order']==list(order)];assert len(correct)==1 and bytes.fromhex(correct[0]['full_suffix_hex'])==text[obj.block_size:]
 assert cell['complete_uncapped'] and cell['unexamined_orders']==cell['unexamined_backend_contexts']==0 and cell['orders_examined']==cell['expected_orders'] and cell['backend_contexts_examined']==cell['expected_backend_contexts']
 return {'cipher_plant':cipher,'plant_order':list(order),'plant_iv_hex':iv.hex(),'orientation_roundtrip':True,'plaintext_sha256':hashlib.sha256(text).hexdigest(),'displayed_sha256':hashlib.sha256(displayed).hexdigest(),'cell':cell,'correct_survivor_present_once':True}
def regenerate(out):
 if out.exists():raise SystemExit('refusing existing output: '+str(out))
 with tempfile.TemporaryDirectory(prefix='astra-amsco-driver-controls-') as td:
  builds=runtime.build_source_libraries(Path(td));objects=runtime.registry(builds);assert tuple(objects)==driver.BACKENDS
  rows=[make_cell(objects,'aes128',2,1,(1,0),'nibble_swap'),make_cell(objects,'loki97',3,2,(2,0,1),'full_hex_reverse')]
 result={'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'scope':'Synthetic complete width-2 and width-3 scans through production scan_cell; no target extraction, gate, or run.','rows':rows,'aggregate':{'cells':2,'orders':sum(x['cell']['orders_examined'] for x in rows),'backend_contexts':sum(x['cell']['backend_contexts_examined'] for x in rows),'expected_orders':2+6,'expected_contexts':(2+6)*7,'retained':sum(x['cell']['retained_count'] for x in rows),'negative':sum(x['cell']['negative_count'] for x in rows)},'artifact_hashes':{'run_target.py':sha(HERE/'run_target.py'),'controls.py':sha(Path(__file__)),'engine.py':sha(SEARCH/'engine.py'),'engine_controls.json':sha(SEARCH/'controls.json'),'base_core.py':sha(BASE/'core.py'),'runtime.py':sha(RUNTIME/'runtime.py'),'runtime_controls.json':sha(RUNTIME/'controls.json')},'environment':{'python':platform.python_version(),'compiler':builds['compiler']},'assertions':{'all_passed':True,'production_scan_cell_used':True,'complete_width2_width3':rows[0]['cell']['orders_examined']==2 and rows[1]['cell']['orders_examined']==6,'exact_context_counts':rows[0]['cell']['backend_contexts_examined']==14 and rows[1]['cell']['backend_contexts_examined']==42,'known_survivors_present':all(x['correct_survivor_present_once'] for x in rows),'callbacks_count_every_context':all(sum(x['cell']['classification_counts'].values())==x['cell']['backend_contexts_examined'] for x in rows),'negative_digests_present':all(len(x['cell']['negative_rows_sha256'])==64 for x in rows),'two_iv_reference_and_reencrypt_every_survivor':all(all(len(y['two_iv_full_reference'])==2 and all(z['suffix_exact'] and z['reencryption_exact'] for z in y['two_iv_full_reference']) for y in x['cell']['retained']) for x in rows),'no_target_read_or_evaluation':True}}
 out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(out),'sha256':sha(out),'aggregate':result['aggregate'],'cells':[{'id':x['cell']['cell_id'],'classes':x['cell']['classification_counts'],'negative_digest':x['cell']['negative_rows_sha256']} for x in rows]},indent=2))
def verify(path=LEDGER):
 d=json.loads(path.read_text());assert d['identity']==IDENTITY and d['target_evaluated'] is False and d['rev7_read'] is False
 expected={'run_target.py':sha(HERE/'run_target.py'),'controls.py':sha(Path(__file__)),'engine.py':sha(SEARCH/'engine.py'),'engine_controls.json':sha(SEARCH/'controls.json'),'base_core.py':sha(BASE/'core.py'),'runtime.py':sha(RUNTIME/'runtime.py'),'runtime_controls.json':sha(RUNTIME/'controls.json')};assert d['artifact_hashes']==expected and d['aggregate']['orders']==d['aggregate']['expected_orders']==8 and d['aggregate']['backend_contexts']==d['aggregate']['expected_contexts']==56 and len(d['rows'])==2 and all(d['assertions'].values())
 for row,w,contexts in zip(d['rows'],(2,3),(14,42)):
  cell=row['cell'];assert cell['width']==w and cell['orders_examined']==cell['expected_orders'] and cell['backend_contexts_examined']==cell['expected_backend_contexts']==contexts and cell['complete_uncapped'] and cell['unexamined_orders']==cell['unexamined_backend_contexts']==0 and sum(cell['classification_counts'].values())==contexts
  assert all(sum(cell['counts_by_backend'][x].values())==cell['expected_orders'] for x in driver.BACKENDS) and len(cell['negative_rows_sha256'])==64 and cell['negative_count']+cell['retained_count']==contexts and len(cell['first_negative_examples'])<=3
  for survivor in cell['retained']:
   suffix=bytes.fromhex(survivor['full_suffix_hex']);assert len(suffix)==survivor['suffix_bytes'] and hashlib.sha256(suffix).hexdigest()==survivor['suffix_sha256'] and len(survivor['two_iv_full_reference'])==2 and all(x['suffix_exact'] and x['reencryption_exact'] for x in survivor['two_iv_full_reference'])
 print(json.dumps({'identity':IDENTITY,'verified':True,'verification_scope':'stdlib source/dependency/ledger structural integrity; no cryptographic replay','ledger_sha256':sha(path),'target_evaluated':False},sort_keys=True))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);ap.add_argument('--ledger',type=Path,default=LEDGER);a=ap.parse_args();regenerate(a.regenerate) if a.regenerate else verify(a.ledger)
if __name__=='__main__':main()

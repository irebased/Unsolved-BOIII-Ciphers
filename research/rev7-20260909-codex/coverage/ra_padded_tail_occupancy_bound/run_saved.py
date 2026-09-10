#!/usr/bin/env python3
"""Explicit, no-crypto saved-result evaluator for the padded-tail lemma."""
from __future__ import annotations
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
import model as M
HERE=Path(__file__).resolve().parent
COV=HERE.parent
FILES={
 'model.py':HERE/'model.py','controls.py':HERE/'controls.py','controls.json':HERE/'controls.json','README.md':HERE/'README.md',
 'partial_audit.py':COV/'ra_partial_block_inventory_audit/audit.py','partial_evidence.json':COV/'ra_partial_block_inventory_audit/evidence.json',
 'ra_target_results.json':COV/'ra_prefix_inventory/target_results.json','threshold_table.json':COV/'occupancy_screen_controls/threshold_table.json'}
PINS={
 'model.py':'0c830310ba3bdd823c0bc454153983d2c33a404ca28dec0286c0346da55a7081',
 'controls.py':'7e2c7f3f318250f2bc01f1818af21aae59cd460d5914ca5eed67320f77d84dba',
 'controls.json':'23606072cdaa3666b51dddc3f2d9d701a4b35c7d6874cdddea22648a2192b248',
 'README.md':'08afceafe80f5bfbd02f3fb24c279f680e86601557f2d30bde3e77885cbf2036',
 'partial_audit.py':'237a296c4bf643f8f91018aaa6a57190e94b9f1c15d0a79f557c9ba4e0b22b01',
 'partial_evidence.json':'91c7e7c686f4cf74e9c801d7d7a199b7ac904b0cc51c8a077c6a844d244b1835',
 'ra_target_results.json':'448ff7f95d9d07a334439ec4ddca831da5d15173bcba104858aed337f4cd67cb',
 'threshold_table.json':'2d084a536141c8e51045b1fa1052ddfc713e0e5f7a869fd62676cf788dfbb447'}
OUTPUT=HERE/'saved_bound_results.json';TMP=HERE/'saved_bound_results.json.tmp'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def stable(x):return (json.dumps(x,sort_keys=True,indent=2)+'\n').encode()
def verify_pins(include_saved=False):
 names=PINS if include_saved else {k:v for k,v in PINS.items() if k!='ra_target_results.json'}
 for n,w in names.items():
  if sha(FILES[n])!=w:raise AssertionError('hash mismatch '+n)
def ranges(vals):
 vals=sorted(vals);out=[]
 for n in vals:
  if not out or n>out[-1][1]+1:out.append([n,n])
  else:out[-1][1]=n
 return out
def default():
 verify_pins(False)
 cp=subprocess.run([sys.executable,'-B',str(HERE/'controls.py')],cwd=str(HERE.parents[3]),text=True,capture_output=True,check=True)
 return {'identity':'ASTRA','status':'PASS','target_evaluated':False,'saved_result_read':False,'controls_stdout':cp.stdout.strip()}
def evaluate():
 verify_pins(True)
 if OUTPUT.exists() or TMP.exists():raise SystemExit('refusing existing result/temp')
 prior=json.loads(FILES['partial_evidence.json'].read_bytes());src=json.loads(FILES['ra_target_results.json'].read_bytes())
 tab=json.loads(FILES['threshold_table.json'].read_bytes());ds=M.thresholds(tab)
 assert prior['strict_wrapper_rejected_subset']['labels']==3312 and src['scope']['labels']==16128
 meta=prior['primitive_metadata'];ready=[r for r in src['rows'] if r['status']=='ready']
 selected=[r for r in ready if meta[r['primitive']]['kind']=='block' and r['mode'] in ('ecb','cbc') and r['length']%meta[r['primitive']]['block_size']]
 assert len(selected)==3312 and hashlib.sha256(('\n'.join(sorted(r['id'] for r in selected))+'\n').encode()).hexdigest()==prior['strict_wrapper_rejected_subset']['label_id_sha256']
 rows=[]
 for r in selected:
  b=bytes.fromhex(r['bytes_hex']);assert len(b)==546 and hashlib.sha256(b).hexdigest()==r['sha256']
  P=b[:544];Q=P.rstrip(b'\0');bs=meta[r['primitive']]['block_size'];L=((546+bs-1)//bs)*bs
  all_lengths=range(len(Q),L+1);unsupported=[n for n in all_lengths if n not in ds];supported=[n for n in all_lengths if n in ds]
  mx=max((ds[n] for n in supported),default=None);all_supported=not unsupported
  fully=all_supported and mx is not None and len(set(Q))>mx
  rows.append({'id':r['id'],'pre':r['pre'],'primitive':r['primitive'],'mode':r['mode'],'block_size':bs,
   'stored_output_sha256':r['sha256'],'stored_output_D':r['distinct_bytes'],'fixed_prefix_sha256':hashlib.sha256(P).hexdigest(),
   'q_sha256':hashlib.sha256(Q).hexdigest(),'q_length':len(Q),'q_distinct':len(set(Q)),'padded_length':L,
   'candidate_length_min':len(Q),'candidate_length_max':L,'supported_length_count':len(supported),
   'unsupported_length_ranges':ranges(unsupported),'maximum_supported_threshold':mx,
   'all_candidate_lengths_supported':all_supported,'fully_excluded':fully})
 fully=sum(r['fully_excluded'] for r in rows);incomplete=len(rows)-fully
 result={'identity':'ASTRA','target_evaluated':True,'new_decryption':False,'evaluation':'post_hoc padded-final-block occupancy bound',
  'source_pins':PINS|{'run_saved.py':sha(Path(__file__))},
  'scope':{'selected_rows':3312,'modes':['cbc','ecb'],'input_length':546,'fixed_prefix_length':544,'block_sizes':[8,16,32],
   'criterion':'fully_excluded only when every integer candidate output length is table-supported and D(Q) exceeds the maximum threshold over that entire interval'},
  'summary':{'rows':len(rows),'fully_excluded':fully,'incomplete':incomplete,
   'unsupported_interval_rows':sum(bool(r['unsupported_length_ranges']) for r in rows),
   'q_length_min':min(r['q_length'] for r in rows),'q_length_max':max(r['q_length'] for r in rows),
   'q_distinct_min':min(r['q_distinct'] for r in rows),'q_distinct_max':max(r['q_distinct'] for r in rows)},'rows':rows}
 TMP.write_bytes(stable(result));TMP.replace(OUTPUT)
 print(json.dumps({'identity':'ASTRA','status':'complete','result':str(OUTPUT),'sha256':sha(OUTPUT),'fully_excluded':fully,'incomplete':incomplete},sort_keys=True))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--evaluate-saved',action='store_true');a=ap.parse_args()
 if a.evaluate_saved:evaluate()
 else:print(json.dumps(default(),sort_keys=True))
if __name__=='__main__':main()

#!/usr/bin/env python3
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[3]
RA=HERE/'build/target/release/ra'; DATA=HERE/'source/ra/data'; RAW=HERE/'target_results.raw.tmp.json'; SCORED=HERE/'target_results.scored.tmp.json'; RESULT=HERE/'target_results.json'; GATE=HERE/'target_gate.json'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def required():
 return {
  'build/target/release/ra':sha(RA),'build_receipt.json':sha(HERE/'build_receipt.json'),'provenance.json':sha(HERE/'provenance.json'),'snapshot.patch':sha(HERE/'snapshot.patch'),
  'source/ra/Cargo.lock':sha(HERE/'source/ra/Cargo.lock'),'source/ra/crates/ra-cli/src/main.rs':sha(HERE/'source/ra/crates/ra-cli/src/main.rs'),'source/ra/crates/ra-cli/src/sweep.rs':sha(HERE/'source/ra/crates/ra-cli/src/sweep.rs'),'source/ra/crates/ra-cli/src/prefix_inventory.rs':sha(HERE/'source/ra/crates/ra-cli/src/prefix_inventory.rs'),'source/ra/data/revelations.json':sha(HERE/'source/ra/data/revelations.json'),
  'controls.json':sha(HERE/'controls.json'),'scorer_controls.json':sha(HERE/'scorer_controls.json'),'controls.js':sha(HERE/'controls.js'),'score_inventory.js':sha(HERE/'score_inventory.js'),'run_target.py':sha(HERE/'run_target.py'),'prepare_gate.py':sha(HERE/'prepare_gate.py'),
  '../occupancy_screen_controls/score.js':sha(ROOT/'research/rev7-20260909-codex/coverage/occupancy_screen_controls/score.js'),'../occupancy_screen_controls/threshold_table.json':sha(ROOT/'research/rev7-20260909-codex/coverage/occupancy_screen_controls/threshold_table.json')}
def validate_receipts():
 b=json.loads((HERE/'build_receipt.json').read_text()); assert b['identity']=='ASTRA' and b['target_evaluated'] is False and b['binary_sha256']==sha(RA) and b['cargo_lock_sha256']==sha(HERE/'source/ra/Cargo.lock'); assert b['source_hashes']=={x:sha(HERE/'source/ra'/x) for x in ['crates/ra-cli/src/main.rs','crates/ra-cli/src/sweep.rs','crates/ra-cli/src/prefix_inventory.rs']}
 p=json.loads((HERE/'provenance.json').read_text()); assert p['identity']=='ASTRA' and p['target_evaluated'] is False and p['upstream']['commit']=='e127b8d6c17f567b930fe67624d3ea199528b775' and p['snapshot_patch_sha256']==sha(HERE/'snapshot.patch')
def gate():
 g=json.loads(GATE.read_text()); assert g['identity']=='ASTRA' and g['authorized'] is True and g['target_evaluated'] is False and 'ASTRA' in g['fable_reference']; assert g['scope']=={'labels':16128,'pre':['identity','reverse','reverse_words'],'variant':['hex-exact'],'toolfmt':['none'],'boundary':'l1.decrypt output before xf/codec/layer2/oracle'}; assert g['artifact_hashes']==required(); return g
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--run-target',action='store_true');a=ap.parse_args()
 if not a.run_target:
  required(); validate_receipts(); print(json.dumps({'identity':'ASTRA','target_evaluated':False,'status':'preflight','gate_present':GATE.exists()}));return
 gate(); validate_receipts()
 for p in [RESULT,RAW,SCORED]: assert not p.exists(),f'refusing existing {p}'
 subprocess.run([str(RA),'--data',str(DATA),'prefix-inventory','--run-target','--output',str(RAW)],check=True)
 subprocess.run(['node',str(HERE/'score_inventory.js'),'--input',str(RAW),'--output',str(SCORED)],check=True)
 doc=json.loads(SCORED.read_text());assert doc['target_evaluated'] is True and len(doc['rows'])==16128
 SCORED.replace(RESULT);RAW.unlink();print(json.dumps({'status':'complete','result':str(RESULT),'sha256':sha(RESULT),'bytes':RESULT.stat().st_size}))
if __name__=='__main__':main()

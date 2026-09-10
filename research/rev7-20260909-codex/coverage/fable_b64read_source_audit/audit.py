#!/usr/bin/env python3
import argparse,base64,hashlib,json,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
IDENTITY='ASTRA'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def build():
 files=[]
 for root in [HERE/'upstream',HERE/'old-ciphers']:
  for p in sorted(x for x in root.rglob('*') if x.is_file()):files.append({'path':str(p.relative_to(HERE)),'bytes':p.stat().st_size,'sha256':sha(p)})
 node=json.loads(subprocess.check_output(['node',str(HERE/'plant_control.js')],cwd=HERE))
 outs=[]
 stored=0
 for tier in ('t0','t1','t2'):
  p=HERE/f'upstream/b64read/out_{tier}.json';x=json.loads(p.read_text()); s=sum(r.get('trials',0) for r in x['results']);e=sum(r.get('errors',0) for r in x['results']);stored+=s
  outs.append({'tier':tier,'nkeys':x['meta']['nKeys'],'targets':len(x['meta']['targets']),'trial_sum':s,'errors':e,'sha256':sha(p)})
 expected_per_key=19*4+4
 assert expected_per_key==80
 assert stored==1467760
 inferred_t3_keys=(396081280-stored)//(7*expected_per_key)
 assert stored+inferred_t3_keys*7*expected_per_key==396081280 and inferred_t3_keys==704667
 assert not (HERE/'upstream/b64read/out_t3.json').exists()
 readings=json.loads((HERE/'upstream/b64read/readings.json').read_text())
 targets=json.loads((HERE/'upstream/b64read/targets.json').read_text())
 neg=next(x for x in targets if x['label']=='NEG')
 plant=next(x for x in targets if x['label']=='POS')
 hexset=set('0123456789ABCDEF')
 # A constructive counterexample to universal impossibility: all-hex glyph strings decode and roundtrip exactly.
 examples=[]
 for s in ['A'*1092,'0123456789ABCDEF'*68+'0123']:
  b=base64.b64decode(s,validate=True);assert len(b)==819 and base64.b64encode(b).decode()==s
  examples.append({'glyph_sha256':hashlib.sha256(s.encode()).hexdigest(),'decoded_sha256':hashlib.sha256(b).hexdigest(),'decoded_length':len(b),'roundtrip_exact':True})
 tiers_keyfiles={'t1':HERE/'upstream/authorkeys/keys.txt','t2':HERE/'upstream/sibvocab/keys.txt'}
 keycounts={k:sum(1 for line in p.read_text().split('\n') if line!='') for k,p in tiers_keyfiles.items()}
 assert keycounts=={'t1':280,'t2':2338}
 return {'identity':IDENTITY,'target_evaluated':False,'full_target_sweep_replayed':False,'source_hashes':{x['path']:x['sha256'] for x in files}|{'audit.py':sha(Path(__file__)),'plant_control.js':sha(HERE/'plant_control.js')},'runtime':{'python':sys.version.split()[0],'node':node['node_version'],'old_ciphers_git_commit':'7c43c6ae65f49bd7504494d9ca3c55ce2e2496b6'},'plant_replay':node,'stored_sweep':{'stored_outputs':outs,'stored_trial_sum':stored,'formula_per_key_per_target':{'block_ciphers':19,'block_modes':4,'stream_ciphers':4,'trials':80},'headline_trial_count':396081280,'headline_arithmetic_inferred_t3_keys':inferred_t3_keys,'out_t3_present':False,'headline_status':'arithmetically consistent with 704667 additional keys, but that tier output is absent and its endpoint results are not replayable from this capture'},'nulls':{'readings_trials':readings['nullTrials'],'readings_rng':'crypto.randomBytes; no seed saved','stored_negative_sha256':hashlib.sha256(neg['b64string'].encode()).hexdigest(),'stored_negative_replayable':True,'negative_generation_reproducible':False,'comparison_design':'one stored random restricted-alphabet target supplies maxima for all five REAL readings; raw-reading null uses 2000 independent restricted-alphabet strings and only displayed-like decode'},'base64_semantics':{'upper_hex_subset_size':len(hexset),'base64_alphabet_size':64,'length':1092,'decoded_bytes':819,'constructive_legal_hex_examples':examples,'iid_uniform_base64_probability_log10':1092*__import__('math').log10(.25),'logical_status':'probability under an iid uniform-symbol model, not impossibility for every cipher or deterministic construction'},'scope':{'readings':['displayed','fullReversed','bytePairReversed','nibbleSwap','lowercased'],'targets':len(targets),'endpoint_code':'upstream/encoded/endpoints.js','worker_skip':'one block size for block ciphers; zero for stream ciphers','stored_positive_hex_fraction':plant['b64string'] and sum(c in hexset for c in plant['b64string'])/1092},'limits':['Only the stored positive plant is cryptographically replayed; no target or broad cipher sweep is rerun.','The positive plant uses the full Base64 alphabet and therefore validates the general Base64/cipher path, not the restrictive all-hex-glyph condition.','Endpoint maxima and a random negative are heuristic comparisons; they do not establish that every cipher or key fails.','The absent t3 output prevents source-backed verification of the 396,081,280 headline trials and their endpoint maxima.']}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--generate',type=Path);a=ap.parse_args();x=build()
 if a.generate:
  if a.generate.exists():raise SystemExit('refuse overwrite')
  a.generate.write_bytes(json.dumps(x,indent=2,sort_keys=True).encode()+b'\n');print(a.generate)
 else:
  p=HERE/'audit.json';saved=json.loads(p.read_text());
  # runtime fields can differ; audit artifacts and deterministic evidence must not.
  assert saved==x,'audit ledger mismatch';print(json.dumps({'identity':IDENTITY,'status':'PASS','audit_sha256':sha(p),'stored_trials':x['stored_sweep']['stored_trial_sum'],'headline_trials':x['stored_sweep']['headline_trial_count']}))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""ASTRA target-free controls and benchmark for the bounded 28-symbol annealer."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,random,re,sys,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];DEFAULT=HERE/'anneal_controls.json';DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
PINS={'model.py':'1f479f1697d84ee16a2cd9f89568756b9d30878418fe810206da9c683bc14725','controls.py':'f771d92d014a02a423585d6d27adf79ae89702ba57d634770bee0560d80cb632','controls.json':'51ae541d6f08c62521630d4ac4bb19c786e0348170567abb1986dae005778a96','build_char_model.py':'2a97582daab4507f1fed524568ad3ceccdc73b2c581383590402ee1e1af7434b','sibling_char4.json':'7752ce6f93d12079cf9e567d9f0dddf37178f8b40f7907ee6d7c733383969b01','anneal.py':'6937961a714e4ec0e26b5d1c5584f001d8b6a381155f76b0e79c8477246c6d79','revelations.json':'68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
def norm(s):
 s=s.upper();s=''.join(c if 'A'<=c<='Z' or c=='.' else ' ' for c in s);return re.sub(' +',' ',s).strip()
def build():
 files={k:(DATA if k=='revelations.json' else HERE/k) for k in PINS};assert all(sha(files[k])==v for k,v in PINS.items())
 m=load('limb_control_model',HERE/'model.py');a=load('limb_anneal_control',HERE/'anneal.py');model=json.loads((HERE/'sibling_char4.json').read_text())
 rows=json.loads(DATA.read_text());plain=norm(next(x['plaintext'] for x in rows if x['id']=='rev11'))
 codes=m.board_codes((2,8));rng=random.Random(731);rng.shuffle(codes);enc=dict(zip(a.ALPHABET,codes));tokens=[enc[c] for c in plain]
 start=time.perf_counter();fit=a.anneal(tokens,model,restarts=8,steps=12000,seed=9182);elapsed=time.perf_counter()-start
 best=fit['best'];assert best['plaintext']==plain
 table,default,_=a.compile_model(model);seq,labels=a.tokenize(tokens);mapping=[a.ALPHABET.index(best['mapping'][x]) for x in labels]
 assert abs(a.score_seq(seq,mapping,table,default)-best['score'])<1e-8
 for row in fit['restarts_retained']:
  assert len(set(row['mapping'].values()))==len(row['mapping'])
  assert hashlib.sha256(row['plaintext'].encode()).hexdigest()==row['plaintext_sha256']
 # A deterministic random stream is only benchmarked; no negative inference is made.
 rr=random.Random(8801);bench_tokens=[codes[rr.randrange(28)] for _ in range(850)]
 bt=time.perf_counter();bench=a.anneal(bench_tokens,model,restarts=4,steps=6000,seed=991);bench_elapsed=time.perf_counter()-bt
 projected=bench_elapsed*20
 return {'identity':'ASTRA','target_evaluated':False,'rev7_read':False,'source_pins':PINS,'model':{k:model[k] for k in ('alphabet','ids','excluded_ids','normalization','record_lengths','tetragrams','smoothing')},'long_encrypted_english_control':{'source_sibling':'rev11','in_sample_for_language_model':True,'plaintext_length':len(plain),'headers':[2,8],'code_assignment_seed':731,'token_classes':len(set(tokens)),'plaintext_sha256':hashlib.sha256(plain.encode()).hexdigest(),'restarts':8,'steps_per_restart':12000,'anneal_seed':9182,'exact_recovery':True,'best_score':best['score'],'best_mapping':best['mapping'],'elapsed_seconds':elapsed},'bounded_benchmark':{'fixture':'850 tokens drawn uniformly from the same fixed 28 checkerboard codes','fixture_seed':8801,'fixture_token_sha256':hashlib.sha256('|'.join(bench_tokens).encode()).hexdigest(),'restarts':4,'steps_per_restart':6000,'elapsed_seconds':bench_elapsed,'prospective_selected_streams':20,'projected_seconds_linear':projected,'benchmark_best_score':bench['best']['score']},'proposed_target_heuristic':{'exact_capacity_cells':1440,'selection':'deduplicate exact token sequences, sort by descending token IoC then stable recipe id, retain first 20','anneal_each':{'restarts':4,'steps_per_restart':6000,'seed':'20260910 + selected rank * 100'},'output_alphabet':a.ALPHABET,'retain':'all restart candidates, mappings, full plaintext, scores and hashes','interpretation':'heuristic lead finding only; failure does not exclude an unknown assignment'},'assertions':{'all_pins_match':True,'long_control_exact':True,'mapping_injective_for_every_restart':True,'independent_full_score_matches':True,'benchmark_completed':True},'anneal_source_sha256':sha(HERE/'anneal.py'),'control_source_sha256':sha(Path(__file__))}

def canonical_for_compare(x):
 x=json.loads(json.dumps(x));x['long_encrypted_english_control'].pop('elapsed_seconds');x['bounded_benchmark'].pop('elapsed_seconds');x['bounded_benchmark'].pop('projected_seconds_linear');return x
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--generate',type=Path);z=ap.parse_args();out=build()
 if z.generate:
  if z.generate.exists():raise SystemExit('refusing existing output')
  z.generate.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');print(json.dumps({'written':str(z.generate),'sha256':sha(z.generate)}));return
 saved=json.loads(DEFAULT.read_text());assert canonical_for_compare(saved)==canonical_for_compare(out)
 print(json.dumps({'identity':'ASTRA','status':'PASS','ledger_sha256':sha(DEFAULT),'exact_long_control':True,'current_benchmark_seconds':out['bounded_benchmark']['elapsed_seconds']}))
if __name__=='__main__':main()

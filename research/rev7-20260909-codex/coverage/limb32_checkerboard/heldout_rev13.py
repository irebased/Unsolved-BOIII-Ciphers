#!/usr/bin/env python3
"""One fixed-budget held-out Rev13 annealer check; never tunes or retries."""
from pathlib import Path
import hashlib,importlib.util,json,random,re,sys,time
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'heldout_rev13.json';DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
def norm(s):
 s=s.upper();s=''.join(c if 'A'<=c<='Z' or c=='.' else ' ' for c in s);return re.sub(' +',' ',s).strip()
def build():
 a=load('heldout_anneal',HERE/'anneal.py');m=load('heldout_model',HERE/'model.py');lm=json.loads((HERE/'sibling_char4.json').read_text());rows=json.loads(DATA.read_text());plain=norm(next(x['plaintext'] for x in rows if x['id']=='rev13'))
 assert 'rev13' in lm['excluded_ids'] and 'rev13' not in lm['ids']
 codes=m.board_codes((2,8));rng=random.Random(731);rng.shuffle(codes);enc=dict(zip(a.ALPHABET,codes));tokens=[enc[c] for c in plain]
 started=time.perf_counter();fit=a.anneal(tokens,lm,restarts=4,steps=6000,seed=9182);elapsed=time.perf_counter()-started;best=fit['best']
 table,default,_=a.compile_model(lm);seq,labels=a.tokenize(tokens);mapping=[a.ALPHABET.index(best['mapping'][x]) for x in labels];full=a.score_seq(seq,mapping,table,default);assert abs(full-best['score'])<1e-8
 match=sum(x==y for x,y in zip(best['plaintext'],plain));truthmap={code:ch for ch,code in enc.items() if code in set(tokens)};truthmapping=[a.ALPHABET.index(truthmap[x]) for x in labels];truthscore=a.score_seq(seq,truthmapping,table,default)
 return {'identity':'ASTRA','target_evaluated':False,'fixture':'held-out Rev13 plaintext','normalization':lm['normalization'],'plaintext_length':len(plain),'plaintext_sha256':hashlib.sha256(plain.encode()).hexdigest(),'model_excludes_rev13':True,'headers':[2,8],'code_assignment_seed':731,'distinct_codes_used':len(set(tokens)),'restarts':4,'steps_per_restart':6000,'anneal_seed':9182,'elapsed_seconds':elapsed,'exact_recovery':best['plaintext']==plain,'matching_positions':match,'matching_fraction':match/len(plain),'best_score':best['score'],'independent_full_score':full,'truth_score':truthscore,'score_gap_best_minus_truth':best['score']-truthscore,'best_plaintext':best['plaintext'],'best_plaintext_sha256':best['plaintext_sha256'],'best_mapping':best['mapping'],'restart_summaries':[{k:r[k] for k in ('restart','seed','score','plaintext_sha256','plaintext')} for r in fit['restarts_retained']],'source_hashes':{'anneal.py':sha(HERE/'anneal.py'),'sibling_char4.json':sha(HERE/'sibling_char4.json'),'model.py':sha(HERE/'model.py'),'revelations.json':sha(DATA),'heldout_rev13.py':sha(__file__)},'limits':['One preregistered budget and seed; no tuning or rerun on failure.','This measures heuristic recovery on one held-out solved sibling and is not an exclusion theorem.']}
def canonical(x):
 x=json.loads(json.dumps(x));x.pop('elapsed_seconds');return x
if __name__=='__main__':
 out=build();b=(json.dumps(out,sort_keys=True,indent=2)+'\n').encode()
 if OUT.exists():assert canonical(json.loads(OUT.read_text()))==canonical(out)
 else:OUT.write_bytes(b)
 print(json.dumps({'status':'PASS','exact_recovery':out['exact_recovery'],'matching_positions':out['matching_positions'],'length':out['plaintext_length'],'best_score':out['best_score'],'truth_score':out['truth_score'],'elapsed_seconds':out['elapsed_seconds'],'ledger_sha256':sha(OUT)},sort_keys=True))

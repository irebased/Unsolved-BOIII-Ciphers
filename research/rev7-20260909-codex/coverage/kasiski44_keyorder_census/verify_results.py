#!/usr/bin/env python3
"""Independent saved-result verifier: no production model import and no target generation."""
from __future__ import annotations
import argparse,hashlib,itertools,json
from collections import Counter
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];RESULT=HERE/'target_results.json';LEDGER=HERE/'verification.json';CONTROL=HERE/'verifier_controls.json'
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
SOURCE_PINS={'model.py':'e7ef87e8cda01a75b45fd0f834f5b785338724dc326a7256e52018704ee37fb9','controls.py':'bed12a5728819bbe54ef9c9692f138ae2d05dd8a0a5766479764818c6d79a36d','controls.json':'6f4846ef1c5058e8e5f28e91671833a475cc6cef4647d33fac8fe1dcabe40ff9','run_target.py':'917fccd6688eaa380783088dd9131bcb924a2c0fe756e4272105174349579168'}
ZOMBIES=(3,5,4,2,1,6,0);N=1092;COLS=7;ROWS=39;CELL=4;SPAN=156;UNIT=114
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def source_indices(order,cols=COLS,rows=ROWS,cell=CELL):
 order=tuple(order);assert sorted(order)==list(range(cols));span=rows*cell;rank=[0]*cols
 for r,c in enumerate(order):rank[c]=r
 return [rank[c]*span+row*cell+k for row in range(rows) for c in range(cols) for k in range(cell)]
def materialize(observed,order):return ''.join(observed[i] for i in source_indices(order))
def diagonal_runs(s,minlen=4,unit=UNIT):
 out=[]
 for gap in range(unit,len(s),unit):
  i=0
  while i+gap<len(s):
   if s[i]!=s[i+gap]:i+=1;continue
   start=i
   while i+gap<len(s) and s[i]==s[i+gap]:i+=1
   L=i-start
   if L>=minlen:out.append({'start_a':start,'start_b':start+gap,'gap':gap,'length':L,'text':s[start:start+L]})
 return sorted(out,key=lambda x:(x['start_a'],x['start_b'],x['length'],x['text']))
def brute_runs(s,minlen,unit):
 out=[]
 for i in range(len(s)-minlen+1):
  for j in range(i+unit,len(s)-minlen+1,unit):
   if s[i:i+minlen]!=s[j:j+minlen]:continue
   if i and s[i-1]==s[j-1]:continue
   L=minlen
   while j+L<len(s) and s[i+L]==s[j+L]:L+=1
   out.append({'start_a':i,'start_b':j,'gap':j-i,'length':L,'text':s[i:i+L]})
 return sorted(out,key=lambda x:(x['start_a'],x['start_b'],x['length'],x['text']))
def synthetic_controls():
 cases=[]
 for n in range(12):
  for bits in itertools.product('01',repeat=n):
   s=''.join(bits)
   for unit in (2,3):assert diagonal_runs(s,2,unit)==brute_runs(s,2,unit)
  cases.append({'length':n,'strings':2**n,'units':[2,3]})
 geometry=[]
 for cols,rows,cell in ((2,3,1),(3,2,2),(4,3,2),(5,2,3)):
  obs=''.join(chr(33+i) for i in range(cols*rows*cell))
  for order in itertools.permutations(range(cols)):
   idx=source_indices(order,cols,rows,cell);rank={c:r for r,c in enumerate(order)}
   independent=''.join(obs[rank[c]*rows*cell+r*cell+k] for r in range(rows) for c in range(cols) for k in range(cell))
   assert ''.join(obs[i] for i in idx)==independent and sorted(idx)==list(range(len(obs)))
  geometry.append({'columns':cols,'rows':rows,'cell':cell,'orders':math_factorial(cols)})
 fixture=[chr(0x1000+i) for i in range(240)]
 for at in (0,114,228):fixture[at:at+6]=list('ABCDEF')
 fixture=''.join(fixture);runs=diagonal_runs(fixture,4,114);assert {(x['start_a'],x['start_b'],x['length']) for x in runs}=={(0,114,6),(0,228,6),(114,228,6)}
 return {'identity':'ASTRA','target_evaluated':False,'kind':'verifier_synthetic_controls','binary_exhaustive':cases,'binary_strings_total':sum(x['strings'] for x in cases),'geometry':geometry,'diagonal_fixture':{'sha256':hashlib.sha256(fixture.encode()).hexdigest(),'runs':runs},'assertions':{'diagonal_only_equals_independent_all_pairs_brute':True,'inverse_rank_formula_equals_independent_matrix_materialization':True,'overlapping_114_diagonals_preserved':True},'verifier_source_sha256':sha(Path(__file__))}
def math_factorial(n):
 x=1
 for i in range(2,n+1):x*=i
 return x
def canonical():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 raw=next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'];s=''.join(raw.split()).upper();t=MDX.read_text();a=t.index('`83 B57B')+1;b=t.index('`',a);assert ''.join(t[a:b].split()).upper()==s
 assert len(s)==N and hashlib.sha256(s.encode()).hexdigest()==TEXT_SHA;return s
def verify_result():
 for name,want in SOURCE_PINS.items():assert sha(HERE/name)==want
 r=json.loads(RESULT.read_text());scope={'input':'canonical forward 1092 hex symbols','cell_symbols':4,'columns':7,'rows':39,'direction':'conventional decode','orders':'all 7! lexicographic permutations','orders_count':5040,'minimum_repeat_length':4,'qualifying_gap_multiple':114,'statistic':'lexicographic (maximum qualifying maximal-repeat length, count of qualifying maximal-repeat pair regions)'}
 assert r['identity']=='ASTRA' and r['status']=='complete' and r['target_evaluated'] is True and r['scope']==scope;assert r['configuration']=={'source_hashes':SOURCE_PINS,'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA}
 raw=canonical();expected_orders=list(itertools.permutations(range(7)));assert len(r['rows'])==5040 and len({tuple(x['order']) for x in r['rows']})==5040
 dist=Counter();z=None
 for expected,row in zip(expected_orders,r['rows']):
  assert tuple(row['order'])==expected;stream=materialize(raw,expected);assert row['stream_sha256']==hashlib.sha256(stream.encode()).hexdigest();w=diagonal_runs(stream,4,114);assert row['qualifying_witnesses']==w
  score={'maximum_qualifying_length':max((x['length'] for x in w),default=0),'qualifying_region_count':len(w)};assert row['score']==score;dist[f"{score['maximum_qualifying_length']}:{score['qualifying_region_count']}"]+=1
  if expected==ZOMBIES:z=row
 expected_dist=dict(sorted(dist.items(),key=lambda kv:tuple(map(int,kv[0].split(':')))));assert r['distribution']==expected_dist and z is not None
 zs=(z['score']['maximum_qualifying_length'],z['score']['qualifying_region_count']);better=sum((x['score']['maximum_qualifying_length'],x['score']['qualifying_region_count'])>zs for x in r['rows']);ties=sum((x['score']['maximum_qualifying_length'],x['score']['qualifying_region_count'])==zs for x in r['rows'])
 assert r['zombies']=={'order':list(ZOMBIES),'score':z['score'],'stream_sha256':z['stream_sha256'],'strictly_better_orders':better,'tied_orders':ties,'rank_with_ties':better+1,'qualifying_witnesses':z['qualifying_witnesses']}
 return {'identity':'ASTRA','target_evaluated':True,'verification_only':True,'new_target_search':False,'status':'PASS','verifier_source_sha256':sha(Path(__file__)),'result_sha256':sha(RESULT),'orders_verified':5040,'canonical_sha256':TEXT_SHA,'distribution':expected_dist,'zombies':r['zombies'],'limits':'Independent saved-result replay; no target generation or cipher inference.'}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--generate-controls',type=Path);ap.add_argument('--generate-verification',type=Path);a=ap.parse_args();controls=synthetic_controls()
 if a.generate_controls:
  assert not a.generate_controls.exists();a.generate_controls.write_text(json.dumps(controls,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':'ASTRA','generated':'controls','sha256':sha(a.generate_controls)},sort_keys=True));return
 assert CONTROL.exists() and json.loads(CONTROL.read_text())==controls
 if not RESULT.exists():
  assert a.generate_verification is None;print(json.dumps({'identity':'ASTRA','status':'PREPARED','target_evaluated':False,'result_exists':False,'controls_sha256':sha(CONTROL)},sort_keys=True));return
 out=verify_result()
 if a.generate_verification:
  assert not a.generate_verification.exists();a.generate_verification.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':'ASTRA','generated':'verification','sha256':sha(a.generate_verification)},sort_keys=True));return
 assert LEDGER.exists() and json.loads(LEDGER.read_text())==out;print(json.dumps({'identity':'ASTRA','status':'PASS','verification_sha256':sha(LEDGER),'orders_verified':5040},sort_keys=True))
if __name__=='__main__':main()

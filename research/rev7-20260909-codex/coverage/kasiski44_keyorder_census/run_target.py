#!/usr/bin/env python3
"""ASTRA inert exact 7! key-order census driver."""
from __future__ import annotations
import argparse,hashlib,importlib.util,itertools,json,subprocess,sys
from collections import Counter
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
MODEL=HERE/'model.py';CONTROLS=HERE/'controls.py';CONTROL_LEDGER=HERE/'controls.json';OUT=HERE/'target_results.json';TMP=HERE/'target_results.tmp'
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
PINS={'model.py':'e7ef87e8cda01a75b45fd0f834f5b785338724dc326a7256e52018704ee37fb9','controls.py':'bed12a5728819bbe54ef9c9692f138ae2d05dd8a0a5766479764818c6d79a36d','controls.json':'6f4846ef1c5058e8e5f28e91671833a475cc6cef4647d33fac8fe1dcabe40ff9'}
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def load_model():
 spec=importlib.util.spec_from_file_location('astra_kasiski_keyorder_target_model',MODEL);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);return m
def preflight():
 for name,want in PINS.items():assert sha(HERE/name)==want,(name,sha(HERE/name),want)
 subprocess.run([sys.executable,'-B',str(CONTROLS)],cwd=ROOT,check=True,capture_output=True,text=True)
def extract():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 text=MDX.read_text();a=text.index('`83 B57B')+1;b=text.index('`',a);s=''.join(text[a:b].split()).upper()
 d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper()
 assert s==d and len(s)==1092 and hashlib.sha256(s.encode()).hexdigest()==TEXT_SHA
 return s
def row_for(m,raw,order):
 stream=m.decode_equal(raw,order);w=m.qualifying(stream);sc=m.score(w)
 return {'order':list(order),'stream_sha256':m.sha_text(stream),'score':{'maximum_qualifying_length':sc[0],'qualifying_region_count':sc[1]},'qualifying_witnesses':w}
def build():
 m=load_model();raw=extract();rows=[];dist=Counter()
 for order in m.all_orders():
  row=row_for(m,raw,order);rows.append(row);s=row['score'];dist[f"{s['maximum_qualifying_length']}:{s['qualifying_region_count']}"]+=1
 assert len(rows)==5040 and [tuple(x['order']) for x in rows]==list(itertools.permutations(range(7)))
 z=next(x for x in rows if tuple(x['order'])==m.ZOMBIES_ORDER);zs=(z['score']['maximum_qualifying_length'],z['score']['qualifying_region_count'])
 better=sum((r['score']['maximum_qualifying_length'],r['score']['qualifying_region_count'])>zs for r in rows);ties=sum((r['score']['maximum_qualifying_length'],r['score']['qualifying_region_count'])==zs for r in rows)
 assert any(x['text']=='030E6' and x['start_a']==828 and x['start_b']==942 and x['gap']==114 for x in z['qualifying_witnesses'])
 return {'identity':'ASTRA','status':'complete','target_evaluated':True,'scope':{'input':'canonical forward 1092 hex symbols','cell_symbols':4,'columns':7,'rows':39,'direction':'conventional decode','orders':'all 7! lexicographic permutations','orders_count':5040,'minimum_repeat_length':4,'qualifying_gap_multiple':114,'statistic':'lexicographic (maximum qualifying maximal-repeat length, count of qualifying maximal-repeat pair regions)'},'configuration':{'source_hashes':{**PINS,'run_target.py':sha(Path(__file__))},'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA},'rows':rows,'distribution':dict(sorted(dist.items(),key=lambda kv:tuple(map(int,kv[0].split(':'))))),'zombies':{'order':list(m.ZOMBIES_ORDER),'score':z['score'],'stream_sha256':z['stream_sha256'],'strictly_better_orders':better,'tied_orders':ties,'rank_with_ties':better+1,'qualifying_witnesses':z['qualifying_witnesses']},'limits':'Exact conditional census for this fixed input, cut, direction, orientation, periods and statistic. No outside Z formula, random-null or global p-value; no cipher/plaintext inference.'}
def verify(saved):
 m=load_model();raw=extract();assert saved['identity']=='ASTRA' and saved['status']=='complete' and saved['scope']['orders_count']==5040
 assert saved['configuration']['source_hashes']['run_target.py']==sha(Path(__file__))
 fresh=build();assert saved==fresh
 return {'identity':'ASTRA','verified':True,'target_evaluated':True,'verification_only':True,'new_target_search':False,'result_sha256':sha(OUT),'orders':5040,'zombies':saved['zombies'],'distribution':saved['distribution']}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--run-target',action='store_true');a=ap.parse_args();preflight()
 if a.run_target:
  assert not OUT.exists() and not TMP.exists(),'refusing existing result/tmp'
  result=build();TMP.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');TMP.replace(OUT)
  print(json.dumps({'identity':'ASTRA','complete':True,'result_sha256':sha(OUT),'bytes':OUT.stat().st_size,'orders':5040,'zombies':result['zombies']},sort_keys=True));return
 if OUT.exists():print(json.dumps(verify(json.loads(OUT.read_text())),sort_keys=True))
 else:print(json.dumps({'identity':'ASTRA','preflight':True,'target_evaluated':False,'result_exists':False,'run_command':'python3 -B research/rev7-20260909-codex/coverage/kasiski44_keyorder_census/run_target.py --run-target','source_sha256':sha(Path(__file__))},sort_keys=True))
if __name__=='__main__':main()

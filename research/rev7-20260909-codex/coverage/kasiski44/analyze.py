#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,itertools,json,os
from pathlib import Path
import geometry as g
IDENTITY='ASTRA';HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json';OUT=HERE/'results.json';TMP=HERE/'results.json.tmp'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c';GEOM_SHA='cad6c29e75cc1d43ba9f43d172767c081bed8b0394ce5ae7c8adee3e22427e61';CONTROL_SOURCE_SHA='b1e930ddd36b2e3e23dcec86f8d7951dbdb964ae6b7a6a8f68ab56bf34f48c33';CONTROL_SHA='17cc743f29378bc938698b7bb83d55d0b3db5800db0116a3fbbe7407b6d1da00';PERIODS=(19,38,57)
def hb(b):return hashlib.sha256(b).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def extract():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 t=MDX.read_text();a=t.index('`83 B57B')+1;b=t.index('`',a);m=''.join(t[a:b].split()).upper();d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper();assert m==d and len(m)==1092 and hb(m.encode())==TEXT_SHA;return m
def repeat_rows(s,n):
 occ={}
 for i in range(len(s)-n+1):occ.setdefault(s[i:i+n],[]).append(i)
 rows=[]
 for gram,starts in sorted(occ.items()):
  if len(starts)>1:
   for a,b in itertools.combinations(starts,2):
    gap=b-a;rows.append({'ngram':gram,'start_a':a,'start_b':b,'gap':gap,'supports_periods':[p for p in PERIODS if gap%p==0]})
 return rows
def main(run):
 assert sha(HERE/'geometry.py')==GEOM_SHA and sha(HERE/'controls.py')==CONTROL_SOURCE_SHA and sha(HERE/'controls.json')==CONTROL_SHA
 raw=extract()
 if not run:print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'scope':'4 contexts x exact ngrams3/4/5','analysis_source_sha256':sha(Path(__file__))},sort_keys=True));return
 assert not OUT.exists() and not TMP.exists(),'refuse existing results/tmp'
 contexts=[]
 for direction in ('encode','decode'):
  for input_orientation in ('forward','full_hex_reverse'):
   inp=raw if input_orientation=='forward' else raw[::-1];out=g.encode(inp) if direction=='encode' else g.decode(inp);assert len(out)==1092
   grams={};allrows=[]
   for n in (3,4,5):
    rows=repeat_rows(out,n);allrows.extend({'n':n,**r} for r in rows);grams[str(n)]={'start_positions_examined':len(out)-n+1,'repeat_pair_count':len(rows),'repeat_pairs':rows,'gap_histogram':{str(v):sum(r['gap']==v for r in rows) for v in sorted({r['gap'] for r in rows})}}
   support={str(p):sum(r['gap']%p==0 for r in allrows) for p in PERIODS};sets={p:{(r['n'],r['ngram'],r['start_a'],r['start_b']) for r in allrows if r['gap']%p==0} for p in PERIODS};common=set.intersection(*(sets[p] for p in PERIODS));assert common=={(r['n'],r['ngram'],r['start_a'],r['start_b']) for r in allrows if r['gap']%114==0}
   contexts.append({'id':f'{direction}:{input_orientation}','direction':direction,'input_orientation':input_orientation,'input_sha256':hb(inp.encode()),'transformed_sha256':hb(out.encode()),'transformed_length':len(out),'ngrams':grams,'support_pair_counts':support,'all_three_periods_common_pair_count':len(common),'all_three_periods_common_pairs':[{'n':n,'ngram':gram,'start_a':a,'start_b':b,'gap':b-a} for n,gram,a,b in sorted(common)],'period_set_intersections':{'19_and_38':len(sets[19]&sets[38]),'19_and_57':len(sets[19]&sets[57]),'38_and_57':len(sets[38]&sets[57]),'19_and_38_and_57':len(common)}})
 example='ABC'+('X'*111)+'ABC'+('Y'*111)+'ABC';er=repeat_rows(example,3);ep=[r for r in er if r['ngram']=='ABC'];assert [(r['start_a'],r['start_b'],r['gap'],r['supports_periods']) for r in ep]==[(0,114,114,[19,38,57]),(0,228,228,[19,38,57]),(114,228,114,[19,38,57])]
 result={'identity':IDENTITY,'target_evaluated':True,'status':'complete','scope':{'cell_symbols':4,'key':'ZOMBIES','rectangle':'273 cells = 39 rows x 7 columns','column_read_indices_zero_based':list(g.ORDER),'contexts':['encode:forward','encode:full_hex_reverse','decode:forward','decode:full_hex_reverse'],'ngram_lengths':[3,4,5],'candidate_periods':[19,38,57],'support_rule':'one repeat pair supports p iff p divides its position gap; all start positions and all occurrence pairs retained'},'configuration':{'analysis_source_sha256':sha(Path(__file__)),'geometry_sha256':GEOM_SHA,'controls_source_sha256':CONTROL_SOURCE_SHA,'controls_sha256':CONTROL_SHA,'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA,'preregistration':'ASTRA message400 on FABLE channel'},'synthetic_common_multiple_example':{'ngram':'ABC','starts':[0,114,228],'pairs':ep,'meaning':'three occurrence pairs with gaps114,228,114 each support19,38,57; the periods are nested divisibility observations, not independent peaks'},'contexts':contexts,'limits':'Exact conventional repeat-pair divisibility only. No external program Z statistic, null model, language score, or generic negative conclusion is reproduced.'}
 TMP.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n');os.replace(TMP,OUT);print(json.dumps({'identity':IDENTITY,'status':'complete','result_sha256':sha(OUT),'result_bytes':OUT.stat().st_size,'contexts':[{'id':x['id'],'support':x['support_pair_counts'],'common114':x['all_three_periods_common_pair_count'],'repeat_pairs':{n:x['ngrams'][n]['repeat_pair_count'] for n in ('3','4','5')}} for x in contexts]},sort_keys=True))
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--run-canonical',action='store_true');a=ap.parse_args();main(a.run_canonical)

#!/usr/bin/env python3
"""Collapse nested n=3..5 repeat rows to left/right-maximal repeated regions."""
from __future__ import annotations
import hashlib,json
from pathlib import Path
import geometry as g
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json';OUT=HERE/'maximal_repeats.json';PERIODS=(19,38,57)
def hb(b):return hashlib.sha256(b).hexdigest()
def extract():
 t=MDX.read_text();a=t.index('`83 B57B')+1;b=t.index('`',a);m=''.join(t[a:b].split()).upper();d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper();assert m==d and hb(m.encode())=='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c';return m
def maximal(s):
 out=[];N=len(s)
 for i in range(N-2):
  for j in range(i+1,N-2):
   if s[i:i+3]!=s[j:j+3]:continue
   if i>0 and s[i-1]==s[j-1]:continue
   n=3
   while j+n<N and s[i+n]==s[j+n]:n+=1
   out.append({'text':s[i:i+n],'length':n,'start_a':i,'start_b':j,'gap':j-i,'supports_periods':[p for p in PERIODS if (j-i)%p==0]})
 return out
def main():
 raw=extract();rows=[]
 for direction in ('encode','decode'):
  for ori in ('forward','full_hex_reverse'):
   inp=raw if ori=='forward' else raw[::-1];s=g.encode(inp) if direction=='encode' else g.decode(inp);mr=maximal(s)
   support={str(p):sum(p in r['supports_periods'] for r in mr) for p in PERIODS};common=[r for r in mr if all(p in r['supports_periods'] for p in PERIODS)]
   rows.append({'id':f'{direction}:{ori}','transformed_sha256':hb(s.encode()),'maximal_repeat_pairs':mr,'maximal_repeat_pair_count':len(mr),'support_counts':support,'all_three_common_count':len(common),'all_three_common':common})
 out={'identity':'ASTRA','target_evaluated':True,'verification_extension_only':True,'new_target_search':False,'definition':'left-maximal and right-extended repeat pairs of length at least3; collapses nested and shifted n=3..5 rows on one occurrence-pair diagonal','periods':list(PERIODS),'contexts':rows}
 assert not OUT.exists();OUT.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':'ASTRA','result_sha256':hb(OUT.read_bytes()),'contexts':[{'id':r['id'],'support':r['support_counts'],'common':r['all_three_common_count']} for r in rows]},sort_keys=True))
if __name__=='__main__':main()

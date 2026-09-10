#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, os
from pathlib import Path

IDENTITY='ASTRA'; HERE=Path(__file__).resolve().parent; PKG=HERE.parent; ROOT=HERE.parents[3]
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx'; DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
OUT=HERE/'target_results.json'; TMP=HERE/'target_results.json.tmp'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91'
DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'
TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
PINS={
'DESIGN.md':'31960ee4281e3930e3ffa5363e392555a1aa28d91a88e2e332cebfea9de824dc',
'symmetry_probe.py':'8bf072deccafabe1e98db126178207d9cf3c8eccdcab6902a28b0c0d123a26e0',
'symmetry_results.json':'c85649306729315d49cbca7c0ab6888b619bfa3c59eb35cc9d39810c8e017f89',
'EVEN_PERIOD_INVARIANT.md':'6482c0751bbf6b8484741be7b3f47b91c5b39556c2c981fa903b04801852169c',
'even_period_invariant.py':'1fa72b75ff59028ed256dbf6853dd44669cd53b07bcce998331e212b65d2a2a2',
'even_period_invariant.json':'f6f2d01801992bb145c583fdc83284ea100c99d30bf4f3e5a477b56317a84a36'}
ORIENTS=('forward','full_hex_reverse','byte_reverse','nibble_swap')
PERIODS=tuple(range(2,1093,2))

def sha(p:Path): return hashlib.sha256(p.read_bytes()).hexdigest()
def orient(s,n):
 if n=='forward': return s
 if n=='full_hex_reverse': return s[::-1]
 if n=='byte_reverse': return ''.join(reversed([s[i:i+2] for i in range(0,len(s),2)]))
 if n=='nibble_swap': return ''.join(s[i+1]+s[i] for i in range(0,len(s),2))
 raise ValueError(n)
def canonical():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 t=MDX.read_text();a=t.index('`83 B57B')+1;b=t.index('`',a);m=''.join(t[a:b].split()).upper()
 d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper()
 assert m==d and len(m)==1092 and hashlib.sha256(m.encode()).hexdigest()==TEXT_SHA and set(m)==set('0123456789ABCDEF')
 return m
def verify_pins():
 for rel,want in PINS.items(): assert sha(PKG/rel)==want,(rel,sha(PKG/rel),want)
def pairs(s,p):
 out=[]
 for a in range(0,len(s),p):
  block=s[a:a+p];L=len(block);assert L%2==0
  h=L//2;out.extend((int(block[j],16)<<4)|int(block[h+j],16) for j in range(h))
 assert len(out)==len(s)//2
 return bytes(out)
def scope(): return {'orientations':list(ORIENTS),'periods':list(PERIODS),'cells':2184,'symbol_length':1092,'pair_count_per_cell':546,'bounds':[165,213],'whole_message_period':1092,'periods_at_or_above_1092_represented_by':1092}
def main(run):
 verify_pins(); raw=canonical()
 if not run:
  print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'scope':scope(),'driver_sha256':sha(Path(__file__))},sort_keys=True,indent=2));return
 assert not OUT.exists() and not TMP.exists(), 'refuse existing output/tmp'
 cells=[]
 for on in ORIENTS:
  s=orient(raw,on); osh=hashlib.sha256(s.encode()).hexdigest()
  for p in PERIODS:
   bs=pairs(s,p);hist=[0]*256
   for v in bs: hist[v]+=1
   distinct=sum(x>0 for x in hist)
   cells.append({'id':f'{on}:p{p}','orientation':on,'orientation_sha256':osh,'period':p,
    'actual_block_lengths':[len(s[a:a+p]) for a in range(0,len(s),p)],
    'pair_count':len(bs),'pair_stream_sha256':hashlib.sha256(bs).hexdigest(),
    'histogram':hist,'distinct_pair_count':distinct,
    'bound_165':'excluded_all_squares' if distinct>165 else 'unresolved',
    'bound_213':'excluded_all_squares' if distinct>213 else 'unresolved'})
 summaries={}
 for on in ORIENTS:
  rows=[x for x in cells if x['orientation']==on]
  summaries[on]={'periods':len(rows),'min_distinct':min(x['distinct_pair_count'] for x in rows),'max_distinct':max(x['distinct_pair_count'] for x in rows),
   'bound_165_excluded':sum(x['distinct_pair_count']>165 for x in rows),'bound_165_unresolved':sum(x['distinct_pair_count']<=165 for x in rows),
   'bound_213_excluded':sum(x['distinct_pair_count']>213 for x in rows),'bound_213_unresolved':sum(x['distinct_pair_count']<=213 for x in rows),
   'whole_period_1092_distinct':next(x['distinct_pair_count'] for x in rows if x['period']==1092)}
 out={'identity':IDENTITY,'target_evaluated':True,'status':'complete','scope':scope(),'configuration':{'driver_sha256':sha(Path(__file__)),'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA,'proof_artifact_hashes':PINS},'cells':cells,'summary':{'cells':len(cells),'by_orientation':summaries}}
 TMP.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');os.replace(TMP,OUT)
 print(json.dumps({'identity':IDENTITY,'status':'complete','cells':len(cells),'result_sha256':sha(OUT),'summary':summaries},sort_keys=True))
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--run-target',action='store_true');a=ap.parse_args();main(a.run_target)

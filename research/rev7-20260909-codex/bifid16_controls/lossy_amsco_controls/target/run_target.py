#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,os
from pathlib import Path
IDENTITY='ASTRA';HERE=Path(__file__).resolve().parent;PKG=HERE.parent;ROOT=HERE.parents[4]
OUT=HERE/'target_results.json';TMP=HERE/'target_results.json.tmp';MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json';INV=ROOT/'research/char_amsco/astra/lossy4_onechar_inventory/inventory.json'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c';INV_SHA='fa9d7463848918d2eaddfe6afdf013f2d5b6b1d1c2011aa5d0aa5a197eec4fe2'
PINS={'core.py':'8e71b08333cf9a8d915e45d4d55f8afe09b12031527776ad70aa20fb0a06807d','controls.py':'cc354ef3f2893a142c215f563ddb43c3c30635ee25ca7b9e09cffcad0561fb88','controls.json':'6d5771bacd4f3c18644ad514651ba94f79d0865f89da01ed5365531c1d4279aa','README.md':'21e58b94f9a6490fda613aff106f130b7e49be0a901267565d9a5e598522b304'}
ORIENTS=('forward','full_hex_reverse','byte_reverse','nibble_swap');PERIODS=tuple(range(2,1311,2));N=1310
def hb(b):return hashlib.sha256(b).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def orient(s,n):
 if n=='forward':return s
 if n=='full_hex_reverse':return s[::-1]
 if n=='byte_reverse':return ''.join(reversed([s[i:i+2] for i in range(0,len(s),2)]))
 if n=='nibble_swap':return ''.join(s[i+1]+s[i] for i in range(0,len(s),2))
 raise ValueError(n)
def extract():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 t=MDX.read_text();a=t.index('`83 B57B')+1;b=t.index('`',a);m=''.join(t[a:b].split()).upper();d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper();assert m==d and len(m)==1092 and hb(m.encode())==TEXT_SHA;return m
def scope():return {'natural_symbol_length':1310,'observed_symbol_length':1092,'maps':12,'orientations':list(ORIENTS),'periods':list(PERIODS),'cells':31440,'bounds':[165,213],'whole_message_period':1310,'periods_at_or_above_1310_represented_by':1310}
def row(partial,p):
 hist=[0]*256;stream=bytearray();known=0
 for a in range(0,N,p):
  L=min(p,N-a);assert L%2==0;h=L//2
  for j in range(h):
   x=partial[a+j];y=partial[a+h+j]
   if x is not None and y is not None:
    v=16*int(x,16)+int(y,16);hist[v]+=1;stream.append(v);known+=1
 d=sum(bool(x) for x in hist);rem=N%p
 return hist,bytes(stream),known,d,N//p,(rem if rem else p),rem
def main(run):
 for rel,w in PINS.items():assert sha(PKG/rel)==w
 assert sha(INV)==INV_SHA;classes=json.loads(INV.read_text())['map_classes'];assert len(classes)==12
 raw=extract()
 if not run:print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'scope':scope(),'driver_sha256':sha(Path(__file__))},sort_keys=True,indent=2));return
 assert not OUT.exists() and not TMP.exists(),'refuse existing result/tmp'
 cells=[]
 for g in classes:
  inds=g['emission_indices'];assert len(inds)==1092 and len(set(inds))==1092 and max(inds)<N
  for on in ORIENTS:
   observed=orient(raw,on);partial=[None]*N
   for idx,ch in zip(inds,observed):partial[idx]=ch
   masksha=hb(bytes(1 if x is not None else 0 for x in partial));partialsha=hb(''.join(x or '?' for x in partial).encode())
   for p in PERIODS:
    hist,stream,known,d,fulls,last,rem=row(partial,p)
    cells.append({'id':f"{g['class_id']}:{on}:p{p}",'class_id':g['class_id'],'map_sha256':g['map_sha256'],'representative_key':g['representative_key'],'orientation':on,'orientation_restored_sha256':hb(observed.encode()),'natural_known_mask_sha256':masksha,'natural_partial_sha256':partialsha,'period':p,'full_block_count_floor':fulls,'remainder':rem,'final_block_length':last,'known_pair_observations':known,'known_pair_stream_sha256':hb(stream),'histogram':hist,'known_distinct_pairs':d,'bound_165':'excluded_all_completions_and_squares' if d>165 else 'unresolved','bound_213':'excluded_all_completions_and_squares' if d>213 else 'unresolved'})
 by=[]
 for g in classes:
  for on in ORIENTS:
   rs=[x for x in cells if x['class_id']==g['class_id'] and x['orientation']==on]
   by.append({'class_id':g['class_id'],'orientation':on,'cells':len(rs),'min_known_distinct':min(x['known_distinct_pairs'] for x in rs),'max_known_distinct':max(x['known_distinct_pairs'] for x in rs),'bound_165_excluded':sum(x['known_distinct_pairs']>165 for x in rs),'bound_165_unresolved_periods':[x['period'] for x in rs if x['known_distinct_pairs']<=165],'bound_213_excluded':sum(x['known_distinct_pairs']>213 for x in rs),'bound_213_unresolved_periods':[x['period'] for x in rs if x['known_distinct_pairs']<=213],'whole_period_1310':next(x['known_distinct_pairs'] for x in rs if x['period']==1310)})
 summary={'cells':len(cells),'bound_165_excluded':sum(x['known_distinct_pairs']>165 for x in cells),'bound_165_unresolved':sum(x['known_distinct_pairs']<=165 for x in cells),'bound_213_excluded':sum(x['known_distinct_pairs']>213 for x in cells),'bound_213_unresolved':sum(x['known_distinct_pairs']<=213 for x in cells),'by_map_orientation':by}
 out={'identity':IDENTITY,'target_evaluated':True,'status':'complete','scope':scope(),'configuration':{'driver_sha256':sha(Path(__file__)),'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA,'inventory_sha256':INV_SHA,'parent_artifact_hashes':PINS,'preregistration':'ASTRA message384 on FABLE channel'},'cells':cells,'summary':summary}
 TMP.write_text(json.dumps(out,sort_keys=True,separators=(',',':'))+'\n');os.replace(TMP,OUT);print(json.dumps({'identity':IDENTITY,'status':'complete','result_sha256':sha(OUT),'result_bytes':OUT.stat().st_size,'summary':{k:v for k,v in summary.items() if k!='by_map_orientation'}},sort_keys=True))
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--run-target',action='store_true');a=ap.parse_args();main(a.run_target)

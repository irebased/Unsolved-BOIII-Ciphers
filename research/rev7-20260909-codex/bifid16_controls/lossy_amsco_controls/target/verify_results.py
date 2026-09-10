#!/usr/bin/env python3
"""Independent natural-index/global-byte replay of saved lossy-Bifid counts."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
IDENTITY='ASTRA';HERE=Path(__file__).resolve().parent;PKG=HERE.parent;ROOT=HERE.parents[4];RESULT=HERE/'target_results.json';DRIVER=HERE/'run_target.py';MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json';INV=ROOT/'research/char_amsco/astra/lossy4_onechar_inventory/inventory.json'
RESULT_SHA='cbe78dd96151e19e1e79a689030e436a670fa490075a894150ebfa30183c3744';DRIVER_SHA='a6663aca9933ad29148a904f07e6e11773f5d8bc60accd49c4fd1686b9aa613f';MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c';INV_SHA='fa9d7463848918d2eaddfe6afdf013f2d5b6b1d1c2011aa5d0aa5a197eec4fe2';PINS={'core.py':'8e71b08333cf9a8d915e45d4d55f8afe09b12031527776ad70aa20fb0a06807d','controls.py':'cc354ef3f2893a142c215f563ddb43c3c30635ee25ca7b9e09cffcad0561fb88','controls.json':'6d5771bacd4f3c18644ad514651ba94f79d0865f89da01ed5365531c1d4279aa','README.md':'21e58b94f9a6490fda613aff106f130b7e49be0a901267565d9a5e598522b304'};ORIENTS=('forward','full_hex_reverse','byte_reverse','nibble_swap');PERIODS=tuple(range(2,1311,2));N=1310
def hb(b):return hashlib.sha256(b).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def extract():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 t=MDX.read_text();a=t.index('`83 B57B')+1;b=t.index('`',a);m=''.join(t[a:b].split()).upper();d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper();assert m==d and len(m)==1092 and hb(m.encode())==TEXT_SHA;return m
def orient(s,n):
 if n=='forward':return ''.join(s[i] for i in range(len(s)))
 if n=='full_hex_reverse':return ''.join(s[len(s)-1-i] for i in range(len(s)))
 if n=='byte_reverse':return ''.join(s[len(s)-2-2*i:len(s)-2*i] for i in range(len(s)//2))
 if n=='nibble_swap':return ''.join(s[i+1]+s[i] for i in range(0,len(s),2))
 raise AssertionError(n)
def indices_from_key(length,key):
 # Separate literal construction: build each alternating-width cell, assign by
 # numeric label with overwrite, then read labels1..4 down rows.
 rows=[];start=0;cell=0
 while start<length:
  width=2 if cell%2==0 else 1;take=min(width,length-start);row=cell//4;col=cell%4
  if row==len(rows):rows.append({})
  rows[row][int(key[col])]=list(range(start,start+take));start+=take;cell+=1
 return [i for label in range(1,5) for row in rows for i in row.get(label,[])]
def bags():
 cps={9,10,13,*range(32,127),*range(0xA0,0x100),0x2013,0x2014,0x2018,0x2019,0x201C,0x201D,0x2026};assert len(cps)==201;b1={b for cp in cps for b in chr(cp).encode()};assert len(b1)==165
 b2={b for cp in range(0x110000) if not 0xD800<=cp<=0xDFFF and (cp>=128 or cp in {9,10,13} or 32<=cp<=126) for b in chr(cp).encode()};assert len(b2)==213;return b1,b2
def replay(partial,p):
 hist=[0]*256;stream=bytearray()
 for j in range(N//2):
  nib=2*j;a=(nib//p)*p;L=min(p,N-a);local=(nib-a)//2;x=partial[a+local];y=partial[a+L//2+local]
  if x is not None and y is not None:v=16*int(x,16)+int(y,16);hist[v]+=1;stream.append(v)
 return hist,bytes(stream)
def main(write):
 assert sha(RESULT)==RESULT_SHA and sha(DRIVER)==DRIVER_SHA and sha(INV)==INV_SHA
 for rel,w in PINS.items():assert sha(PKG/rel)==w
 raw=extract();inv=json.loads(INV.read_text());classes=inv['map_classes'];assert len(classes)==12;x=json.loads(RESULT.read_text());assert x['identity']==IDENTITY and x['target_evaluated'] is True and x['status']=='complete';assert x['configuration']=={'driver_sha256':DRIVER_SHA,'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA,'inventory_sha256':INV_SHA,'parent_artifact_hashes':PINS,'preregistration':'ASTRA message384 on FABLE channel'}
 exact,broad=bags();scope={'natural_symbol_length':N,'observed_symbol_length':1092,'maps':12,'orientations':list(ORIENTS),'periods':list(PERIODS),'cells':31440,'bounds':[len(exact),len(broad)],'whole_message_period':1310,'periods_at_or_above_1310_represented_by':1310};assert x['scope']==scope
 rows={(r['class_id'],r['orientation'],r['period']):r for r in x['cells']};expected={(g['class_id'],o,p) for g in classes for o in ORIENTS for p in PERIODS};assert len(rows)==len(x['cells'])==31440 and set(rows)==expected
 summaryrows=[]
 for g in classes:
  inds=indices_from_key(N,g['representative_key']);assert inds==g['emission_indices'] and len(inds)==1092 and len(set(inds))==1092
  mask=bytes(1 if i in set(inds) else 0 for i in range(N));masksha=hb(mask)
  for o in ORIENTS:
   observed=orient(raw,o);partial=[None]*N
   for i,ch in zip(inds,observed):partial[i]=ch
   psha=hb(''.join(ch or '?' for ch in partial).encode());orsha=hb(observed.encode());rs=[]
   for p in PERIODS:
    r=rows[(g['class_id'],o,p)];hist,stream=replay(partial,p);d=sum(bool(n) for n in hist);rem=N%p;last=rem if rem else p
    assert r['id']==f"{g['class_id']}:{o}:p{p}" and r['map_sha256']==g['map_sha256'] and r['representative_key']==g['representative_key'] and r['orientation_restored_sha256']==orsha and r['natural_known_mask_sha256']==masksha and r['natural_partial_sha256']==psha
    assert r['full_block_count_floor']==N//p and r['remainder']==rem and r['final_block_length']==last and last%2==0
    assert r['known_pair_observations']==len(stream)==sum(hist) and r['known_pair_stream_sha256']==hb(stream) and r['histogram']==hist and r['known_distinct_pairs']==d
    assert r['bound_165']==('excluded_all_completions_and_squares' if d>165 else 'unresolved') and r['bound_213']==('excluded_all_completions_and_squares' if d>213 else 'unresolved');rs.append(r)
   summaryrows.append({'class_id':g['class_id'],'orientation':o,'cells':655,'min_known_distinct':min(r['known_distinct_pairs'] for r in rs),'max_known_distinct':max(r['known_distinct_pairs'] for r in rs),'bound_165_excluded':sum(r['known_distinct_pairs']>165 for r in rs),'bound_165_unresolved_periods':[r['period'] for r in rs if r['known_distinct_pairs']<=165],'bound_213_excluded':sum(r['known_distinct_pairs']>213 for r in rs),'bound_213_unresolved_periods':[r['period'] for r in rs if r['known_distinct_pairs']<=213],'whole_period_1310':next(r['known_distinct_pairs'] for r in rs if r['period']==1310)})
 summary={'cells':31440,'bound_165_excluded':sum(r['known_distinct_pairs']>165 for r in x['cells']),'bound_165_unresolved':sum(r['known_distinct_pairs']<=165 for r in x['cells']),'bound_213_excluded':sum(r['known_distinct_pairs']>213 for r in x['cells']),'bound_213_unresolved':sum(r['known_distinct_pairs']<=213 for r in x['cells']),'by_map_orientation':summaryrows};assert x['summary']==summary
 cert={'identity':IDENTITY,'target_evaluated':True,'verification_only':True,'new_target_search':False,'status':'PASS','method':'independent source-map placement and global plaintext-byte indexing','result_sha256':RESULT_SHA,'driver_sha256':DRIVER_SHA,'cells_verified':31440,'pair_values_verified':sum(r['known_pair_observations'] for r in x['cells']),'histogram_bins_verified':31440*256,'summary':{k:v for k,v in summary.items() if k!='by_map_orientation'}}
 if write:
  d=Path(write);assert not d.exists();d.write_text(json.dumps(cert,sort_keys=True,indent=2)+'\n');cert['certificate_sha256']=sha(d)
 print(json.dumps(cert,sort_keys=True,indent=2))
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--write');a=ap.parse_args();main(a.write)

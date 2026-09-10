#!/usr/bin/env python3
"""Independent global-byte-index replay of the saved even-block inventory."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
IDENTITY='ASTRA'; HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[3]
RESULT=HERE/'target_results.json'; DRIVER=HERE/'run_target.py'; MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
RESULT_SHA='acc7df78f141e79b9d3c4e23dba3124ddb7665d5cb5f7450eabd5d9a88ce1dc8';DRIVER_SHA='b86fdd8402319753eb0292e75b9f0712a1ed2044038761e5d7a23af30cd4ff85';MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
ORIENTS=('forward','full_hex_reverse','byte_reverse','nibble_swap');PERIODS=tuple(range(2,1093,2));PKG=HERE.parent
PINS={'DESIGN.md':'31960ee4281e3930e3ffa5363e392555a1aa28d91a88e2e332cebfea9de824dc','symmetry_probe.py':'8bf072deccafabe1e98db126178207d9cf3c8eccdcab6902a28b0c0d123a26e0','symmetry_results.json':'c85649306729315d49cbca7c0ab6888b619bfa3c59eb35cc9d39810c8e017f89','EVEN_PERIOD_INVARIANT.md':'6482c0751bbf6b8484741be7b3f47b91c5b39556c2c981fa903b04801852169c','even_period_invariant.py':'1fa72b75ff59028ed256dbf6853dd44669cd53b07bcce998331e212b65d2a2a2','even_period_invariant.json':'f6f2d01801992bb145c583fdc83284ea100c99d30bf4f3e5a477b56317a84a36'}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def extract():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 t=MDX.read_text();a=t.index('`83 B57B')+1;b=t.index('`',a);m=''.join(t[a:b].split()).upper()
 d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper()
 assert m==d and len(m)==1092 and hashlib.sha256(m.encode()).hexdigest()==TEXT_SHA;return m
def orientation(s,name):
 if name=='forward':return s
 if name=='full_hex_reverse':return ''.join(reversed(s))
 pairs=[s[i:i+2] for i in range(0,len(s),2)]
 if name=='byte_reverse':return ''.join(pairs[len(pairs)-1-i] for i in range(len(pairs)))
 if name=='nibble_swap':return ''.join(pair[1]+pair[0] for pair in pairs)
 raise AssertionError(name)
def pair_stream_global(s,p):
 vals=[];N=len(s)
 for j in range(N//2):
  nib=2*j;a=(nib//p)*p;L=min(p,N-a);local=(nib-a)//2
  assert L%2==0 and 0<=local<L//2
  vals.append(16*int(s[a+local],16)+int(s[a+L//2+local],16))
 return bytes(vals)
def bags():
 exact_cp=set((9,10,13))|set(range(32,127))|set(range(0xA0,0x100))|{0x2013,0x2014,0x2018,0x2019,0x201C,0x201D,0x2026}
 assert len(exact_cp)==201
 exact_bytes={b for cp in exact_cp for b in chr(cp).encode('utf-8')};assert len(exact_bytes)==165
 broad_cp=(cp for cp in range(0x110000) if not 0xD800<=cp<=0xDFFF and (cp>=128 or cp in {9,10,13} or 32<=cp<=126))
 broad_bytes={b for cp in broad_cp for b in chr(cp).encode('utf-8')};assert len(broad_bytes)==213
 return exact_bytes,broad_bytes
def main(write):
 assert sha(RESULT)==RESULT_SHA and sha(DRIVER)==DRIVER_SHA
 raw=extract();x=json.loads(RESULT.read_text());assert x['identity']==IDENTITY and x['target_evaluated'] is True and x['status']=='complete'
 for rel,want in PINS.items():assert sha(PKG/rel)==want
 cfg=x['configuration'];assert cfg=={'driver_sha256':DRIVER_SHA,'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA,'proof_artifact_hashes':PINS}
 exact,broad=bags();assert x['scope']=={'orientations':list(ORIENTS),'periods':list(PERIODS),'cells':2184,'symbol_length':1092,'pair_count_per_cell':546,'bounds':[len(exact),len(broad)],'whole_message_period':1092,'periods_at_or_above_1092_represented_by':1092}
 expected={(o,p) for o in ORIENTS for p in PERIODS};seen=set();summaries={}
 for row in x['cells']:
  key=(row['orientation'],row['period']);assert key in expected and key not in seen;seen.add(key)
  o,p=key;s=orientation(raw,o);assert row['id']==f'{o}:p{p}' and row['orientation_sha256']==hashlib.sha256(s.encode()).hexdigest()
  assert row['actual_block_lengths']==[len(s[a:a+p]) for a in range(0,len(s),p)] and all(L%2==0 for L in row['actual_block_lengths'])
  bs=pair_stream_global(s,p);hist=[0]*256
  for v in bs:hist[v]+=1
  d=sum(bool(n) for n in hist);assert len(bs)==546 and row['pair_count']==546 and row['histogram']==hist and sum(hist)==546
  assert row['pair_stream_sha256']==hashlib.sha256(bs).hexdigest() and row['distinct_pair_count']==d
  assert row['bound_165']==('excluded_all_squares' if d>len(exact) else 'unresolved')
  assert row['bound_213']==('excluded_all_squares' if d>len(broad) else 'unresolved')
 assert seen==expected
 for o in ORIENTS:
  rows=[r for r in x['cells'] if r['orientation']==o];summaries[o]={'periods':546,'min_distinct':min(r['distinct_pair_count'] for r in rows),'max_distinct':max(r['distinct_pair_count'] for r in rows),'bound_165_excluded':sum(r['distinct_pair_count']>165 for r in rows),'bound_165_unresolved':sum(r['distinct_pair_count']<=165 for r in rows),'bound_213_excluded':sum(r['distinct_pair_count']>213 for r in rows),'bound_213_unresolved':sum(r['distinct_pair_count']<=213 for r in rows),'whole_period_1092_distinct':next(r['distinct_pair_count'] for r in rows if r['period']==1092)}
 assert x['summary']=={'cells':2184,'by_orientation':summaries}
 cert={'identity':IDENTITY,'status':'PASS','target_evaluated':True,'verification_only':True,'new_target_search':False,'method':'independent global plaintext-byte index reconstruction; no square solver','result_sha256':RESULT_SHA,'driver_sha256':DRIVER_SHA,'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA,'cells_verified':2184,'histogram_bins_verified':2184*256,'pair_values_verified':2184*546,'exact_201_byte_union_size':len(exact),'broad_unicode_byte_union_size':len(broad),'summary':x['summary']}
 if write:
  dest=Path(write);assert not dest.exists();dest.write_text(json.dumps(cert,sort_keys=True,indent=2)+'\n');cert['certificate_sha256']=sha(dest)
 print(json.dumps(cert,sort_keys=True,indent=2))
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--write');a=ap.parse_args();main(a.write)

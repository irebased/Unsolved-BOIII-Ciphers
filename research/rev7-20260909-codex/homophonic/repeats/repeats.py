#!/usr/bin/env python3
import argparse, hashlib, itertools, json, re
from collections import Counter
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]
DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx'
EXPECT_DATA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'
EXPECT_MDX='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91'
EXPECT_HEX='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
def sh(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def norm(a):
 d={}; return tuple(d.setdefault(x,len(d)) for x in a)
def stats(a):
 c=Counter(a); lags={d:sum(a[i]==a[i+d] for i in range(len(a)-d)) for d in range(1,len(a))}
 return {'length':len(a),'distinct':len(c),'unobserved_256':256-len(c),'histogram':dict(sorted(c.items())),'multiplicity_histogram':dict(sorted(Counter(c.values()).items())),'singleton_count':sum(v==1 for v in c.values()),'doubleton_count':sum(v==2 for v in c.values()),'repeated_occurrences':len(a)-len(c),'equal_unordered_position_pairs':sum(v*(v-1)//2 for v in c.values()),'adjacent_equality_count':lags[1],'max_run':max((len(list(g)) for _,g in itertools.groupby(a)),default=0),'repeat_lag_histogram_1_to_545':lags}
def compute():
 assert sh(DATA)==EXPECT_DATA and sh(MDX)==EXPECT_MDX
 records=json.loads(DATA.read_text()); h=re.sub('[^0-9A-Fa-f]','',records[6]['ciphertext']).upper(); assert len(h)==1092 and hashlib.sha256(h.encode()).hexdigest()==EXPECT_HEX
 mdx_text=MDX.read_text(); m=re.search(r'<CodeBlockWithLength code=\{\s*`([^`]*)`\s*\}/>',mdx_text,re.S); assert m and re.sub('[^0-9A-Fa-f]','',m.group(1)).upper()==h
 pairs=[h[i:i+2] for i in range(0,len(h),2)]; vals=[int(x,16) for x in pairs]
 ors={'forward':vals,'full_hex_reverse':[int(h[::-1][i:i+2],16) for i in range(0,len(h),2)],'byte_reverse':list(reversed(vals)),'nibble_swap':[int(x[1]+x[0],16) for x in pairs]}
 inv=all(norm(vals)==norm(v) or norm(vals)==norm(v[::-1]) for v in ors.values())
 return {'identity':'ASTRA','target_evaluated':True,'crypto_evaluated':False,'scope':'Exact byte-pair equality statistics on pinned canonical Rev7 ciphertext; no deciphering or search.','inputs':{'dataset':'lavender/src/data/ciphers/revelations.json','dataset_sha256':EXPECT_DATA,'mdx':'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx','mdx_sha256':EXPECT_MDX,'record_index':6,'record_title':records[6]['title'],'canonical_hex_chars':len(h),'canonical_bytes':len(vals),'canonical_hex_sha256':EXPECT_HEX,'known_prefix':'83 B57B2'},'orientations':{k:stats(v) for k,v in ors.items()},'orientation_invariance':{'equality_pattern_same_under_bijective_relabel_or_position_reversal':inv,'tested':'normalized first-occurrence pattern forward and reversed for all four orientations','note':'nibble swap is a byte-symbol bijection; byte-order reversal reverses positions; full-hex reversal combines pair reversal and nibble swap'},'source_sha256':sh(Path(__file__))}
def write_new(path):
 if path.exists(): raise SystemExit('refusing existing output: '+str(path))
 path.write_text(json.dumps(compute(),indent=2,sort_keys=True)+'\n')
def verify(path):
 expected=json.loads(path.read_text()); actual=json.loads(json.dumps(compute())); assert expected==actual
 print(json.dumps({'identity':'ASTRA','verified':True,'ledger_sha256':sh(path),'source_sha256':actual['source_sha256']},sort_keys=True))
if __name__=='__main__':
 ap=argparse.ArgumentParser(); ap.add_argument('--regenerate',type=Path); a=ap.parse_args(); out=Path(__file__).with_name('repeats.json')
 if a.regenerate: write_new(a.regenerate)
 else: verify(out)

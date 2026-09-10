#!/usr/bin/env python3
import argparse,hashlib,json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[4]; DATA=ROOT/'lavender/src/data/ciphers/revelations.json'; EXPECT='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'; IDS=['rev1','rev2','rev3','rev4','rev5','rev6','rev8','rev9','rev10','rev11','rev12','rev13','rev14']; ALLOC=[6,2,3,5,16,2,3,4,7,1,1,3,4,9,3,1,1,7,7,6,4,1,1,1,1,1]
def sh(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def norm(s):return ''.join(c for c in s.upper() if 'A'<=c<='Z')
def compute():
 assert sh(DATA)==EXPECT; rows=json.loads(DATA.read_text()); out=[]; counts=[0]*26
 for r in rows:
  if r.get('id')=='rev7':continue
  assert r['id'] in IDS and isinstance(r.get('plaintext'),str); t=norm(r['plaintext']); out.append({'id':r['id'],'source_plaintext_sha256':hashlib.sha256(r['plaintext'].encode()).hexdigest(),'normalized_length':len(t),'normalized_sha256':hashlib.sha256(t.encode()).hexdigest()})
  for c in t: counts[ord(c)-65]+=1
 assert [x['id'] for x in out]==IDS and sum(counts)==3196
 return {'identity':'ASTRA','target_evaluated':False,'crypto_evaluated':False,'scope':'Derived A-Z unigram fingerprint from solved sibling plaintext records; rev7 excluded. No target stream scoring.','input':{'path':'lavender/src/data/ciphers/revelations.json','sha256':EXPECT,'included_ids':IDS,'excluded_ids':['rev7']},'normalization':'uppercase then retain A-Z only, exactly per cryptool100/build_model.py','record_rows':out,'letters_total':sum(counts),'alphabet':'ABCDEFGHIJKLMNOPQRSTUVWXYZ','counts':dict(zip('ABCDEFGHIJKLMNOPQRSTUVWXYZ',counts)),'probability_definitions':{'letter_add_one':'p_l=(count_l+1)/(3196+26)','homophonic_code':'p(code)=p(letter(code))/allocation(letter(code))','uniform_letter':'p=1/(26*allocation(letter))','allocation_cryptool100':ALLOC,'allocation_sum':sum(ALLOC)},'source_sha256':sh(Path(__file__))}
def write_new(p):
 if p.exists(): raise SystemExit('refusing existing output')
 p.write_text(json.dumps(compute(),indent=2,sort_keys=True)+'\n')
def verify(p):
 d=json.loads(p.read_text());assert d==json.loads(json.dumps(compute()));print(json.dumps({'identity':'ASTRA','verified':True,'ledger_sha256':sh(p)},sort_keys=True))
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();p=Path(__file__).with_name('model.json');write_new(a.regenerate) if a.regenerate else verify(p)

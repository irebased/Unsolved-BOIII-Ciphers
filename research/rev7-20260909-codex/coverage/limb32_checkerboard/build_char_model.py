#!/usr/bin/env python3
"""Build an ASTRA 28-symbol tetragram model from solved siblings, excluding Rev7 and held-out Rev13."""
from pathlib import Path
from collections import Counter
import argparse,hashlib,json,re
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];DATA=ROOT/'lavender/src/data/ciphers/revelations.json';ALPHABET='ABCDEFGHIJKLMNOPQRSTUVWXYZ .'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def norm(s):
 s=s.upper();s=''.join(c if 'A'<=c<='Z' or c=='.' else ' ' for c in s);return re.sub(' +',' ',s).strip()
def build():
 rows=json.loads(DATA.read_text());texts=[];ids=[]
 for row in rows:
  if row['id'] in ('rev7','rev13'):continue
  t=norm(row.get('plaintext',''))
  if t:ids.append(row['id']);texts.append(t)
 grams=Counter();uni=Counter()
 for t in texts:
  uni.update(t);grams.update(t[i:i+4] for i in range(len(t)-3))
 return {'identity':'ASTRA','purpose':'28-symbol character tetragram ranking model; target Rev7 and held-out Rev13 excluded','alphabet':ALPHABET,'ids':ids,'excluded_ids':['rev7','rev13'],'source_sha256':sha(DATA),'cross_record_tetragrams':False,'normalization':'uppercase A-Z; period preserved; every other run becomes one space; trim','record_lengths':list(map(len,texts)),'unigrams':dict(sorted(uni.items())),'tetragrams':sum(grams.values()),'counts':dict(sorted(grams.items())),'smoothing':'add-one over 28^4'}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,default=HERE/'sibling_char4.json');a=ap.parse_args();out=build()
 if a.output.exists():
  assert json.loads(a.output.read_text())==out;print(json.dumps({'verified':True,'sha256':sha(a.output)}));return
 a.output.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');print(json.dumps({'written':str(a.output),'sha256':sha(a.output)}))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Build sibling-only A-Z tetragram counts. Explicitly excludes rev7 and record-boundary ngrams."""
from pathlib import Path
import argparse,collections,hashlib,json
IDENTITY='ASTRA'; EXPECTED_IDS=['rev1','rev2','rev3','rev4','rev5','rev6','rev8','rev9','rev10','rev11','rev12','rev13','rev14']
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def norm(s):return ''.join(c for c in s.upper() if 'A'<=c<='Z')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('revelations',type=Path);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args()
 if a.output.exists():raise SystemExit('refusing existing output')
 rows=json.loads(a.revelations.read_text()); texts=[];ids=[]
 for r in rows:
  if r.get('id')=='rev7':continue
  if r.get('solved') and isinstance(r.get('plaintext'),str):ids.append(r['id']);texts.append(norm(r['plaintext']))
 assert ids==EXPECTED_IDS
 counts=collections.Counter(g for t in texts for g in (t[i:i+4] for i in range(len(t)-3)))
 out={'identity':IDENTITY,'purpose':'A-Z tetragram ranking model from solved sibling plaintexts only; rev7 excluded','source_path':'lavender/src/data/ciphers/revelations.json','source_sha256':sha(a.revelations),'ids':ids,'excluded_ids':['rev7'],'cross_record_tetragrams':False,'normalized_letters':sum(map(len,texts)),'record_lengths':list(map(len,texts)),'tetragrams':sum(counts.values()),'counts':dict(sorted(counts.items())),'smoothing':'add-one over 26^4'}
 a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
if __name__=='__main__':main()

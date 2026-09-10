#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,itertools,json
from pathlib import Path
import model as M
HERE=Path(__file__).resolve().parent
TABLE=HERE.parent/'occupancy_screen_controls/threshold_table.json'
SCORE=HERE.parent/'occupancy_screen_controls/score.js'
PINS={"threshold_table.json":"2d084a536141c8e51045b1fa1052ddfc713e0e5f7a869fd62676cf788dfbb447","score.js":"6ff228f71ef8e9441c3ba12418d8b49c7238ff4e66ed0eef0f24471a3573ae27"}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def canon(x):return (json.dumps(x,sort_keys=True,indent=2)+'\n').encode()
def generate():
 assert sha(TABLE)==PINS['threshold_table.json'] and sha(SCORE)==PINS['score.js']
 tab=json.loads(TABLE.read_bytes());ds=M.thresholds(tab);assert min(ds)==128 and max(ds)==1092
 checked=0
 # Exhaust all tails over a tiny alphabet for prefixes with/without terminal zeros.
 for prefix in [b'',b'AB',b'AB\0',b'A\0\0',b'\0\0']:
  q=prefix.rstrip(b'\0')
  for k in range(5):
   for tup in itertools.product(range(3),repeat=k):
    tail=bytes(tup); raw=prefix+tail
    for out in [raw,M.zero_unpad(raw)]:
     assert out.startswith(q) and M.dcount(out)>=M.dcount(q)
     assert len(q)<=len(out)<=len(raw);checked+=1
 # Production-shape synthetic bound: 193 distinct bytes in Q exceeds every table threshold through 576.
 prefix=bytes(range(193))+bytes((i*37+11)%193 for i in range(544-193-3))+b'\0\0\0'
 assert len(prefix)==544 and len(prefix.rstrip(b'\0'))==541 and M.dcount(prefix.rstrip(b'\0'))==193
 shapes={str(bs):M.bound(prefix,((546+bs-1)//bs)*bs,ds) for bs in (8,16,32)}
 assert [shapes[str(b)]['padded_length'] for b in (8,16,32)]==[552,560,576]
 assert all(v['proves_no_screen_hit'] for v in shapes.values())
 # Directly enumerate representative tails, including all-zero and new-byte tails.
 tail_rows=[]
 for bs in (8,16,32):
  L=((546+bs-1)//bs)*bs
  for name,tail in [('zeros',bytes(L-544)),('existing',bytes([7])*(L-544)),('new',bytes(range(193,193+L-544)) )]:
   raw=prefix+tail; out=M.zero_unpad(raw)
   b=M.bound(prefix,L,ds); c=M.classify(len(out),M.dcount(out),ds)
   assert out.startswith(prefix.rstrip(b'\0')) and M.dcount(out)>=b['q_distinct'] and c['screen_hit'] is False
   tail_rows.append({'block_size':bs,'tail':name,'output_length':len(out),'D':M.dcount(out),'status':c['status']})
 short=M.classify(127,40,ds);oor=M.classify(1093,240,ds)
 assert short['status']=='short' and short['screen_hit'] is None and oor['status']=='out-of-range' and oor['screen_hit'] is None
 low=M.bound(b'A'*544,552,ds);assert low['q_distinct']==1 and low['proves_no_screen_hit'] is False
 no_supported=M.bound(b'A'*20,40,ds);assert no_supported['supported_length_count']==0 and no_supported['maximum_supported_threshold'] is None and no_supported['proves_no_screen_hit'] is False
 return {'identity':'ASTRA','target_evaluated':False,'saved_result_read':False,
  'scope':'Synthetic controls for a known-prefix distinct-byte lower bound under arbitrary replacement tail and optional trailing-NUL removal.',
  'source_pins':{**PINS,'model.py':sha(HERE/'model.py'),'controls.py':sha(HERE/'controls.py')},
  'lemma':{'known_prefix_length':544,'construction':'Q=P.rstrip(NUL)','claim':'Every P||tail, with or without trailing-NUL stripping, begins with Q; therefore D(output)>=D(Q) and len(output) is between len(Q) and padded length.','production_padded_lengths':{'8':552,'16':560,'32':576},'maximum_table_threshold_over_544_through_576':max(ds[n] for n in range(544,577))},
  'exhaustive_tiny_tail_outputs_checked':checked,'production_shape':shapes,'representative_tails':tail_rows,
  'boundary_status_controls':{'short':short,'out_of_range':oor,'low_alphabet_does_not_prove':low,'no_supported_lengths_does_not_prove':no_supported},
  'limits':['Controls do not inspect the frozen target result or measure its prefixes.','A proof requires the first 544 plaintext bytes to be invariant under the compared padding convention.','This does not prove PHP/tool equivalence, key derivation, IV choice, or any other mode.']}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--generate',type=Path);a=ap.parse_args();got=generate()
 if a.generate:
  if a.generate.exists():raise SystemExit('refusing existing output')
  a.generate.write_bytes(canon(got));print(a.generate);return
 p=HERE/'controls.json';assert json.loads(p.read_bytes())==got
 print(json.dumps({'identity':'ASTRA','status':'PASS','ledger_sha256':sha(p),'tiny_outputs':got['exhaustive_tiny_tail_outputs_checked']},sort_keys=True))
if __name__=='__main__':main()

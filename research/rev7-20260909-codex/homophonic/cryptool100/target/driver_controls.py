#!/usr/bin/env python3
"""Synthetic full-driver controls; never reads Rev7."""
from pathlib import Path
import argparse,hashlib,json,sys
HERE=Path(__file__).resolve().parent;PKG=HERE.parent
sys.path.insert(0,str(HERE));import run_target as d
sys.path.insert(0,str(PKG));import controls as c
IDENTITY='ASTRA'
def h(b):return hashlib.sha256(b).hexdigest()
def generate():
 counts,total,_=d.score_model();seed=c.normalize('Sphinx of black quartz judge my vow while careful agents preserve every code and verify the reconstructed message');plain=(seed*20)[:200];ds,usage=c.encode_varying(plain,1,0,'driver-control');assert len(usage)==100 and ds[0]!='0' and ds[-1]!='0'
 paths=[]
 for hn in d.HEX_ORIENTS:
  for dn in d.DEC_ORIENTS:
   displayed,construction=d.construct(ds,dn,hn);rec,recovery=d.recover(displayed,dn,hn);assert rec==ds
   row=d.candidate_row(rec,dn,hn,1,0,displayed,counts,total);assert row['plaintext']==plain and row['observed_codes_valid_for_board'] and row['exact_integer_reencryption']
   paths.append({'id':f'{hn}|{dn}','displayed_sha256':h(displayed.encode()),'digits':len(rec),'truth_row':row,'construction':construction,'recovery':recovery})
 # One complete 4,000-board driver cell verifies IDs, retention, score order and exact-row assertions.
 displayed,_=d.construct(ds,'pair_reverse','nibble_swap');rows=[]
 for a in c.coprimes100():
  for b in range(100):rows.append(d.candidate_row(ds,'pair_reverse','nibble_swap',a,b,displayed,counts,total))
 assert len(rows)==4000 and len({r['id'] for r in rows})==4000 and all(r['observed_codes_valid_for_board'] and r['exact_integer_reencryption'] for r in rows)
 truth=next(i+1 for i,r in enumerate(sorted(rows,key=lambda r:(-r['score_per_tetragram'],r['a'],r['b']))) if (r['a'],r['b'])==(1,0))
 # Directed leading-zero cases: after parity restoration, further even zeros remain unknowable at the stated end.
 loss=[]
 natural={'identity':'00001234','swap_within_pair':'00001234','digit_reverse':'12340000','pair_reverse':'12340000'}
 for dn,s in natural.items():
  shown,_=d.construct(s,dn,'forward');rec,meta=d.recover(shown,dn,'forward');side=meta['additional_zero_pair_ambiguity_side'];assert len(rec)%2==0
  if side=='prefix':assert s.endswith(rec)
  else:assert s.startswith(rec)
  loss.append({'decimal_orientation':dn,'input':s,'recovered':rec,'unknown_side':side,'lost_digits':len(s)-len(rec)})
 return {'identity':IDENTITY,'target_evaluated':False,'driver_sha256':d.sha(HERE/'run_target.py'),'scope':d.scope(),'sixteen_full_chain_paths':paths,'complete_board_cell':{'rows':len(rows),'row_digest':h(''.join(h(d.canon(r).encode()) for r in rows).encode()),'truth_rank':truth,'all_exact':True},'leading_zero_controls':loss,'assertions':{'all_passed':True,'all_hex_decimal_paths':len(paths)==16,'complete_board_rows':len(rows)==4000}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();got=generate()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(got,indent=2,sort_keys=True)+'\n')
 else:assert json.loads((HERE/'controls.json').read_text())==got;print('PASS',d.sha(HERE/'controls.json'))
if __name__=='__main__':main()

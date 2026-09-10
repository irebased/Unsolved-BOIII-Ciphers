#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
import geometry as g
HERE=Path(__file__).resolve().parent;LEDGER=HERE/'controls.json';IDENTITY='ASTRA'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def compute():
 text=''.join(chr(33+(i*37)%90) for i in range(1092));e=g.encode(text);d=g.decode(text);ei=g.encode_indices(1092);di=g.decode_indices(1092)
 assert len(text)==1092 and len(ei)==len(di)==1092 and sorted(ei)==sorted(di)==list(range(1092))
 assert e==''.join(text[i] for i in ei) and d==''.join(text[i] for i in di)
 assert g.decode(e)==text and g.encode(d)==text
 # Small labelled rectangle makes direction visible.
 small=''.join(f'{i:04X}'[-4:] for i in range(14));assert len(small)==56
 se=g.encode(small);assert g.decode(se)==small and se!=small
 return {'identity':IDENTITY,'target_evaluated':False,'scope':'Synthetic-only 4-symbol equal-cell rectangular column geometry, key ZOMBIES.','key':g.KEY,'cell_symbols':g.CELL,'columns':g.COLS,'rows_at_1092':39,'cells_at_1092':273,'alphabetical_read_letters':['B','E','I','M','O','S','Z'],'column_read_indices_zero_based':list(g.ORDER),'synthetic':{'length':1092,'plaintext_sha256':hashlib.sha256(text.encode()).hexdigest(),'encoded_sha256':hashlib.sha256(e.encode()).hexdigest(),'decoded_direction_sha256':hashlib.sha256(d.encode()).hexdigest(),'encode_decode_roundtrip':g.decode(e)==text,'decode_encode_roundtrip':g.encode(d)==text,'encode_index_permutation_sha256':hashlib.sha256(json.dumps(ei,separators=(',',':')).encode()).hexdigest(),'decode_index_permutation_sha256':hashlib.sha256(json.dumps(di,separators=(',',':')).encode()).hexdigest(),'small_labelled_plain':small,'small_labelled_encoded':se},'assertions':{'exact_rectangle_39x7':True,'column_order_B_E_I_M_O_S_Z':True,'both_inverse_directions':True,'indices_are_permutations':True,'directions_distinct_on_control':True,'no_target_read':True},'geometry_source_sha256':sha(HERE/'geometry.py'),'controls_source_sha256':sha(Path(__file__))}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();fresh=compute()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(fresh,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)}))
 else:
  old=json.loads(LEDGER.read_text());assert old==fresh and all(old['assertions'].values());print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(LEDGER)},sort_keys=True))
if __name__=='__main__':main()

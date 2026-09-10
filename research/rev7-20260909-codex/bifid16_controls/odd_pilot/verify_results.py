#!/usr/bin/env python3
"""Read-only result/formula audit; never performs a new target solve."""
import argparse,gzip,hashlib,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import run_target as rt
MAX_SMT2_BYTES=10_000_000

def bounded_gunzip(path):
 assert path.stat().st_size<=MAX_SMT2_BYTES
 with gzip.open(path,'rb') as f:
  raw=f.read(MAX_SMT2_BYTES+1)
 assert len(raw)<=MAX_SMT2_BYTES
 return raw

def main():
 ap=argparse.ArgumentParser();ap.add_argument('result',nargs='?',type=Path,default=HERE/'target_results.json');a=ap.parse_args()
 gate=rt.require_gate();d=json.loads(a.result.read_text());assert d['identity']=='ASTRA' and d['target_evaluated'] is True
 assert d['scope']==gate['scope']=={'periods':list(rt.PERIODS),'orientations':list(rt.ORIENTS),'bag':rt.BAG,'prefix_bytes':rt.PREFIX,'timeout_ms_per_cell':rt.TIMEOUT_MS,'cells':16}
 assert d['source_hashes']==rt.sources() and d['driver_sha256']==rt.sha(HERE/'run_target.py') and d['gate_sha256']==rt.sha(HERE/'target_gate.json')
 text=rt.extract();expected=[(o,p) for o in rt.ORIENTS for p in rt.PERIODS];assert len(d['cells'])==len(expected)==16
 counts={s:0 for s in ('sat','unsat','unknown')};negative=0;sat=0
 for row,(orient,period) in zip(d['cells'],expected):
  assert row['cell_id']==f'{orient}_p{period}' and row['orientation']==orient and row['period']==period
  assert row['status'] in counts and row['bag']==rt.BAG and row['prefix_bytes']==rt.PREFIX and row['timeout_ms']==rt.TIMEOUT_MS
  counts[row['status']]+=1;negative+=int(row['classified_as_negative']);assert row['classified_as_negative']==(row['status']=='unsat')
  cipher=bytes.fromhex(rt.orientation(text,orient));assert hashlib.sha256(cipher).hexdigest()==row['ciphertext_sha256']
  dump=HERE/row['smt_dump']['path'];assert dump.is_file() and rt.sha(dump)==row['smt_dump']['gzip_sha256'] and dump.stat().st_size==row['smt_dump']['gzip_bytes']
  raw=bounded_gunzip(dump);assert hashlib.sha256(raw).hexdigest()==row['smt_dump']['smt2_sha256']
  solver,_,_,_,limit=rt.bagmode.build(cipher,period,rt.BAG,prefix_bytes=rt.PREFIX,timeout_ms=rt.TIMEOUT_MS)
  assert limit==rt.PREFIX and solver.sexpr().encode()==raw
  if row['status']=='sat':
   plain=rt.probe_decrypt(cipher,row['square'],period);assert len(plain)==len(cipher)==546 and plain.hex()==row['plaintext_hex'] and hashlib.sha256(plain).hexdigest()==row['plaintext_sha256']
   assert rt.probe_encrypt(plain,row['square'],period)==cipher and all(x in rt.BAG_VALUES for x in plain[:rt.PREFIX])
   assert rt.utf8_info(plain)=={k:row[k] for k in ('full_bag213','full_utf8_valid','full_exact_endpoint')};sat+=1
 assert counts=={k:d['summary'][k] for k in counts};assert negative==d['summary']['negative_claims']==counts['unsat']
 print(json.dumps({'identity':'ASTRA','ok':True,'target_evaluated':True,'verification_only':True,'new_target_search':False,'cells':16,'sat_models_recomputed':sat,'formulas_reconstructed':16,'summary':counts,'result_sha256':rt.sha(a.result)},sort_keys=True))
if __name__=='__main__':main()

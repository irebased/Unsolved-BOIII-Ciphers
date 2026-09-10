#!/usr/bin/env python3
"""Inert complete-result verifier: evidence union, inputs, formulas and SAT models."""
import argparse,gzip,hashlib,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import run_target as rt
MAX=10_000_000
def main():
 ap=argparse.ArgumentParser();ap.add_argument('result',nargs='?',type=Path,default=HERE/'target_results.json');a=ap.parse_args();gate=rt.require_gate();d=json.loads(a.result.read_text());s=rt.derive_scope();assert d['identity']=='ASTRA' and d['target_evaluated'] and d['status']=='complete' and d['scope']==gate['scope']==rt.public_scope(s) and len(d['cells'])==2175
 assert d['source_hashes']==rt.sources() and d['driver_sha256']==rt.sha(HERE/'run_target.py') and d['gate_sha256']==rt.sha(HERE/'target_gate.json') and d['checkpoint_sha256']==rt.sha(HERE/'checkpoint.jsonl');status=json.loads((HERE/'status.json').read_text());assert status['state']=='complete' and status['completed_cells']==2175 and status['result_sha256']==rt.sha(a.result)
 text=rt.extract();oriented={o:bytes.fromhex(rt.orientation(text,o)) for o in rt.ORIENTS};counts={q:0 for q in ('sat','unsat','unknown')}
 for row,(orient,period) in zip(d['cells'],s['fresh']):
  assert row['cell_id']==rt.cell_id(orient,period) and row['orientation']==orient and row['period']==period and row['status'] in counts and row['bag']==213 and row['prefix_bytes']==546 and row['timeout_ms']==10000;counts[row['status']]+=1;assert row['classified_as_negative']==(row['status']=='unsat');cipher=oriented[orient];assert hashlib.sha256(cipher).hexdigest()==row['ciphertext_sha256'];dump=HERE/row['smt_dump']['path'];assert dump.stat().st_size<=MAX and rt.sha(dump)==row['smt_dump']['gzip_sha256'] and dump.stat().st_size==row['smt_dump']['gzip_bytes']
  with gzip.open(dump,'rb') as f:raw=f.read(MAX+1)
  assert len(raw)<=MAX and hashlib.sha256(raw).hexdigest()==row['smt_dump']['smt2_sha256'];solver,_,_,_,limit=rt.bagmode.build(cipher,period,213,prefix_bytes=546,timeout_ms=10000);assert limit==546 and solver.sexpr().encode()==raw
  if row['status']=='sat':plain=rt.probe_decrypt(cipher,row['square'],period);assert len(plain)==546 and plain.hex()==row['plaintext_hex'] and hashlib.sha256(plain).hexdigest()==row['plaintext_sha256'] and rt.probe_encrypt(plain,row['square'],period)==cipher and all(x in rt.BAG_VALUES for x in plain);assert rt.utf8_info(plain)=={k:row[k] for k in ('full_bag213','full_utf8_valid','full_exact_endpoint')}
 assert counts=={k:d['summary'][k] for k in counts} and d['summary']['negative_claims']==counts['unsat'];lines=[json.loads(x) for x in (HERE/'checkpoint.jsonl').read_text().splitlines()];assert lines==d['cells'];print(json.dumps({'identity':'ASTRA','ok':True,'verification_only':True,'new_target_search':False,'complete_cells':2175,'formulas_reconstructed':2175,'summary':counts,'result_sha256':rt.sha(a.result)},sort_keys=True))
if __name__=='__main__':main()

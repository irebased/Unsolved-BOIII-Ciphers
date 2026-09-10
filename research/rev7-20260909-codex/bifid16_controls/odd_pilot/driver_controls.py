#!/usr/bin/env python3
"""Synthetic-only wiring controls for the inert odd-period pilot."""
import hashlib,json,random,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import run_target as rt
IDENTITY='ASTRA'
def main():
 rng=random.Random(20260911);sq=list(range(16));rng.shuffle(sq);pos=[0]*16
 for i,s in enumerate(sq):pos[s]=i
 fixed={s:pos[s] for s in range(16)}
 allowed=(b'Synthetic bag pilot '+bytes.fromhex('e28093')+b'\t')*3
 bad=bytes([0xff])+allowed[1:]
 rows=[]
 with tempfile.TemporaryDirectory() as td:
  t=Path(td)
  for label,plain,want in [('positive',allowed,'sat'),('forbidden_first_byte',bad,'unsat')]:
   cipher=rt.bifid16.encrypt_bytes(plain,sq,31);row=rt.solve_cell(cipher,label,31,t/f'{label}.gz',fixed=fixed,timeout_ms=10000);assert row['status']==want
   if want=='sat':assert bytes.fromhex(row['plaintext_hex'])==plain and row['independent_reencrypt_equal']
   rows.append({'label':label,'period':31,'plaintext_hex':plain.hex(),'ciphertext_hex':cipher.hex(),'status':row['status'],'classified_as_negative':row['classified_as_negative'],'smt2_sha256':row['smt_dump']['smt2_sha256']})
 orientations={x:rt.orientation('123456',x) for x in rt.ORIENTS};assert len(set(orientations.values()))==4
 out={'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'seed':20260911,'orientation_fixture':orientations,'fixed_square':sq,'cells':rows,'assertions':{'positive_sat_and_exact':True,'forbidden_fixed_square_unsat':True,'all_four_orientations_exact':True},'source_hashes':{'run_target.py':rt.sha(HERE/'run_target.py'),'driver_controls.py':rt.sha(Path(__file__))}}
 dest=Path(sys.argv[1]) if len(sys.argv)>1 else HERE/'driver_controls.json'
 if dest.exists():raise SystemExit('refusing existing output')
 dest.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':IDENTITY,'sha256':rt.sha(dest),'statuses':[x['status'] for x in rows]}))
if __name__=='__main__':main()

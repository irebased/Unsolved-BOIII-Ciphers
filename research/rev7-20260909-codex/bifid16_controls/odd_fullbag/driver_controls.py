#!/usr/bin/env python3
"""Fixed-square synthetic controls proving the full-bag extension is active."""
import hashlib,json,random,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import run_target as rt
IDENTITY='ASTRA'
def main():
 rng=random.Random(20260911);sq=list(range(16));rng.shuffle(sq);pos=[0]*16
 for i,s in enumerate(sq):pos[s]=i
 fixed={s:pos[s] for s in range(16)};unit=b'Full bag extension '+bytes.fromhex('e28093')+b'\t\r\n';good=(unit*(546//len(unit)+1))[:546];bad=good[:-1]+b'\xff';rows=[]
 for label,plain,prefix,want in [('valid_full546',good,546,'sat'),('bad_final_full546',bad,546,'unsat'),('bad_final_prefix128',bad,128,'sat')]:
  cipher=rt.probe_encrypt(plain,sq,31);row=rt.solve_cell(cipher,label,31,prefix_bytes=prefix,fixed=fixed)
  assert row['status']==want
  if want=='sat':assert bytes.fromhex(row['plaintext_hex'])==plain and rt.probe_decrypt(cipher,sq,31)==plain
  rows.append({'label':label,'period':31,'prefix_bytes':prefix,'status':row['status'],'plaintext_hex':plain.hex(),'plaintext_sha256':hashlib.sha256(plain).hexdigest(),'ciphertext_hex':cipher.hex(),'ciphertext_sha256':hashlib.sha256(cipher).hexdigest(),'smt2_sha256':row['smt_dump']['smt2_sha256'],'independent_roundtrip':want!='sat' or row['independent_reencrypt_equal']})
 assert rows[1]['status']=='unsat' and rows[2]['status']=='sat'
 out={'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'seed':20260911,'truth_square':sq,'cells':rows,'assertions':{'valid_full_sat_exact':True,'final_forbidden_full_unsat':True,'same_final_forbidden_prefix128_sat':True,'extension_active':True,'sat_rows_independently_decode_reencrypt':True},'source_hashes':{'run_target.py':rt.sha(HERE/'run_target.py'),'driver_controls.py':rt.sha(Path(__file__))}}
 dest=Path(sys.argv[1]) if len(sys.argv)>1 else HERE/'driver_controls.json'
 if dest.exists():raise SystemExit('refusing existing output')
 dest.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':IDENTITY,'sha256':rt.sha(dest),'statuses':[x['status'] for x in rows]}))
if __name__=='__main__':main()

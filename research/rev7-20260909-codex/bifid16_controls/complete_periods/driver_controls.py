#!/usr/bin/env python3
"""Small fixed-square dispatch controls; reads only frozen prior target ledgers."""
import hashlib,json,random,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import run_target as rt
def main():
 rng=random.Random(20260911);square=list(range(16));rng.shuffle(square);pos=[0]*16
 for i,s in enumerate(square):pos[s]=i
 fixed={s:pos[s] for s in range(16)};cases=[];spec=(('forward',1,17),('reverse',3,18),('byte_reverse',16,31),('nibble_swap',31,33))
 with tempfile.TemporaryDirectory() as td:
  td=Path(td)
  for orient,period,n in spec:
   unit=b'Dispatch '+bytes.fromhex('e28093')+b'\t';good=(unit*(n//len(unit)+1))[:n]
   for kind,plain,want in (('positive',good,'sat'),('last_ff',good[:-1]+b'\xff','unsat')):
    cipher=rt.probe_encrypt(plain,square,period);canonical=rt.orientation(cipher.hex().upper(),orient);dispatched=bytes.fromhex(rt.orientation(canonical,orient));assert dispatched==cipher
    row=rt.solve_cell(dispatched,f'{orient}_{kind}',period,td/f'{orient}_{kind}.gz',fixed=fixed);assert row['status']==want
    if want=='sat':assert bytes.fromhex(row['plaintext_hex'])==plain and row['independent_decrypt_reencrypt']
    cases.append({'orientation':orient,'period':period,'bytes':n,'final_block_symbols':(2*n)%period or period,'kind':kind,'status':want,'canonical_hex':canonical,'ciphertext_sha256':hashlib.sha256(cipher).hexdigest(),'smt2_sha256':row['smt_dump']['smt2_sha256']})
 out={'identity':'ASTRA','target_evaluated':False,'prior_target_ledgers_read':True,'canonical_ciphertext_extracted':False,'fresh_target_computation':False,'seed':20260911,'truth_square':square,'cases':cases,'assertions':{'eight_fixed_square_cases':len(cases)==8,'varied_periods_and_final_blocks':True,'all_orientation_dispatch_exact':True,'all_positive_sat':True,'all_last_ff_fullbag_unsat':True,'sat_independent_roundtrip':True},'derived_scope_without_target':rt.public_scope(rt.derive_scope()),'source_hashes':{'run_target.py':rt.sha(HERE/'run_target.py'),'driver_controls.py':rt.sha(Path(__file__))}}
 dest=Path(sys.argv[1]) if len(sys.argv)>1 else HERE/'driver_controls.json'
 if dest.exists():raise SystemExit('refusing existing output')
 dest.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':'ASTRA','sha256':rt.sha(dest),'cases':len(cases),'fresh_cells':out['derived_scope_without_target']['fresh_cells']}))
if __name__=='__main__':main()

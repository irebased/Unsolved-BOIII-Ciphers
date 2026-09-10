#!/usr/bin/env python3
from pathlib import Path
import argparse,hashlib,json,sys
HERE=Path(__file__).resolve().parent;PKG=HERE.parent;sys.path.insert(0,str(HERE));import run_target as d;sys.path.insert(0,str(PKG));import case_frontier as case
IDENTITY='ASTRA'
def hb(b):return hashlib.sha256(b).hexdigest()
def plant():
 s='Quiet agents map lower words Title Words and ALLCAPS safely through every register while preserving exact case and spaces '
 return (s*((819+len(s)-1)//len(s)))[:819].encode()
def generate():
 legacy=d.load_legacy();plain=plant();assert case.regex_accept(plain.decode());rows=[]
 for c in d.CIPHERS:
  for ivname in d.IVS:
   iv=d.iv_for(ivname,c);ct=case.core.encrypt_cfb8(c,iv,plain);observed=case.core.lossy_emit(ct.hex().upper());assert legacy.legacy_encode(ct.hex().upper().encode(),'2016')['raw'].decode()==observed
   for o in d.ORIENTS:
    canonical=d.orient(observed,o);cell=d.run_cell(canonical,o,c,ivname,legacy);truth=[x for x in cell['solutions'] if x['plaintext_sha256']==hb(plain) and x['ciphertext_sha256']==hb(ct)]
    assert cell['complete'] and truth and all(all(v is True for v in x['independent_verification'].values()) for x in cell['solutions'])
    rows.append({'id':cell['id'],'canonical_sha256':hb(canonical.encode()),'observed_sha256':hb(observed.encode()),'truth_retained':True,'solution_count':len(cell['solutions']),'extra_solutions':len(cell['solutions'])-1,'max_frontier':cell['max_frontier'],'accepted_states':cell['accepted_states'],'block_calls':cell['block_calls'],'inverse_orientation_exact':cell['inverse_orientation_exact']})
 expected={f'{o}|{c}|{v}' for o in d.ORIENTS for c in d.CIPHERS for v in d.IVS};assert len(rows)==16 and {x['id'] for x in rows}==expected
 return {'identity':IDENTITY,'target_evaluated':False,'case_frontier_sha256':d.sha(PKG/'case_frontier.py'),'driver_sha256':d.sha(HERE/'run_target.py'),'scope':d.scope(),'mixed_case_plant':{'bytes':819,'plaintext_sha256':hb(plain),'regex_accept':True,'contexts':rows},'assertions':{'all_16_paths_complete':True,'all_truths_retained':True,'all_solutions_independent_cfb_legacy_regex_dfa':True,'all_orientations_invert':True}}
def main():
 a=argparse.ArgumentParser();a.add_argument('--regenerate',type=Path);x=a.parse_args();got=generate()
 if x.regenerate:
  if x.regenerate.exists():raise SystemExit('refusing existing output')
  x.regenerate.write_text(json.dumps(got,indent=2,sort_keys=True)+'\n')
 else:assert json.loads((HERE/'controls.json').read_text())==got;print('PASS',d.sha(HERE/'controls.json'))
if __name__=='__main__':main()

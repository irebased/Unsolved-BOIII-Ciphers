#!/usr/bin/env python3
from pathlib import Path
import argparse,hashlib,json,sys
HERE=Path(__file__).resolve().parent;PKG=HERE.parent;sys.path.insert(0,str(HERE));import run_target as d;sys.path.insert(0,str(PKG));import core
IDENTITY='ASTRA'
def hb(b):return hashlib.sha256(b).hexdigest()
def text819():
 s=''.join(c for c in 'Quiet archivists preserve every exact branch while lanterns mark the complete cipher register. '.upper() if c==' ' or 'A'<=c<='Z');return (s*((819+len(s)-1)//len(s)))[:819].encode()
def generate():
 legacy=d.load_legacy();plain=text819();rows=[]
 for c in d.CIPHERS:
  _,bs,key=core.cipher_spec(c)
  for ivname in d.IVS:
   iv=d.iv_for(ivname,c);ct=core.encrypt_cfb8(c,iv,plain);observed=legacy.legacy_encode(ct.hex().upper().encode(),'2016')['raw'].decode();assert observed==core.lossy_emit(ct.hex().upper())
   for o in d.ORIENTS:
    canonical=d.orient(observed,o);cell=d.run_cell(canonical,o,c,ivname,legacy);truth=[x for x in cell['solutions'] if x['plaintext_sha256']==hb(plain) and x['ciphertext_sha256']==hb(ct)]
    assert cell['complete'] and truth and cell['inverse_orientation_exact'] and all(all(v is True for v in x['independent_verification'].values()) for x in cell['solutions'])
    rows.append({'id':cell['id'],'canonical_sha256':hb(canonical.encode()),'observed_sha256':hb(observed.encode()),'truth_retained':True,'solution_count':len(cell['solutions']),'extra_solutions':len(cell['solutions'])-1,'max_frontier':cell['max_frontier'],'accepted_states':cell['accepted_states'],'block_calls':cell['block_calls'],'inverse_orientation_exact':True})
 assert len(rows)==16 and {x['id'] for x in rows}=={f'{o}|{c}|{iv}' for o in d.ORIENTS for c in d.CIPHERS for iv in d.IVS}
 return {'identity':IDENTITY,'target_evaluated':False,'driver_sha256':d.sha(HERE/'run_target.py'),'scope':d.scope(),'plant':{'bytes':819,'plaintext_sha256':hb(plain),'contexts':rows},'assertions':{'all_16_paths_complete':True,'all_truths_retained':True,'all_solutions_independently_verified':True,'all_source_emissions_exact':True}}
def main():
 a=argparse.ArgumentParser();a.add_argument('--regenerate',type=Path);x=a.parse_args();got=generate()
 if x.regenerate:
  if x.regenerate.exists():raise SystemExit('refusing existing output')
  x.regenerate.write_text(json.dumps(got,indent=2,sort_keys=True)+'\n')
 else:
  old=json.loads((HERE/'controls.json').read_text());assert old==got;print('PASS',d.sha(HERE/'controls.json'))
if __name__=='__main__':main()

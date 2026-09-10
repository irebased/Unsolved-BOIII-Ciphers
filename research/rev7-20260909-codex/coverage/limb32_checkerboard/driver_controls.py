#!/usr/bin/env python3
"""ASTRA synthetic wiring control for the inert limb32 target driver."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,sys
HERE=Path(__file__).resolve().parent;DEFAULT=HERE/'driver_controls.json'
PINS={'model.py':'1f479f1697d84ee16a2cd9f89568756b9d30878418fe810206da9c683bc14725','anneal.py':'6937961a714e4ec0e26b5d1c5584f001d8b6a381155f76b0e79c8477246c6d79','sibling_char4.json':'7752ce6f93d12079cf9e567d9f0dddf37178f8b40f7907ee6d7c733383969b01'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
def build():
 assert all(sha(HERE/k)==v for k,v in PINS.items());m=load('limb_driver_control_model',HERE/'model.py');d=load('limb_driver_control_target',HERE/'run_target.py')
 digits=m.encode_fixed('HLIMBHHH');raw=m.deserialize(digits,6,'big','forward','forward');serializers,rows,patterns=d.scan(raw.hex())
 assert len(serializers)==32 and len(rows)==1440
 rid='ori=forward|endian=big|limbs=forward|digits=forward|headers=3,7';row=next(x for x in rows if x['id']==rid)
 assert row['complete'] and row['fixed_rev3_complete'] and row['fixed_rev3_plaintext']=='HLIMBHHH' and row['distinct_tokens']==len(set(m.parse_tokens(digits,(3,7))))
 # Independently recompute all IoCs and ordering/dedup identities.
 for p in patterns:
  n=len(p['tokens']);counts={x:p['tokens'].count(x) for x in set(p['tokens'])};v=sum(c*(c-1) for c in counts.values())/(n*(n-1)) if n>1 else 0.0
  assert abs(v-p['token_ioc'])<1e-15 and p['token_sequence_sha256']==hashlib.sha256('|'.join(p['tokens']).encode()).hexdigest()
 assert patterns==sorted(patterns,key=lambda x:(-x['token_ioc'],x['first_id']))
 return {'identity':'ASTRA','target_evaluated':False,'canonical_ciphertext_extracted':False,'source_pins':PINS,'fixture':{'plaintext':'HLIMBHHH','digits':digits,'canonical_hex':raw.hex().upper(),'cells':len(rows),'serializers':len(serializers),'unique_complete_patterns':len(patterns),'fixed_rev3_row':row},'assertions':{'same_scan_path':True,'exact_grid_1440':True,'fixed_rev3_full_chain':True,'independent_ioc_all_patterns':True,'stable_selection_order':True},'driver_source_sha256':sha(HERE/'run_target.py'),'control_source_sha256':sha(Path(__file__))}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--generate',type=Path);a=ap.parse_args();out=build()
 if a.generate:
  if a.generate.exists():raise SystemExit('refusing existing output')
  a.generate.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');print(json.dumps({'written':str(a.generate),'sha256':sha(a.generate)}));return
 saved=json.loads(DEFAULT.read_text());assert saved==out;print(json.dumps({'identity':'ASTRA','status':'PASS','ledger_sha256':sha(DEFAULT),'cells':out['fixture']['cells']}))
if __name__=='__main__':main()

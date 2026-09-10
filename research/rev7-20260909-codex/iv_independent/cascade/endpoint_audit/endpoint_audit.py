#!/usr/bin/env python3
import argparse, hashlib, importlib.util, itertools, json, re
from pathlib import Path
HERE=Path(__file__).resolve().parent
SRC=HERE.parent/'target/run_target.py'
EXPECTED_SOURCE='dea3bceff94993abb7f59993300f71552c3ca84b344e96b22d27479c3dc05d41'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(SRC)==EXPECTED_SOURCE
spec=importlib.util.spec_from_file_location('current_target',SRC)
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
TOKEN=rb'(?:[\x09\x0a\x0d\x20-\x7e]|\xe2\x80[\x93\x94\x98\x99\xa6])*'
RX=re.compile(rb'\A'+TOKEN+rb'\Z')
LEFT_INTERNAL=(b'',b'\xe2',b'\xe2\x80')
RIGHT_INTERNAL=(b'',b'\x80\x93',b'\x93')
THIRDS=(0x93,0x94,0x98,0x99,0xa6)
CATS=(b'A',b'\x09',b'\x0a',b'\x0d',b' ',b'~',b'\x00',b'\xff',b'\xe2',b'\x80',*(bytes([x]) for x in THIRDS),b'\x81',b'\xc2')
def regex_endpoint(data,lb,rb):
 ps=(b'',) if lb else LEFT_INTERNAL; ss=(b'',) if rb else RIGHT_INTERNAL
 return any(RX.fullmatch(x+data+y) is not None for x in ps for y in ss)
def fsa_endpoint(data,lb,rb):
 left=0 if lb else 3; right=left+len(data); total=right if rb else right+3
 return mod.endpoint(data,left,right,total)['accepted'] is True
def empty_coords(lb,rb):
 left=0 if lb else 3; right=left
 return left,right,(right if rb else right+3)
def verify_result(path):
 d=json.loads(path.read_text()); assert d['identity']=='ASTRA' and d['source_hashes']['run_target.py']==EXPECTED_SOURCE
 assert d['target_evaluated'] is False and d['rev7_read'] is False and d['cases']==354960 and not d['mismatches']
 print(json.dumps({'identity':'ASTRA','verified':True,'ledger_sha256':sha(path),'source_sha256':EXPECTED_SOURCE,'cases':d['cases'],'mismatches':len(d['mismatches'])},sort_keys=True))
def produce(out):
 if out.exists(): raise SystemExit('refusing existing output: '+str(out))
 cases=0; mismatches=[]; dist={}
 for n in range(1,5):
  for tup in itertools.product(CATS,repeat=n):
   data=b''.join(tup)
   for lb,rb,label in ((True,True,'real_real'),(False,False,'internal_internal'),(False,True,'internal_realright'),(True,False,'realleft_internalright')):
    a=fsa_endpoint(data,lb,rb); b=regex_endpoint(data,lb,rb); cases+=1; k=(label,a,b); dist[k]=dist.get(k,0)+1
    if a!=b and len(mismatches)<20: mismatches.append({'data_hex':data.hex(),'left_boundary':lb,'right_boundary':rb,'fsa':a,'regex':b})
 empty=[]
 for lb,rb,label in ((True,True,'real_real'),(False,False,'internal_internal'),(False,True,'internal_realright'),(True,False,'realleft_internalright')):
  left,right,total=empty_coords(lb,rb); x=mod.endpoint(b'',left,right,total)
  empty.append({'mode':label,'coordinates':[left,right,total],'fsa_classification':x['classification'],'fsa_accepted':x['accepted'],'regex_would_match':regex_endpoint(b'',lb,rb)})
 result={'identity':'ASTRA','target_evaluated':False,'rev7_read':False,'crypto_evaluated':False,'scope':'Synthetic endpoint audit only; category-product byte strings of lengths 1..4.','oracle':{'engine':'Python re.fullmatch compiled once','language':'TAB/LF/CR, ASCII 32..126, and exact UTF-8 E2 80 (93|94|98|99|A6)','internal_left_completions':['','e2','e280'],'internal_right_completions':['','8093','93'],'real_boundary_completion':'empty only'},'categories':[x.hex() for x in CATS],'category_count':len(CATS),'tested_lengths':[1,2,3,4],'boundary_modes':['real_real','internal_internal','internal_realright','realleft_internalright'],'cases':cases,'mismatches':mismatches,'empty_interval':empty,'source_hashes':{'run_target.py':EXPECTED_SOURCE},'assertions':{'all_nonempty_boolean_results_equal':not mismatches,'no_counterexample':not mismatches,'empty_interval_separate_inconclusive':all(x['fsa_classification']=='inconclusive_empty' for x in empty)}}
 result['distribution']={'%s/fsa=%s/regex=%s'%k:v for k,v in dist.items()}; out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n'); assert not mismatches
 print(json.dumps({'identity':'ASTRA','output':str(out),'sha256':sha(out),'source_sha256':EXPECTED_SOURCE,'cases':cases,'mismatches':len(mismatches)},sort_keys=True))
if __name__=='__main__':
 ap=argparse.ArgumentParser(); ap.add_argument('--output',type=Path); ap.add_argument('--verify',type=Path); a=ap.parse_args()
 if a.verify: verify_result(a.verify)
 elif a.output: produce(a.output)
 else: raise SystemExit('use --output NEW_PATH or --verify EXISTING_PATH')

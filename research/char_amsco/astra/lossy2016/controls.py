#!/usr/bin/env python3
"""Synthetic-only controls for lossy AMSCO-2016 masked CFB8."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];sys.path.insert(0,str(HERE));import core
IDENTITY='ASTRA';ANALYZE=ROOT/'research/char_amsco/astra/cryptool_bug/analyze.py';ANALYZE_SHA='ba66b3c844cf5784749587af960a11163d5e47deddf523a04530bea4f5d9629b'
def h(b):return hashlib.sha256(b).hexdigest()
def fixed_text(seed,n):
 s=''.join(c for c in seed.upper() if c==' ' or 'A'<=c<='Z');return (s*((n+len(s)-1)//len(s)))[:n].encode()
def random_observed(chars):
 out='';i=0
 while len(out)<chars:
  out+=''.join('0123456789ABCDEF'[x&15] for x in hashlib.sha256(f'LOSSY2016 RANDOM {i}'.encode()).digest());i+=1
 return out[:chars]
def load_source_port():
 assert h(ANALYZE.read_bytes())==ANALYZE_SHA
 sp=importlib.util.spec_from_file_location('legacy',ANALYZE);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);m.verify_pins();return m
def generate():
 legacy=load_source_port();source_checks=[]
 for n in (3,6,99,819):
  hx=('0123456789ABCDEF'*((2*n+15)//16))[:2*n];direct=core.lossy_emit(hx);actual=legacy.legacy_encode(hx.encode(),'2016')['raw'].decode();assert direct==actual
  vals,masks=core.reconstruct_masks(direct,n);expected=bytes(core.MASK_CYCLE*(n//3));assert masks==expected
  original=bytes.fromhex(hx);assert all((v&m)==(c&m) for v,m,c in zip(vals,masks,original))
  source_checks.append({'bytes':n,'input_sha256':h(hx.encode()),'emission_sha256':h(direct.encode()),'emitted_chars':len(direct),'mask_sha256':h(masks),'mask_cycle':['ff','0f','f0'],'legacy_equal':True})
 texts=[('short99',fixed_text('Quiet agents map every surviving nibble and preserve each exact branch for review. ',99)),('full819',fixed_text('Lanterns glow above the archive while patient readers trace every byte through the cipher register and record the complete message without guessing. ',819))]
 plants=[]
 for tid,plain in texts:
  assert len(plain)%3==0 and set(plain)<=set(core.ALLOWED)
  for name in ('des','aes128'):
   _,bs,key=core.cipher_spec(name)
   for ivname,iv in [('nul',bytes(bs)),('ascii0',b'0'*bs)]:
    ct=core.encrypt_cfb8(name,iv,plain);assert core.manual_decrypt(name,iv,ct)==plain
    observed=core.lossy_emit(ct.hex().upper());assert legacy.legacy_encode(ct.hex().upper().encode(),'2016')['raw'].decode()==observed
    r=core.search(name,iv,observed,len(plain));truth=(h(plain),h(ct));sol={(x['plaintext_sha256'],x['ciphertext_sha256']) for x in r['solutions']}
    assert r['complete'] and truth in sol
    plants.append({'id':f'{tid}|{name}|{ivname}','text_id':tid,'bytes':len(plain),'cipher':name,'key_hex':key.hex(),'iv_hex':iv.hex(),'plaintext_sha256':h(plain),'ciphertext_sha256':h(ct),'observed_sha256':h(observed.encode()),'observed_chars':len(observed),'truth_retained':True,'solution_count':len(r['solutions']),'extra_solution_count':len(r['solutions'])-1,'solutions':r['solutions'],'frontier_counts':r['frontier_counts'],'max_frontier':r['max_frontier'],'accepted_states':r['accepted_states'],'block_calls':r['block_calls'],'seconds':r['seconds'],'complete':r['complete']})
 # Separately labeled alphabet-size calibration reuses the exact DES/NUL short99 ciphertext and mask.
 base=next(x for x in plants if x['id']=='short99|des|nul');truth_solution=next(x for x in base['solutions'] if x['plaintext_sha256']==base['plaintext_sha256'] and x['ciphertext_sha256']==base['ciphertext_sha256']);wide_observed=core.lossy_emit(bytes.fromhex(truth_solution['ciphertext_hex']).hex().upper());assert h(wide_observed.encode())==base['observed_sha256'];wide_allowed=bytes([32]+list(range(65,91))+list(range(97,123)))
 wide=core.search('des',bytes(8),wide_observed,99,allowed=wide_allowed)
 truth_globally_consistent=all((c&m)==(v&m) for c,v,m in zip(bytes.fromhex(truth_solution['ciphertext_hex']),*core.reconstruct_masks(wide_observed,99))) and set(bytes.fromhex(truth_solution['plaintext_hex']))<=set(wide_allowed)
 truth_in_complete_solutions=any(x['plaintext_sha256']==base['plaintext_sha256'] and x['ciphertext_sha256']==base['ciphertext_sha256'] for x in wide['solutions']) if wide['complete'] else None
 wide_control={'id':'short99|des|nul|alphabet53','allowed_count':len(wide_allowed),'same_observed_as_27_case':True,'complete':wide['complete'],'capped_reason':wide.get('capped_reason'),'solution_count':len(wide['solutions']) if wide['complete'] else None,'truth_in_complete_solutions':truth_in_complete_solutions,'truth_globally_mask_consistent':truth_globally_consistent,'frontier_counts':wide['frontier_counts'],'max_frontier':wide['max_frontier'],'accepted_states':wide['accepted_states'],'block_calls':wide['block_calls'],'seconds':wide['seconds'],'classification':'method calibration only; cap is incomplete, not exclusion'}
 assert truth_globally_consistent and ((not wide['complete']) or truth_in_complete_solutions)
 obs=random_observed(1092);nulls=[]
 for name in ('des','aes128'):
  _,bs,key=core.cipher_spec(name)
  for ivname,iv in [('nul',bytes(bs)),('ascii0',b'0'*bs)]:
   r=core.search(name,iv,obs,819);nulls.append({'id':f'random819|{name}|{ivname}','cipher':name,'iv_hex':iv.hex(),'observed_sha256':h(obs.encode()),'complete':r['complete'],'solution_count':len(r['solutions']),'frontier_counts':r['frontier_counts'],'max_frontier':r['max_frontier'],'accepted_states':r['accepted_states'],'block_calls':r['block_calls'],'seconds':r['seconds'],'stopped_after_bytes':r['stopped_after_bytes']})
 assert all(x['complete'] for x in plants+nulls)
 return {'identity':IDENTITY,'target_evaluated':False,'source_hashes':{'core.py':h((HERE/'core.py').read_bytes()),'cryptool_bug/analyze.py':ANALYZE_SHA},'model':{'legacy_key':'2016','input_hex_chars_for_819_bytes':1638,'observed_hex_chars':1092,'natural_byte_mask_cycle':['ff','0f','f0'],'ciphers':{'des':{'key_hex':b'Zombies\0'.hex(),'block_size':8},'aes128':{'key_hex':(b'Zombies'+b'\0'*9).hex(),'block_size':16}},'ivs':['NUL block','ASCII 0 block'],'allowed_plaintext':'A-Z plus SPACE','max_frontier':100000,'max_accepted_states':5000000,'branching_estimate':{'value':27**3/65536,'formula':'27^3/65536','classification':'heuristic only; not a bound or guarantee'}},'source_mask_checks':source_checks,'plants':plants,'alphabet53_calibration':wide_control,'random_nulls':nulls,'assertions':{'all_source_emissions_match':True,'all_masks_repeat_ff_0f_f0':True,'all_library_cfb8_match_manual':True,'all_plants_retain_exact_truth':True,'all_original27_runs_complete':True},'limits':['Synthetic data only; no Rev7 bytes read.','Every frontier path is retained until completion or an explicit cap; capped output would be INCOMPLETE.','Alphabet is exactly uppercase A-Z and SPACE.','Fixed key and IV cells only; no arbitrary-IV theorem is claimed.']}
def stable(x):
 if isinstance(x,dict):return {k:stable(v) for k,v in x.items() if k!='seconds'}
 if isinstance(x,list):return [stable(v) for v in x]
 return x
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();got=generate()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(got,indent=2,sort_keys=True)+'\n')
 else:
  old=json.loads((HERE/'controls.json').read_text());assert stable(old)==stable(got);print('PASS',h((HERE/'controls.json').read_bytes()))
if __name__=='__main__':main()

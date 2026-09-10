#!/usr/bin/env python3
import argparse,hashlib,json,re,time,sys,importlib.util
from Crypto.Cipher import AES,DES
from pathlib import Path
HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[3]; sys.path.insert(0,str(ROOT/'research/char_amsco/astra/lossy2016')); import core
IDENTITY='ASTRA'; ALLOWED=bytes([32]+list(range(65,91))+list(range(97,123)))
CORE_SHA='869f707b0f7ff318f576db14c6cbd2b7f9e3bac1495126e0fb06312aa010d75a'
LEGACY_SHA='ba66b3c844cf5784749587af960a11163d5e47deddf523a04530bea4f5d9629b'
LEGACY_PATH=ROOT/'research/char_amsco/astra/cryptool_bug/analyze.py'
def load_legacy():
 assert sha(LEGACY_PATH)==LEGACY_SHA
 sp=importlib.util.spec_from_file_location('legacy_case',LEGACY_PATH);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m);m.verify_pins();return m
def library_decrypt(name,iv,ct):
 if name=='des': return DES.new(b'Zombies\0',DES.MODE_CFB,iv=iv,segment_size=8).decrypt(ct)
 return AES.new(b'Zombies'+b'\0'*9,AES.MODE_CFB,iv=iv,segment_size=8).decrypt(ct)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
LEGACY=load_legacy()
def transition(st,b):
 if b==32:return 'B' if st in ('B','L','U','C') else None
 if 97<=b<=122:return {'B':'L','U':'L','L':'L'}.get(st)
 if 65<=b<=90:return {'B':'U','U':'C','C':'C'}.get(st)
 return None
def regex_accept(x):
 try:return re.fullmatch(r' *(?:(?:[a-z]+|[A-Z][a-z]*|[A-Z]+)(?: +(?:[a-z]+|[A-Z][a-z]*|[A-Z]+))*)? *',x) is not None
 except: return False
def frontier(name,iv,observed,nbytes,max_frontier=100000,max_accepted=5000000):
 vals,masks=core.reconstruct_masks(observed,nbytes); e,_,_=core.cipher_spec(name); frontier=[(iv,b'',b'','B')]; counts=[]; accepted=0; calls=0
 for pos,(v,m) in enumerate(zip(vals,masks)):
  nxt=[]
  for reg,pt,ct,st in frontier:
   k=e.encrypt(reg)[0]; calls+=1
   choices=ALLOWED if m!=255 else [v^k]
   for p in choices:
    ns=transition(st,p)
    if ns is None:continue
    c=(p^k) if m!=255 else v
    if m==255 and p!=c^k:continue
    if m!=255 and (c&m)!=(v&m):continue
    nxt.append((reg[1:]+bytes([c]),pt+bytes([p]),ct+bytes([c]),ns))
   if len(nxt)>max_frontier:return {'complete':False,'capped_reason':'max_frontier','stopped_after_bytes':pos+1,'frontier_counts':counts,'max_frontier':max(counts+[len(nxt)]),'accepted_states':accepted+len(nxt),'block_calls':calls,'solutions':[]}
  accepted+=len(nxt);counts.append(len(nxt));
  if accepted>max_accepted:return {'complete':False,'capped_reason':'max_accepted','stopped_after_bytes':pos+1,'frontier_counts':counts,'max_frontier':max(counts),'accepted_states':accepted,'block_calls':calls,'solutions':[]}
  frontier=nxt
  if not frontier:break
 return {'complete':True,'capped_reason':None,'stopped_after_bytes':len(counts),'frontier_counts':counts,'max_frontier':max(counts,default=1),'accepted_states':accepted,'block_calls':calls,'solutions':[{'plaintext_hex':p.hex(),'ciphertext_hex':c.hex(),'state':s} for _,p,c,s in frontier]}
def plant(seed,n):
 s=(seed*((n+len(seed)-1)//len(seed)))[:n]; return s.encode()
def run_control(label,name,iv,plain):
 ct=core.encrypt_cfb8(name,iv,plain); assert core.manual_decrypt(name,iv,ct)==plain
 obs=core.lossy_emit(ct.hex().upper()); r=frontier(name,iv,obs,len(plain)); truth=False
 for x in r['solutions']:
  pp=bytes.fromhex(x['plaintext_hex']); cc=bytes.fromhex(x['ciphertext_hex']); st='B'
  for b in pp: st=transition(st,b)
  assert st is not None and st==x['state'] and len(pp)==len(plain) and len(cc)==len(plain)
  assert core.encrypt_cfb8(name,iv,pp)==cc
  assert library_decrypt(name,iv,cc)==pp and core.manual_decrypt(name,iv,cc)==pp
  assert LEGACY.legacy_encode(cc.hex().upper().encode(),'2016')['raw'].decode()==obs and core.lossy_emit(cc.hex().upper())==obs
  assert regex_accept(pp.decode('ascii'))
  if pp==plain and cc==ct: truth=True
 return {'id':label,'cipher':name,'iv_hex':iv.hex(),'bytes':len(plain),'plaintext_sha256':hashlib.sha256(plain).hexdigest(),'ciphertext_sha256':hashlib.sha256(ct).hexdigest(),'observed_sha256':hashlib.sha256(obs.encode()).hexdigest(),'complete':r['complete'],'capped_reason':r.get('capped_reason'),'frontier_counts':r['frontier_counts'],'max_frontier':r['max_frontier'],'accepted_states':r['accepted_states'],'block_calls':r['block_calls'],'truth_retained':truth,'solution_count':len(r['solutions']) if r['complete'] else None,'solutions':r['solutions'] if r['complete'] else []}
def controls():
 small=[]
 for n in range(7):
  import itertools
  for tup in itertools.product('aAbB ', repeat=n):
   x=''.join(tup); st='B'
   for b in x.encode(): st=transition(st,b)
   dfa=st is not None; assert dfa==regex_accept(x); small.append({'text':x,'accepted':dfa})
 for x in ('aA','ABc','aBc'):assert not regex_accept(x)
 p99=plant('Quiet Agents map lower words Title Words and ALLCAPS safely ',99)
 p819=plant('Quiet agents map lower words Title Words and ALLCAPS safely through every register while preserving exact case and spaces ',819)
 rows=[run_control('case99|des|nul','des',bytes(8),p99),run_control('case99|aes128|ascii0','aes128',b'0'*16,p99),run_control('case819|des|nul','des',bytes(8),p819),run_control('case819|aes128|ascii0','aes128',b'0'*16,p819)]
 assert all(r['complete'] and r['truth_retained'] for r in rows)
 return {'identity':IDENTITY,'target_evaluated':False,'crypto_evaluated':True,'scope':'Synthetic case-preserving masked-CFB8 frontier only; no Rev7 data.','grammar':{'states':['B','L','U','C'],'all_states_accepting_eof':True,'space_repeats_leading_trailing':True,'styles':'lowercase, Titlecase, ALLCAPS','alphabet':'ASCII letters and SPACE'},'caps':{'max_frontier':100000,'max_accepted':5000000,'capped_classification':'INCOMPLETE; no exclusion claim'},'controls':rows,'regex_controls':{'exhaustive_reduced_alphabet':'aAbB ', 'lengths':'0..6','rejected':['aA','ABc','aBc'],'cases':len(small),'expected_cases':19531,'all_agree':True,'rows':small},'source_hashes':{'lossy2016/core.py':sha(ROOT/'research/char_amsco/astra/lossy2016/core.py')},'assertions':{'all_four_reference_cfb8_match':True,'all_four_truth_paths_retained_or_capped':all(x['truth_retained'] or not x['complete'] for x in rows),'regex_agreement':True,'no_beam_pruning':True}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args(); assert sha(ROOT/'research/char_amsco/astra/lossy2016/core.py')==CORE_SHA; out=controls()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
 else:
  old=json.loads((HERE/'controls.json').read_text()); assert old==out; print(json.dumps({'identity':IDENTITY,'verified':True,'controls':len(out['controls']),'regex_agreement':out['assertions']['regex_agreement']}))
if __name__=='__main__':main()

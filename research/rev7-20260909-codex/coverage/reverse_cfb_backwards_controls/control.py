#!/usr/bin/env python3
"""Synthetic exact backwards reconstruction for reversed CFB8 roles."""
from pathlib import Path
import argparse,hashlib,json,platform
import Crypto
from Crypto.Cipher import AES,DES,Blowfish
HERE=Path(__file__).resolve().parent;LEDGER=HERE/'controls.json';IDENTITY='ASTRA';ALLOWED=bytes((9,10,13,*range(32,127)));MAX_FRONTIER=100_000;MAX_CALLS=1_000_000
SPECS={'des':(DES,b'Zombies\0',8),'blowfish':(Blowfish,b'Zombies',8)}
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def ecb(name):mod,key,_=SPECS[name];return mod.new(key,mod.MODE_ECB)
def library_x(name,p,iv):mod,key,_=SPECS[name];return mod.new(key,mod.MODE_CFB,iv=iv,segment_size=8).decrypt(p)
def library_p(name,x,iv):mod,key,_=SPECS[name];return mod.new(key,mod.MODE_CFB,iv=iv,segment_size=8).encrypt(x)
def manual_x(name,p,iv):
 e=ecb(name);reg=bytearray(iv);out=bytearray()
 for c in p:out.append(c^e.encrypt(bytes(reg))[0]);reg[:]=reg[1:]+bytes((c,))
 return bytes(out)
def forward_suffix(name,x,crib,start):
 e=ecb(name);reg=bytearray(crib);out=bytearray()
 for value in x[start+len(crib):]:
  c=value^e.encrypt(bytes(reg))[0];out.append(c);reg[:]=reg[1:]+bytes((c,))
 return bytes(out)
def search(name,x,crib,start,max_frontier=MAX_FRONTIER,max_calls=MAX_CALLS):
 _,_,bs=SPECS[name];assert len(crib)==bs and start>=0 and start+bs<=len(x);suffix=forward_suffix(name,x,crib,start);suffix_allowed=all(c in ALLOWED for c in suffix);e=ecb(name);front=[(crib,crib)];calls=0;counts=[];steps=[]
 if not suffix_allowed:return {'complete':True,'capped_reason':None,'cipher':name,'block_size':bs,'crib_offset':start,'crib_hex':crib.hex(),'forward_suffix_hex':suffix.hex(),'forward_suffix_allowed':False,'predecessor_steps_completed':0,'frontier_counts':[1],'ecb_calls':0,'max_live_frontier':1,'solution_count':0,'solutions':[]}
 for i in range(start+bs,0,-1):
  nxt=[];domain=ALLOWED if i>bs else bytes(range(256));kind='plaintext' if i>bs else 'iv'
  for reg,left in front:
   rhs=x[i-1]^reg[-1]
   for z in domain:
    if calls>=max_calls:return {'complete':False,'capped_reason':'max_ecb_calls','cipher':name,'block_size':bs,'crib_offset':start,'crib_hex':crib.hex(),'forward_suffix_hex':suffix.hex(),'forward_suffix_allowed':True,'predecessor_steps_completed':len(steps),'partial_step':{'i':i,'kind':kind,'frontier_before':len(front),'next_constructed':len(nxt)},'frontier_counts':[1,*counts],'ecb_calls':calls,'max_live_frontier':max([1,*counts,len(nxt)]),'solution_count':0,'solutions':[]}
    pred=bytes((z,))+reg[:-1];calls+=1
    if e.encrypt(pred)[0]!=rhs:continue
    if len(nxt)>=max_frontier:return {'complete':False,'capped_reason':'max_frontier','cipher':name,'block_size':bs,'crib_offset':start,'crib_hex':crib.hex(),'forward_suffix_hex':suffix.hex(),'forward_suffix_allowed':True,'predecessor_steps_completed':len(steps),'partial_step':{'i':i,'kind':kind,'frontier_before':len(front),'next_constructed':len(nxt)},'frontier_counts':[1,*counts],'ecb_calls':calls,'max_live_frontier':max([1,*counts,len(nxt)]),'solution_count':0,'solutions':[]}
    nxt.append((pred,(bytes((z,))+left) if i>bs else left))
  front=nxt;counts.append(len(front));steps.append({'i':i,'kind':kind,'candidate_domain':len(domain),'frontier_after':len(front)})
  if not front:break
 solutions=[]
 for iv,prefix_crib in front:
  p=prefix_crib+suffix;solutions.append({'iv_hex':iv.hex(),'recovered_plaintext_prefix_hex':prefix_crib[:-bs].hex(),'crib_hex':crib.hex(),'full_p_hex':p.hex(),'full_p_sha256':hb(p),'x_sha256':hb(x)})
 return {'complete':True,'capped_reason':None,'cipher':name,'block_size':bs,'crib_offset':start,'crib_hex':crib.hex(),'forward_suffix_hex':suffix.hex(),'forward_suffix_allowed':True,'predecessor_steps_completed':len(steps),'predecessor_steps':steps,'frontier_counts':[1,*counts],'ecb_calls':calls,'max_live_frontier':max([1,*counts]),'solution_count':len(solutions),'solutions':solutions}
def paragraph(which):
 texts=(b'REVERSE CFB CONTROL ONE USES A HIDDEN IV AND A CRIB WELL INSIDE THIS ASCII PARAGRAPH. EVERY BYTE IS DECLARED TEXT AND THE EXACT BACKWARD SEARCH KEEPS ALL PREDECESSORS.\n',b'SECOND REVERSE CFB EXAMPLE CHECKS BLOWFISH WITH A DIFFERENT IV. THE KNOWN CIPHERTEXT REGISTER SITS AT OFFSET SEVENTEEN AND THE REMAINDER IS REBUILT FORWARD.\r\n')
 p=texts[which];assert len(p)>100 and all(x in ALLOWED for x in p);return p
def validate(name,x,crib,start,row):
 _,_,bs=SPECS[name];assert row['complete'] and row['solution_count']==len(row['solutions']) and row['ecb_calls']<=MAX_CALLS and row['max_live_frontier']<=MAX_FRONTIER
 for sol in row['solutions']:
  iv=bytes.fromhex(sol['iv_hex']);p=bytes.fromhex(sol['full_p_hex']);assert len(iv)==bs and p[start:start+bs]==crib and len(p)==len(x) and all(c in ALLOWED for c in p)
  assert library_x(name,p,iv)==x==manual_x(name,p,iv) and library_p(name,x,iv)==p
  rebuilt=forward_suffix(name,x,crib,start);assert rebuilt==p[start+bs:]
  mod,key,_=SPECS[name];assert mod.new(key,mod.MODE_CFB,iv=crib,segment_size=8).encrypt(x[start+bs:])==rebuilt
  assert hb(p)==sol['full_p_sha256'] and hb(x)==sol['x_sha256']
 return {'every_full_candidate_declared_ascii':True,'every_full_candidate_library_decrypts_to_x':True,'every_full_candidate_manual_decrypts_to_x':True,'every_full_candidate_library_encrypts_x_to_p':True,'every_crib_exact':True,'every_forward_suffix_library_and_manual_exact':True,'every_hash_and_length_exact':True}
def plant(name,index,iv):
 p=paragraph(index);start=17;crib=p[start:start+8];x=library_x(name,p,iv);assert x==manual_x(name,p,iv) and library_p(name,x,iv)==p;row=search(name,x,crib,start);check=validate(name,x,crib,start,row);truth=[s for s in row['solutions'] if bytes.fromhex(s['iv_hex'])==iv and bytes.fromhex(s['full_p_hex'])==p];assert len(truth)==1
 return {'id':name+'|plant','cipher':name,'key_hex':SPECS[name][1].hex(),'hidden_iv_hex':iv.hex(),'p_length':len(p),'p_hex':p.hex(),'p_sha256':hb(p),'x_hex':x.hex(),'x_sha256':hb(x),'crib_offset':start,'crib_hex':crib.hex(),'library_decrypt_p_equals_x':True,'manual_decrypt_p_equals_x':True,'library_encrypt_x_equals_p':True,'truth_retained_exactly_once':True,'search':row,'validation':check}
def forward_controls():
 rows=[]
 for name in SPECS:
  for ivn,iv in enumerate((bytes.fromhex('1023456789ABCDEF'),bytes.fromhex('FEDCBA9876543210'))):
   for start in (0,1,7,8,17,31):
    p=(paragraph(0)+paragraph(1))[:112];x=library_x(name,p,iv);crib=p[start:start+8];rebuilt=forward_suffix(name,x,crib,start);mod,key,_=SPECS[name];lib=mod.new(key,mod.MODE_CFB,iv=crib,segment_size=8).encrypt(x[start+8:]);assert rebuilt==lib==p[start+8:]
    rows.append({'cipher':name,'iv_id':ivn,'offset':start,'suffix_length':len(rebuilt),'suffix_sha256':hb(rebuilt)})
 return rows
def generate():
 plants=[plant('des',0,bytes.fromhex('D31A907B42E56C08')),plant('blowfish',1,bytes.fromhex('6FB204D9813AC75E'))];caps=[]
 for src in plants:
  x=bytes.fromhex(next(s['full_p_hex'] for s in src['search']['solutions'] if s['iv_hex']==src['hidden_iv_hex']));x=library_x(src['cipher'],x,bytes.fromhex(src['hidden_iv_hex']));row=search(src['cipher'],x,bytes.fromhex(src['crib_hex']),src['crib_offset'],max_calls=1);assert not row['complete'] and row['capped_reason']=='max_ecb_calls' and row['solution_count']==0;caps.append({'cipher':src['cipher'],'complete':False,'capped_reason':row['capped_reason'],'ecb_calls':row['ecb_calls'],'partial_step':row['partial_step'],'solutions':[]})
 fw=forward_controls();assert len(fw)==24
 return {'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'crypto_evaluated':True,'model':'Observed X=CFB8_DECRYPT(P, hidden IV), with readable P. A known eight-byte P register at offset 17 permits unique forward reconstruction and exact branching backward reconstruction.','equation':'For i>=1, predecessor R_(i-1)=z||R_i[:-1] must satisfy E(R_(i-1))[0] = X[i-1] XOR R_i[-1]. For i>b z is restricted to declared P bytes; for i<=b all 256 IV-byte values are tested.','limits':{'alphabet':'TAB/LF/CR plus ASCII 32..126','max_live_frontier':MAX_FRONTIER,'max_ecb_calls':MAX_CALLS,'cap_semantics':'INCOMPLETE; no partial branch is reported as a solution','cipher_scope':['DES','standard Blowfish'],'key_scope':['DES Zombies+NUL','Blowfish raw Zombies'],'crib_bytes':8,'crib_offset':17,'no_beam_or_score':True},'plants':plants,'forward_suffix_controls':fw,'tiny_caps':caps,'environment':{'python':platform.python_version(),'pycryptodome':Crypto.__version__},'source_sha256':sha(Path(__file__)),'assertions':{'two_backwards_plants_only':len(plants)==2,'both_truth_p_and_iv_retained_exactly_once':True,'all_surviving_p_iv_pairs_library_and_manual_roundtrip':True,'all_forward_suffixes_library_and_manual_exact':True,'24_small_forward_offset_controls':len(fw)==24,'both_tiny_caps_incomplete_without_solutions':True,'no_target_or_corpus':True}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();out=generate()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)},sort_keys=True))
 else:
  assert json.loads(LEDGER.read_text())==out;print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(LEDGER),'plants':2,'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()

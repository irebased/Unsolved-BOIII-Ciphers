#!/usr/bin/env python3
from pathlib import Path
import argparse,hashlib,json,os,re,sys
from Crypto.Cipher import AES,DES
HERE=Path(__file__).resolve().parent;PKG=HERE.parent;ROOT=HERE.parents[4];sys.path.insert(0,str(PKG));import case_frontier as case
IDENTITY='ASTRA';ORIENTS=('forward','full_hex_reverse','byte_reverse','nibble_swap');CIPHERS=('des','aes128');IVS=('nul','ascii0');NBYTES=819;MAX_FRONTIER=100000;MAX_ACCEPTED=5000000
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json';MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'
GATE=HERE/'target_gate.json';RESULT=HERE/'target_results.json'
REQUIRED=('research/rev7-20260909-codex/homophonic/lossy2016_case_controls/case_frontier.py','research/rev7-20260909-codex/homophonic/lossy2016_case_controls/controls.json','research/rev7-20260909-codex/homophonic/lossy2016_case_controls/README.md','research/char_amsco/astra/lossy2016/core.py','research/char_amsco/astra/lossy2016/controls.py','research/char_amsco/astra/lossy2016/controls.json','research/char_amsco/astra/lossy2016/README.md','research/char_amsco/astra/lossy2016/REPORT.md','research/char_amsco/astra/cryptool_bug/analyze.py','research/char_amsco/astra/cryptool_bug/evidence.json','research/char_amsco/astra/cryptool_bug/source/class.amsco.php.base64','research/char_amsco/astra/cryptool_bug/source/default_tool.php','research/rev7-20260909-codex/homophonic/lossy2016_case_controls/target/driver_controls.py','research/rev7-20260909-codex/homophonic/lossy2016_case_controls/target/controls.json','research/rev7-20260909-codex/homophonic/lossy2016_case_controls/target/README.md','research/rev7-20260909-codex/homophonic/lossy2016_case_controls/target/prepare_gate.py','lavender/src/data/ciphers/revelations.json')
def hb(b):return hashlib.sha256(b).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def orient(s,name):
 assert len(s)%2==0
 if name=='forward':return s
 if name=='full_hex_reverse':return s[::-1]
 ps=[s[i:i+2] for i in range(0,len(s),2)]
 if name=='byte_reverse':return ''.join(reversed(ps))
 if name=='nibble_swap':return ''.join(x[::-1] for x in ps)
 raise ValueError(name)
def scope():return {'identity':IDENTITY,'legacy_key':'2016','source_start':'21','natural_ciphertext_bytes':NBYTES,'observed_hex_chars':1092,'orientations':list(ORIENTS),'ciphers':list(CIPHERS),'ivs':list(IVS),'contexts':16,'allowed_plaintext':'ASCII letters plus SPACE under exact lower/Title/ALLCAPS word DFA','mask_cycle':['ff','0f','f0'],'max_frontier':MAX_FRONTIER,'max_accepted_states':MAX_ACCEPTED,'retention':'every complete solution; capped contexts explicitly incomplete'}
def extract_target():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 t=MDX.read_text();a=t.index('`83 B57B2')+1;b=t.index('`',a);raw=''.join(t[a:b].split()).upper();assert len(raw)==1092 and hb(raw.encode())==TEXT_SHA
 d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper();assert d==raw
 return raw
def load_legacy():return case.load_legacy()
def iv_for(name,cipher):
 _,bs,_=case.core.cipher_spec(cipher);return bytes(bs) if name=='nul' else b'0'*bs
def verify_solution(sol,cipher,iv,observed,legacy):
 pt=bytes.fromhex(sol['plaintext_hex']);ct=bytes.fromhex(sol['ciphertext_hex']);assert len(pt)==len(ct)==NBYTES and set(pt)<=set(case.ALLOWED)
 _,_,key=case.core.cipher_spec(cipher);mod=DES if cipher=='des' else AES
 assert mod.new(key,mod.MODE_CFB,iv=iv,segment_size=8).decrypt(ct)==pt and case.core.encrypt_cfb8(cipher,iv,pt)==ct
 assert legacy.legacy_encode(ct.hex().upper().encode(),'2016')['raw'].decode()==observed==case.core.lossy_emit(ct.hex().upper())
 assert sol.get('plaintext_sha256',hb(pt))==hb(pt) and sol.get('ciphertext_sha256',hb(ct))==hb(ct)
 text=pt.decode('ascii');assert re.fullmatch(r' *(?:(?:[a-z]+|[A-Z][a-z]*|[A-Z]+)(?: +(?:[a-z]+|[A-Z][a-z]*|[A-Z]+))*)? *',text) is not None
 st='B'
 for b in pt:
  if b==32:st='B' if st in ('B','L','U','C') else None
  elif 97<=b<=122:st={'B':'L','U':'L','L':'L'}.get(st)
  elif 65<=b<=90:st={'B':'U','U':'C','C':'C'}.get(st)
  else:st=None
  assert st is not None
 assert st==sol['state'] and case.regex_accept(text)
 sol['plaintext_sha256']=hb(pt);sol['ciphertext_sha256']=hb(ct)
 return {'library_cfb8_plaintext_exact':True,'library_reencrypt_exact':True,'legacy_source_emission_exact':True,'independent_regex_exact':True,'independent_dfa_exact':True}
def run_cell(canonical,o,c,ivname,legacy):
 observed=orient(canonical,o);assert orient(observed,o)==canonical;iv=iv_for(ivname,c);r=case.frontier(c,iv,observed,NBYTES,MAX_FRONTIER,MAX_ACCEPTED)
 for sol in r['solutions']:sol['independent_verification']=verify_solution(sol,c,iv,observed,legacy)
 return {'id':f'{o}|{c}|{ivname}','orientation':o,'cipher':c,'iv':ivname,'iv_hex':iv.hex(),'observed_sha256':hb(observed.encode()),'observed_length':len(observed),'inverse_orientation_exact':True,**r}
def require_gate():
 g=json.loads(GATE.read_text());assert g['identity']==IDENTITY and g['target_evaluated'] is False and g['scope']==scope() and g['driver_sha256']==sha(Path(__file__)) and g['mdx_sha256']==MDX_SHA and g['canonical_text_sha256']==TEXT_SHA and g['dataset_sha256']==DATA_SHA
 assert set(g['artifact_hashes'])==set(REQUIRED) and sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 for rel,want in g['artifact_hashes'].items():assert sha(ROOT/rel)==want
 return g
def run_target():
 tmp=RESULT.with_suffix('.json.tmp')
 if RESULT.exists() or tmp.exists():raise SystemExit('refusing existing result or temporary file')
 g=require_gate();canonical=extract_target();legacy=load_legacy();cells=[run_cell(canonical,o,c,iv,legacy) for o in ORIENTS for c in CIPHERS for iv in IVS];assert len(cells)==16
 out={'identity':IDENTITY,'target_evaluated':True,'scope':scope(),'configuration':{'gate_sha256':sha(GATE),'driver_sha256':sha(Path(__file__)),'artifact_hashes':g['artifact_hashes'],'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA},'cells':cells,'summary':{'complete_contexts':sum(x['complete'] for x in cells),'incomplete_contexts':sum(not x['complete'] for x in cells),'solutions':sum(len(x['solutions']) for x in cells)}}
 tmp.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');os.replace(tmp,RESULT);print(json.dumps({'identity':IDENTITY,'result_sha256':sha(RESULT),**out['summary']},sort_keys=True))
def main():
 a=argparse.ArgumentParser();a.add_argument('--run-target',action='store_true');x=a.parse_args()
 if x.run_target:run_target()
 else:
  if GATE.exists():require_gate()
  assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
  print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'handling':'MDX and dataset bytes hashed only; no ciphertext extraction or evaluation','scope':scope(),'driver_sha256':sha(Path(__file__)),'gate_present':GATE.exists()},indent=2,sort_keys=True))
if __name__=='__main__':main()

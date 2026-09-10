#!/usr/bin/env python3
"""Read-only structural and independent zero-prefix verifier for the all-IV DES result."""
from pathlib import Path
from collections import Counter
import argparse,hashlib,itertools,json
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
RESULT=HERE/'target_results.json';GATE=HERE/'target_gate.json';LEDGER=HERE/'independent_prefix_certificates.json'
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
RESULT_SHA='bbebe2a33edcdd11f335f2f8f6abc3377f4203e825702613d827128abf63862c'
GATE_SHA='dbea147677ad626163cc44a6e49445db65c0ae82cbcd38bd542080c435a988ea'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
ORIENTS=('forward','full_hex_reverse','byte_reverse','nibble_swap');KEY=b'Zombies\0';N=655

def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def orient(s,name):
 if name=='forward':return s
 if name=='full_hex_reverse':return s[::-1]
 pairs=[s[i:i+2] for i in range(0,len(s),2)]
 if name=='byte_reverse':return ''.join(reversed(pairs))
 if name=='nibble_swap':return ''.join(x[::-1] for x in pairs)
 raise ValueError(name)

def canonical():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 t=MDX.read_text();a=t.index('`83 B57B2')+1;b=t.index('`',a);s=''.join(t[a:b].split()).upper()
 d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper()
 assert s==d and len(s)==1092 and hb(s.encode())==TEXT_SHA
 return s

def independent_emission_indices(length=1310,key='2013'):
 # Faithful local port of the cited PHP row assignment/read loops: 2,1 cells and numeric labels.
 rows={};pos=0;cell=0;size=2;width=len(key)
 while pos<length:
  take=min(size,length-pos);row=cell//width;col=cell%width
  rows.setdefault(row,{})[int(key[col])]=tuple(range(pos,pos+take))
  pos+=take;cell+=1;size=3-size
 out=[]
 for label in range(1,width+1):
  for row in range(max(rows)+1):out.extend(rows.get(row,{}).get(label,()))
 return tuple(out)

def reconstruct(observed):
 idx=independent_emission_indices();assert len(idx)==len(observed)==1092
 vals=bytearray(N);masks=bytearray(N)
 for ch,natural in zip(observed,idx):
  nib=int(ch,16);byte=natural//2
  if natural%2:vals[byte]|=nib;masks[byte]|=15
  else:vals[byte]|=nib<<4;masks[byte]|=240
 return bytes(vals),bytes(masks)

def replay_zero(observed):
 vals,masks=reconstruct(observed)
 domains=[tuple(c for c in range(256) if (c&m)==(v&m)) for v,m in zip(vals[:8],masks[:8])]
 roots=[bytes(x) for x in itertools.product(*domains)]
 assert [len(x) for x in domains]==[1,16,1,1,16,1,1,16] and len(roots)==len(set(roots))==4096
 e=DES.new(KEY,DES.MODE_ECB);accepted_by=[0]*(N-8);calls=0;maxlive=0;empty=Counter();outcome=hashlib.sha256();latest=[]
 for seed in roots:
  front=[seed];empty_after=None
  for pos in range(8,N):
   nxt=[];v=vals[pos];m=masks[pos]
   for reg in front:
    k=e.encrypt(reg)[0];calls+=1
    # Independent branch oracle enumerates compatible ciphertext bytes, then tests plaintext.
    for c in range(256):
     if (c&m)!=(v&m):continue
     plain=c^k
     if 32<=plain<=126:nxt.append(reg[1:]+bytes((c,)))
   accepted_by[pos-8]+=len(nxt);maxlive=max(maxlive,len(nxt));front=nxt
   if not front:empty_after=pos+1;break
  assert empty_after is not None
  empty[empty_after]+=1;outcome.update(seed);outcome.update(empty_after.to_bytes(2,'big'))
  latest.append((empty_after,seed.hex()))
 assert sum(empty.values())==4096
 latest=sorted(latest,reverse=True)[:8]
 return {'compatible_register_counts_per_byte':[len(x) for x in domains],'compatible_registers':len(roots),'compatible_registers_unique':len(set(roots)),'compatible_registers_sha256':hb(b''.join(roots)),'all_roots_empty_before_terminal':True,'root_empty_after_natural_byte_histogram':{str(k):empty[k] for k in sorted(empty)},'root_outcome_digest_sha256':outcome.hexdigest(),'latest_empty_roots':[{'empty_after_natural_bytes':n,'initial_register_hex':s} for n,s in latest],'maximum_reached_natural_bytes':max(empty)-1,'accepted_states_by_suffix_byte':accepted_by,'accepted_states':sum(accepted_by),'block_calls':calls,'max_live_frontier_per_root':maxlive}

def build():
 assert sha(RESULT)==RESULT_SHA and sha(GATE)==GATE_SHA
 result=json.loads(RESULT.read_text());gate=json.loads(GATE.read_text())
 assert result['identity']=='ASTRA' and result['target_evaluated'] is True and gate['identity']=='ASTRA' and gate['target_evaluated'] is False
 assert result['configuration']['gate_sha256']==GATE_SHA and result['configuration']['artifact_hashes']==gate['artifact_hashes']
 assert set(gate['artifact_hashes'])==set(result['configuration']['artifact_hashes'])
 for rel,want in gate['artifact_hashes'].items():assert sha(ROOT/rel)==want,(rel,sha(ROOT/rel),want)
 assert [x['id'] for x in result['cells']]==list(ORIENTS)
 can=canonical();rows=[]
 for stored in result['cells']:
  obs=orient(can,stored['orientation']);proof=replay_zero(obs)
  assert stored['complete'] and stored['capped_reason'] is None and stored['solution_count']==0 and stored['solutions']==[]
  assert stored['roots_started']==stored['roots_completed']==4096 and stored['roots_unexamined']==0 and stored['partial_root'] is None
  for field in ('accepted_states_by_suffix_byte','accepted_states','block_calls','max_live_frontier_per_root'):
   assert stored[field]==proof[field],(stored['id'],field)
  assert stored['initial_register_proof']['generated_count']==stored['initial_register_proof']['unique_count']==4096
  assert stored['initial_register_proof']['registers_digest_sha256']==proof['compatible_registers_sha256']
  assert stored['accepted_states']==sum(stored['accepted_states_by_suffix_byte'])
  rows.append({'id':stored['id'],'observed_sha256':stored['observed_sha256'],**proof})
 assert result['summary']=={'accepted_states':sum(x['accepted_states'] for x in result['cells']),'block_calls':sum(x['block_calls'] for x in result['cells']),'complete_contexts':4,'incomplete_contexts':0,'terminal_solutions':0}
 return {'identity':'ASTRA','target_evaluated':True,'verification_kind':'structural pin/accounting verification plus an independent complete enumeration of every necessary printable-prefix branch until each of 4096 roots empties; this is a second negative prefix computation, not a target rerun that searches beyond empty frontiers','result_sha256':RESULT_SHA,'gate_sha256':GATE_SHA,'canonical_text_sha256':TEXT_SHA,'cells_verified':4,'all_zero_certificates_valid':True,'rows':rows}

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--write-ledger',type=Path);a=ap.parse_args();fresh=build()
 if a.write_ledger:
  if a.write_ledger.exists():raise SystemExit('refusing existing ledger')
  a.write_ledger.write_text(json.dumps(fresh,indent=2,sort_keys=True)+'\n')
 else:assert json.loads(LEDGER.read_text())==fresh
 print(json.dumps({'identity':'ASTRA','verified':True,'cells':4,'result_sha256':RESULT_SHA,'ledger_sha256':sha(a.write_ledger or LEDGER)},sort_keys=True))
if __name__=='__main__':main()

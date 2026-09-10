#!/usr/bin/env python3
"""Read-only 44-new-cell negative-prefix verifier plus exact prior-cell reuse check."""
from pathlib import Path
from collections import Counter
import argparse,hashlib,itertools,json
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
RESULT=HERE/'target_results.json';GATE=HERE/'target_gate.json';LEDGER=HERE/'independent_prefix_certificates.json';INVENTORY=ROOT/'research/char_amsco/astra/lossy4_onechar_inventory/inventory.json';MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json';PRIOR=ROOT/'research/rev7-20260909-codex/lossy2013_alliv_controls/target/target_results.json';PRIOR_CERT=ROOT/'research/rev7-20260909-codex/lossy2013_alliv_controls/target/independent_prefix_certificates.json'
RESULT_SHA='25286408d594956aab904e3e4111866160c300b85a8eb73c61791285733dd507';GATE_SHA='816ea9f8dc83414147e01e6a11983769e48ede21649e21262f07defa8f7ab55c';PRIOR_SHA='bbebe2a33edcdd11f335f2f8f6abc3377f4203e825702613d827128abf63862c';PRIOR_CERT_SHA='e194a07fecd25374d5809bd50435659ded7f54f5a16b13fcc3cb986ee0234abd';MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c';INVENTORY_SHA='fa9d7463848918d2eaddfe6afdf013f2d5b6b1d1c2011aa5d0aa5a197eec4fe2';ORIENTS=('forward','full_hex_reverse','byte_reverse','nibble_swap');KEY=b'Zombies\0';N=655
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def orient(s,name):
 if name=='forward':return s
 if name=='full_hex_reverse':return s[::-1]
 pairs=[s[i:i+2] for i in range(0,len(s),2)]
 if name=='byte_reverse':return ''.join(reversed(pairs))
 if name=='nibble_swap':return ''.join(x[::-1] for x in pairs)
 raise ValueError(name)
def source_indices(length,key):
 rows={};pos=cell=0;size=2
 while pos<length:
  take=min(size,length-pos);row=cell//4;col=cell%4;rows.setdefault(row,{})[int(key[col])]=tuple(range(pos,pos+take));pos+=take;cell+=1;size=3-size
 out=[]
 for label in range(1,5):
  for row in range(max(rows)+1):out.extend(rows.get(row,{}).get(label,()))
 return tuple(out)
def reconstruct(observed,indices):
 vals=bytearray(N);masks=bytearray(N);assert len(observed)==len(indices)==1092
 for ch,index in zip(observed,indices):
  nib=int(ch,16);byte=index//2
  if index&1:vals[byte]|=nib;masks[byte]|=15
  else:vals[byte]|=nib<<4;masks[byte]|=240
 return bytes(vals),bytes(masks)
def canonical():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 t=MDX.read_text();a=t.index('`83 B57B2')+1;b=t.index('`',a);s=''.join(t[a:b].split()).upper();d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper();assert s==d and hb(s.encode())==TEXT_SHA;return s
def replay(observed,key):
 indices=source_indices(1310,key);vals,masks=reconstruct(observed,indices);domains=[tuple(c for c in range(256) if (c&m)==(v&m)) for v,m in zip(vals[:8],masks[:8])];roots=[bytes(x) for x in itertools.product(*domains)];assert len(roots)==len(set(roots)) in (256,4096)
 e=DES.new(KEY,DES.MODE_ECB);accepted=[0]*(N-8);calls=maxlive=0;hist=Counter();digest=hashlib.sha256();latest=[]
 for seed in roots:
  front=[seed];empty=None
  for pos in range(8,N):
   nxt=[];v=vals[pos];m=masks[pos]
   for reg in front:
    k=e.encrypt(reg)[0];calls+=1
    # Independent ciphertext-first oracle, unlike the target's plaintext-first branches.
    for c in range(256):
     if (c&m)==(v&m) and 32<=c^k<=126:nxt.append(reg[1:]+bytes((c,)))
   accepted[pos-8]+=len(nxt);maxlive=max(maxlive,len(nxt));front=nxt
   if not front:empty=pos+1;break
  assert empty is not None;hist[empty]+=1;digest.update(seed);digest.update(empty.to_bytes(2,'big'));latest.append((empty,seed.hex()))
 assert sum(hist.values())==len(roots)
 return {'representative_key':key,'map_sha256':hb(json.dumps(list(indices),separators=(',',':')).encode()),'compatible_counts_per_byte':[len(x) for x in domains],'compatible_registers':len(roots),'compatible_registers_unique':len(set(roots)),'compatible_registers_sha256':hb(b''.join(roots)),'all_roots_empty_before_terminal':True,'root_empty_after_natural_byte_histogram':{str(k):hist[k] for k in sorted(hist)},'root_outcome_digest_sha256':digest.hexdigest(),'latest_empty_roots':[{'empty_after_natural_bytes':n,'initial_register_hex':s} for n,s in sorted(latest,reverse=True)[:8]],'maximum_reached_natural_bytes':max(hist)-1,'accepted_states_by_suffix_byte':accepted,'accepted_states':sum(accepted),'block_calls':calls,'max_live_frontier_per_root':maxlive}
def build():
 assert sha(RESULT)==RESULT_SHA and sha(GATE)==GATE_SHA and sha(PRIOR)==PRIOR_SHA and sha(PRIOR_CERT)==PRIOR_CERT_SHA and sha(INVENTORY)==INVENTORY_SHA
 result=json.loads(RESULT.read_text());gate=json.loads(GATE.read_text());prior=json.loads(PRIOR.read_text());pcert=json.loads(PRIOR_CERT.read_text());assert result['identity']=='ASTRA' and result['target_evaluated'] is True and gate['identity']=='ASTRA' and gate['target_evaluated'] is False and result['configuration']['gate_sha256']==GATE_SHA and result['configuration']['artifact_hashes']==gate['artifact_hashes']
 for rel,want in gate['artifact_hashes'].items():assert sha(ROOT/rel)==want,(rel,sha(ROOT/rel),want)
 inv=json.loads(INVENTORY.read_text());maps=[x for x in inv['map_classes'] if x['input_chars']==1310];ids=[f"{x['class_id']}|{o}" for x in maps for o in ORIENTS];assert [x['id'] for x in result['cells']]==ids
 can=canonical();new=[];reused=[]
 for meta in maps:
  assert tuple(meta['emission_indices'])==source_indices(1310,meta['representative_key'])
  for orientation in ORIENTS:
   cell=next(x for x in result['cells'] if x['id']==f"{meta['class_id']}|{orientation}");obs=orient(can,orientation);assert cell['observed_sha256']==hb(obs.encode()) and cell['solutions']==[] and cell['solution_count']==0 and cell['complete'] and cell['accepted_states']==sum(cell['accepted_states_by_suffix_byte']) and cell['roots_started']==cell['roots_completed']==cell['initial_registers_total'] and cell['roots_unexamined']==0 and cell['partial_root'] is None
   if meta['class_id']=='N1310-C01':
    old=next(x for x in prior['cells'] if x['id']==orientation);assert cell['evidence_kind']=='reused_prior_complete_search' and cell['prior_result_sha256']==PRIOR_SHA and cell['prior_gate_sha256']==pcert['gate_sha256'] and pcert['all_zero_certificates_valid']
    for k,v in old.items():
     if k not in ('id','orientation','observed_sha256','observed_length','inverse_orientation_exact','validation'):assert cell[k]==v,(cell['id'],k)
    reused.append({'id':cell['id'],'prior_cell_id':orientation,'prior_result_sha256':PRIOR_SHA,'prior_certificate_result_sha256':pcert['result_sha256'],'exact_prior_search_fields_copied':True})
   else:
    assert cell['evidence_kind']=='new_search';proof=replay(obs,meta['representative_key'])
    for field in ('accepted_states_by_suffix_byte','accepted_states','block_calls','max_live_frontier_per_root'):assert cell[field]==proof[field],(cell['id'],field)
    assert cell['initial_register_proof']['registers_digest_sha256']==proof['compatible_registers_sha256'] and cell['initial_registers_total']==proof['compatible_registers']
    new.append({'id':cell['id'],'observed_sha256':cell['observed_sha256'],**proof})
 assert len(new)==44 and len(reused)==4
 expected={'logical_contexts':48,'newly_evaluated_contexts':44,'reused_contexts':4,'complete_contexts':48,'incomplete_contexts':0,'terminal_solutions':0,'accepted_states':sum(x['accepted_states'] for x in result['cells']),'block_calls':sum(x['block_calls'] for x in result['cells'])};assert result['summary']==expected
 newcells=[x for x in result['cells'] if x['evidence_kind']=='new_search'];reusecells=[x for x in result['cells'] if x['evidence_kind']=='reused_prior_complete_search']
 return {'identity':'ASTRA','target_evaluated':True,'verification_kind':'structural pin/accounting and exact prior-copy checks, plus independent ciphertext-first negative-prefix enumeration for only the 44 new cells; reused cells are not recomputed or counted as new','result_sha256':RESULT_SHA,'gate_sha256':GATE_SHA,'canonical_text_sha256':TEXT_SHA,'counts':{'logical_cells':48,'new_cells_independently_replayed':44,'reused_cells_exactly_checked':4,'new_accepted_states':sum(x['accepted_states'] for x in newcells),'new_block_calls':sum(x['block_calls'] for x in newcells),'reused_accepted_states':sum(x['accepted_states'] for x in reusecells),'reused_block_calls':sum(x['block_calls'] for x in reusecells)},'all_new_zero_certificates_valid':True,'all_reused_prior_copies_valid':True,'new_rows':new,'reused_rows':reused}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--write-ledger',type=Path);a=ap.parse_args();fresh=build()
 if a.write_ledger:
  if a.write_ledger.exists():raise SystemExit('refusing existing ledger')
  a.write_ledger.write_text(json.dumps(fresh,indent=2,sort_keys=True)+'\n')
 else:assert json.loads(LEDGER.read_text())==fresh
 print(json.dumps({'identity':'ASTRA','verified':True,'new_cells':44,'reused_cells':4,'result_sha256':RESULT_SHA,'ledger_sha256':sha(a.write_ledger or LEDGER)},sort_keys=True))
if __name__=='__main__':main()

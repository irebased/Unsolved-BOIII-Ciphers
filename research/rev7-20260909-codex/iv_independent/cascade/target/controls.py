#!/usr/bin/env python3
"""Synthetic-only controls for the cascade target traversal and evidence recording."""
from __future__ import annotations
import argparse,hashlib,json,platform,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;CASCADE=HERE.parent;RUNTIME=CASCADE/'runtime'
sys.path.insert(0,str(HERE));sys.path.insert(0,str(RUNTIME))
import run_target as driver
import runtime
IDENTITY='ASTRA';LEDGER=HERE/'controls.json'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def strict_plain(n=160):
 phrase='ASCII – — ‘ ’ … CONTROL. '.encode('utf-8');tail=b'END.\n';room=n-len(tail);return phrase*(room//len(phrase))+b'A'*(room%len(phrase))+tail
def encrypt_chain(plain,names,between,objects,ivs):
 value=plain
 for i in range(len(names)-1,-1,-1):
  value=driver.reference_cfb(names[i],objects[names[i]],value,ivs[i],False)
  if i>0:value=driver.transform(value,between[i-1])
 return value
def independent_endpoint(data,left,right,total):
 """Separate necessary-byte/FSA oracle used only by synthetic controls."""
 if not data:return ('inconclusive_empty',None)
 if any(v not in {9,10,13,*range(32,127),0xe2,0x80,0x93,0x94,0x98,0x99,0xa6} for v in data):return ('rejected_a105',False)
 states={0} if left==0 else {0,1,2}
 for v in data:
  next_states=set()
  for state in states:
   if state==0 and (v in (9,10,13) or 32<=v<=126):next_states.add(0)
   elif state==0 and v==0xe2:next_states.add(1)
   elif state==1 and v==0x80:next_states.add(2)
   elif state==2 and v in (0x93,0x94,0x98,0x99,0xa6):next_states.add(0)
  states=next_states
  if not states:return ('rejected_fsa_transition',False)
 if right==total and 0 not in states:return ('rejected_fsa_terminal',False)
 return ('retained',True)
def plant(names,between,objects,label):
 plain=strict_plain();layers=[objects[x] for x in names];ivs=driver.suite_ivs(layers,7);outer=encrypt_chain(plain,names,between,objects,ivs);rows=[]
 # One-choice-per-depth uses the exact target traversal and cannot prune rejected ancestors.
 def collect(o,outer2,n,t,l,r,d,objs):
  row=driver.record_case(o,outer2,n,t,l,r,d,objs);independent=independent_endpoint(d,l,r,len(outer2));assert (row['endpoint']['classification'],row['endpoint']['accepted'])==independent;row['independent_endpoint_oracle_match']=True;rows.append(row)
 count=driver.traverse_grid(outer,'forward',objects,tuple((x,) for x in names),tuple((x,) for x in between),collect)
 assert count==len(names) and [x['depth'] for x in rows]==list(range(1,len(names)+1));leaf=rows[-1]
 assert leaf['backends']==list(names) and leaf['interlayer_transforms']==list(between) and leaf['endpoint']['classification']=='retained'
 left,right=leaf['known_interval'];assert bytes.fromhex(leaf['candidate_hex'])==plain[left:right]
 assert len(leaf['two_iv_full_chain_replays'])==2 and all(x['known_interval_matches'] and x['full_reencryption_exact'] for x in leaf['two_iv_full_chain_replays'])
 return {'label':label,'plant_ivs_hex':[x.hex() for x in ivs],'plaintext_sha256':hashlib.sha256(plain).hexdigest(),'outer_sha256':hashlib.sha256(outer).hexdigest(),'traversal_count':count,'cases':rows,'leaf_retained_exact':True}
def verify(path=LEDGER):
 d=json.loads(path.read_text());assert d['identity']==IDENTITY and d['target_evaluated'] is False and d['rev7_read'] is False
 assert d['artifact_hashes']['run_target.py']==sha(HERE/'run_target.py') and d['artifact_hashes']['controls.py']==sha(Path(__file__)) and d['artifact_hashes']['runtime.py']==sha(RUNTIME/'runtime.py') and d['artifact_hashes']['runtime_controls.json']==sha(RUNTIME/'controls.json')
 assert d['scope']['backend_ids']==list(driver.BACKENDS) and d['scope']['target_total_path_endpoints']==22764
 assert len(d['direct_backend_plants'])==7 and [x['cases'][-1]['backends'][-1] for x in d['direct_backend_plants']]==list(driver.BACKENDS)
 assert d['mixed_depth2']['cases'][0]['endpoint']['accepted'] is False and d['mixed_depth2']['cases'][1]['endpoint']['classification']=='retained'
 assert d['mixed_depth2']['rejected_intermediate_still_expanded_to_retained_child']
 assert all(c['independent_endpoint_oracle_match'] for x in d['direct_backend_plants']+[d['mixed_depth2'],d['mixed_depth3']] for c in x['cases'])
 assert d['mixed_depth3']['cases'][-1]['endpoint']['classification']=='retained'
 branch=d['multi_branch_grid'];assert branch['endpoint_count']==branch['unique_case_ids']==584 and branch['expected_case_ids_equal'] and branch['every_interval_matches_full_reference'] and branch['every_endpoint_matches_independent_oracle'] and branch['planted_leaf_retained']
 blocks={'aes128':16,'des':8,'blowfish':8,'bfcompat':8,'rc2':8,'twofish':16,'loki97':16}
 for plant in d['direct_backend_plants']+[d['mixed_depth2'],d['mixed_depth3']]:
  names=tuple(plant['cases'][-1]['backends']);between=tuple(plant['cases'][-1]['interlayer_transforms']);left=0;right=160
  for i,case in enumerate(plant['cases']):
   left=min(left+blocks[names[i]],right);assert case['case_id']==driver.path_id('forward',names[:i+1],between[:i]) and case['known_interval']==[left,right] and case['known_bytes']==right-left
   if case['candidate_hex'] is not None:assert hashlib.sha256(bytes.fromhex(case['candidate_hex'])).hexdigest()==case['known_sha256']
   if i<len(between):left,right,_=driver.transform_interval(left,right,b'X'*(right-left),160,between[i])
 assert all(d['assertions'].values())
 print(json.dumps({'identity':IDENTITY,'verified':True,'verification_scope':'stdlib source/ledger structural integrity; no cryptographic replay','ledger_sha256':sha(path),'target_evaluated':False},sort_keys=True))
def independent_expected_ids(orientations,backend_choices,transform_choices):
 out=[]
 for orient in orientations:
  for a in backend_choices[0]:
   out.append(driver.path_id(orient,(a,),()))
   for t0 in transform_choices[0]:
    for b in backend_choices[1]:
     out.append(driver.path_id(orient,(a,b),(t0,)))
     for t1 in transform_choices[1]:
      for c in backend_choices[2]:out.append(driver.path_id(orient,(a,b,c),(t0,t1)))
 return out
def full_reference_decrypt(outer,names,between,objects):
 layers=[objects[x] for x in names];ivs=driver.suite_ivs(layers,11);value=outer
 for i,name in enumerate(names):
  value=driver.reference_cfb(name,objects[name],value,ivs[i],True)
  if i<len(between):value=driver.transform(value,between[i])
 return value
def regenerate(outdir):
 if outdir.exists():raise SystemExit('refusing existing regeneration directory: '+str(outdir))
 outdir.mkdir(parents=True)
 with tempfile.TemporaryDirectory(prefix='astra-cascade-driver-controls-') as td:
  builds=runtime.build_source_libraries(Path(td));objects=runtime.registry(builds)
  direct=[plant((name,),(),objects,'direct_'+name) for name in driver.BACKENDS]
  # The intermediate bytes are an inner ciphertext transformed before the outer layer: normally nontext, while the final plant is strict text.
  depth2=plant(('aes128','des'),('nibble_swap',),objects,'depth2_rejected_parent_retained_child')
  assert depth2['cases'][0]['endpoint']['accepted'] is False and depth2['cases'][1]['endpoint']['classification']=='retained'
  depth2['rejected_intermediate_still_expanded_to_retained_child']=True
  depth3=plant(('bfcompat','twofish','rc2'),('byte_reverse','full_hex_reverse'),objects,'depth3_two_distinct_interlayer_transforms')
  # A real branching grid: 4 orientations * (2 + 2*4*2 + 2*4*2*4*2) = 584 endpoints.
  choices=(('bfcompat','aes128'),('twofish','des'),('rc2','loki97'));tchoices=(driver.TRANSFORMS,driver.TRANSFORMS);plain=strict_plain();plant_names=('bfcompat','twofish','rc2');plant_between=('byte_reverse','full_hex_reverse');plant_layers=[objects[x] for x in plant_names];plant_ivs=driver.suite_ivs(plant_layers,7);base_outer=encrypt_chain(plain,plant_names,plant_between,objects,plant_ivs)
  expected_ids=independent_expected_ids(driver.ORIENTATIONS,choices,tchoices);seen=[];digest_rows=[];class_counts={};planted=False
  for orient in driver.ORIENTATIONS:
   outer=driver.transform(base_outer,orient)
   def branch_collect(o,outer2,n,t,l,r,d,objs):
    nonlocal planted
    cid=driver.path_id(o,n,t);full=full_reference_decrypt(outer2,n,t,objs);assert full[l:r]==d
    independent=independent_endpoint(d,l,r,len(outer2));production=driver.endpoint(d,l,r,len(outer2));assert (production['classification'],production['accepted'])==independent
    seen.append(cid);class_counts[independent[0]]=class_counts.get(independent[0],0)+1;digest_rows.append([cid,l,r,hashlib.sha256(d).hexdigest(),independent[0],independent[1],hashlib.sha256(full).hexdigest()])
    if o=='forward' and n==plant_names and t==plant_between:
     assert independent==('retained',True) and d==plain[l:r];planted=True
   count=driver.traverse_grid(outer,orient,objects,choices,tchoices,branch_collect);assert count==146
  assert len(seen)==len(set(seen))==len(expected_ids)==584 and set(seen)==set(expected_ids) and planted
  branch={'backend_choices_by_depth':[list(x) for x in choices],'transform_choices_by_boundary':[list(x) for x in tchoices],'orientations':list(driver.ORIENTATIONS),'endpoint_count':len(seen),'unique_case_ids':len(set(seen)),'expected_case_ids_equal':True,'canonical_rows_sha256':hashlib.sha256(json.dumps(digest_rows,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'classification_counts':class_counts,'every_interval_matches_full_reference':True,'every_endpoint_matches_independent_oracle':True,'full_reference_iv_suite':11,'planted_path':driver.path_id('forward',plant_names,plant_between),'planted_leaf_retained':planted,'stored_rows':'aggregate digest and counts only; deterministic row serialization is [id,L,R,known_sha256,class,accepted,full_plaintext_sha256] in traversal order'}
  edges={
   'ordinary_full':driver.endpoint(b'ASCII END.\n',0,11,11),
   'left_dependent':driver.endpoint(bytes.fromhex('80a6')+b'A',5,8,20),
   'left_same_bytes_at_stream_start':driver.endpoint(bytes.fromhex('80a6')+b'A',0,3,3),
   'right_partial_internal':driver.endpoint(b'A'+bytes.fromhex('e280'),4,7,20),
   'right_same_bytes_at_stream_end':driver.endpoint(b'A'+bytes.fromhex('e280'),0,3,3),
   'empty':driver.endpoint(b'',8,8,20)}
  assert edges['ordinary_full']['accepted'] and edges['left_dependent']['accepted'] and not edges['left_same_bytes_at_stream_start']['accepted']
  assert edges['right_partial_internal']['accepted'] and not edges['right_same_bytes_at_stream_end']['accepted'] and edges['empty']['accepted'] is None
  result={'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'scope':{'backend_ids':list(driver.BACKENDS),'direct_plants':7,'mixed_depths':[2,3],'transforms_exercised':['nibble_swap','byte_reverse','full_hex_reverse'],'target_total_path_endpoints':22764,'control_traversal':'one registered backend choice per depth; exact production traverse_grid and record_case'},'direct_backend_plants':direct,'mixed_depth2':depth2,'mixed_depth3':depth3,'multi_branch_grid':branch,'boundary_endpoint_controls':edges,'source_build':{'compiler':builds['compiler'],'temporary_only':True,'source_binary_hashes':{x:builds[x]['sha256'] for x in ('bfcompat','twofish','loki97')}},'artifact_hashes':{'run_target.py':sha(HERE/'run_target.py'),'controls.py':sha(Path(__file__)),'runtime.py':sha(RUNTIME/'runtime.py'),'runtime_controls.json':sha(RUNTIME/'controls.json')},'runtime':{'python':platform.python_version()},'assertions':{'all_passed':True,'all_seven_backends':len(direct)==7,'every_direct_leaf_retained':all(x['leaf_retained_exact'] for x in direct),'mixed_depth2_retained':depth2['leaf_retained_exact'],'mixed_depth3_retained':depth3['leaf_retained_exact'],'rejected_intermediate_did_not_prune':depth2['rejected_intermediate_still_expanded_to_retained_child'],'two_iv_replay_and_reencryption':all(all(len(c['two_iv_full_chain_replays'])==2 for c in x['cases'] if c['endpoint']['classification'] in ('retained','inconclusive_empty')) for x in direct+[depth2,depth3]),'exact_case_ids_intervals_and_classifications':True,'independent_endpoint_oracle_every_traversed_case':all(c['independent_endpoint_oracle_match'] for x in direct+[depth2,depth3] for c in x['cases']),'multi_branch_584_exact_ids_intervals_oracle':branch['endpoint_count']==584 and branch['expected_case_ids_equal'] and branch['every_interval_matches_full_reference'] and branch['every_endpoint_matches_independent_oracle'] and branch['planted_leaf_retained'],'boundary_dependent_states':True,'no_target_read_or_evaluation':True}}
  out=outdir/'controls.json';out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(out),'sha256':sha(out),'depth2_classes':[x['endpoint']['classification'] for x in depth2['cases']],'depth3_classes':[x['endpoint']['classification'] for x in depth3['cases']]},indent=2))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate-dir',type=Path);ap.add_argument('--ledger',type=Path,default=LEDGER);a=ap.parse_args()
 if a.regenerate_dir:regenerate(a.regenerate_dir)
 else:verify(a.ledger)
if __name__=='__main__':main()

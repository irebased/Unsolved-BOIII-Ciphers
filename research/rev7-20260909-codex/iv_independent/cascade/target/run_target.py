#!/usr/bin/env python3
"""Draft gated driver for all-IV direct-binary CFB8 cascades. No target runs are authorized by this draft."""
from __future__ import annotations
import argparse,hashlib,itertools,json,os,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;CASCADE=HERE.parent;RUNTIME=CASCADE/'runtime';ROOT=HERE.parents[4]
sys.path.insert(0,str(RUNTIME))
import runtime
IDENTITY='ASTRA';GATE=HERE/'target_gate.json';MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
BACKENDS=('aes128','des','blowfish','bfcompat','rc2','twofish','loki97')
TRANSFORMS=('forward','full_hex_reverse','byte_reverse','nibble_swap');ORIENTATIONS=TRANSFORMS
THIRDS={0x93,0x94,0x98,0x99,0xa6};RELAXED={9,10,13,*range(32,127),0xe2,0x80,*THIRDS}
REQUIRED_ARTIFACTS=(
 'research/rev7-20260909-codex/iv_independent/cascade/proof.py',
 'research/rev7-20260909-codex/iv_independent/cascade/controls.json',
 'research/rev7-20260909-codex/iv_independent/cascade/interval_extension.py',
 'research/rev7-20260909-codex/iv_independent/cascade/interval_extension.json',
 'research/rev7-20260909-codex/iv_independent/cascade/runtime/runtime.py',
 'research/rev7-20260909-codex/iv_independent/cascade/runtime/controls.py',
 'research/rev7-20260909-codex/iv_independent/cascade/runtime/controls.json',
 'research/rev7-20260909-codex/iv_independent/cascade/runtime/README.md',
 'research/rev7-20260909-codex/iv_independent/cascade/runtime/source/PROVENANCE.md',
 'research/rev7-20260909-codex/sources/rev9_source/controls.json',
 'research/rev7-20260909-codex/hex_cfb/native_siblings/controls.json',
 'research/rev7-20260909-codex/iv_independent/cascade/target/README.md',
 'research/rev7-20260909-codex/iv_independent/cascade/target/prepare_gate.py',
 'research/rev7-20260909-codex/iv_independent/cascade/target/controls.py',
 'research/rev7-20260909-codex/iv_independent/cascade/target/controls.json',
 *tuple('research/rev7-20260909-codex/iv_independent/cascade/runtime/source/'+rel for rel in runtime.SOURCE_HASHES),
)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def swap(v):return ((v&15)<<4)|(v>>4)
def transform(data,name):
 if name=='forward':return data
 if name=='byte_reverse':return data[::-1]
 if name=='nibble_swap':return bytes(swap(x) for x in data)
 if name=='full_hex_reverse':return bytes(swap(x) for x in reversed(data))
 raise ValueError(name)
def transform_interval(left,right,data,total,name):
 if name in ('forward','nibble_swap'):return left,right,transform(data,name)
 return total-right,total-left,transform(data,name)
def path_id(orientation,layers,transforms):return orientation+'|d'+str(len(layers))+'|'+','.join(layers)+'|'+(','.join(transforms) if transforms else '-')
def expected_ids():
 out=[]
 for orient in ORIENTATIONS:
  for depth in (1,2,3):
   for layers in itertools.product(BACKENDS,repeat=depth):
    for between in itertools.product(TRANSFORMS,repeat=depth-1):out.append(path_id(orient,layers,between))
 return out
def scope():
 counts={str(d):4*(7**d)*(4**(d-1)) for d in (1,2,3)}
 return {'identity':IDENTITY,'mode':'CFB8','key_family':'fixed Zombies conventions pinned by cascade/runtime controls','external_iv':'every independent IV at every layer; unknown and not searched','input_bytes':546,'backends':list(BACKENDS),'depths':[1,2,3],'outer_orientations':list(ORIENTATIONS),'interlayer_involutions':list(TRANSFORMS),'endpoint_counts_by_depth':counts,'total_path_endpoints':sum(counts.values()),'intermediate_policy':'record endpoint classification but always expand through depth 3, including rejected or empty intermediate endpoints','endpoint':'A105 necessary byte filter followed by boundary-aware five-sequence UTF-8 FSA','empty_interval':'inconclusive and still expanded','survivors':'retain complete known interval bytes/states and independently replay full chains under two IV suites'}
def require_gate():
 gate=json.loads(GATE.read_text());assert gate['identity']==IDENTITY and gate['target_evaluated'] is False and gate['authorization']=='FABLE preregistered; root GO required'
 assert isinstance(gate.get('fable_reference'),str) and gate['fable_reference'].strip()
 assert sha(MDX)==MDX_SHA
 assert gate['scope']==scope() and gate['driver_sha256']==sha(Path(__file__)) and gate['mdx_sha256']==MDX_SHA and gate['canonical_text_sha256']==TEXT_SHA
 assert set(gate['artifact_hashes'])==set(REQUIRED_ARTIFACTS)
 for rel,want in gate['artifact_hashes'].items():assert sha(ROOT/rel)==want,rel
 return gate,sha(GATE)
def extract():
 text=MDX.read_text();a=text.index('`83 B57B2')+1;b=text.index('`',a);raw=''.join(text[a:b].split()).upper()
 assert len(raw)==1092 and hashlib.sha256(raw.encode()).hexdigest()==TEXT_SHA
 data=bytes.fromhex(raw);return raw,{name:transform(data,name) for name in ORIENTATIONS}
def endpoint(data,left,right,total):
 initial={0} if left==0 else {0,1,2};terminal={0} if right==total else {0,1,2}
 if not data:return {'classification':'inconclusive_empty','accepted':None,'initial_states':sorted(initial),'ending_states':sorted(initial),'terminal_states':sorted(terminal),'witness':None}
 for i,v in enumerate(data):
  if v not in RELAXED:
   return {'classification':'rejected_a105','accepted':False,'initial_states':sorted(initial),'ending_states':[],'terminal_states':sorted(terminal),'witness':{'relative_offset':i,'absolute_offset':left+i,'byte':v,'reason':'outside A105'}}
 states=set(initial)
 for i,v in enumerate(data):
  nxt=set()
  for state in states:
   if state==0:
    if v in (9,10,13) or 32<=v<=126:nxt.add(0)
    elif v==0xe2:nxt.add(1)
   elif state==1 and v==0x80:nxt.add(2)
   elif state==2 and v in THIRDS:nxt.add(0)
  if not nxt:return {'classification':'rejected_fsa_transition','accepted':False,'initial_states':sorted(initial),'ending_states':[],'terminal_states':sorted(terminal),'witness':{'relative_offset':i,'absolute_offset':left+i,'byte':v,'prior_states':sorted(states),'reason':'no five-sequence FSA transition'}}
  states=nxt
 accepted=bool(states&terminal)
 if not accepted:return {'classification':'rejected_fsa_terminal','accepted':False,'initial_states':sorted(initial),'ending_states':sorted(states),'terminal_states':sorted(terminal),'witness':{'relative_offset':len(data),'absolute_offset':right,'prior_states':sorted(states),'reason':'interval reaches stream end without terminal state 0'}}
 return {'classification':'retained','accepted':True,'initial_states':sorted(initial),'ending_states':sorted(states),'terminal_states':sorted(terminal),'witness':None}
def suite_ivs(layers,suite):return [bytes(((suite*71+i*37+j*19)&255) for j in range(backend.block_size)) for i,backend in enumerate(layers)]
def reference_cfb(name,obj,data,iv,decrypt):
 if name in ('aes128','des','blowfish','rc2'):
  from Crypto.Cipher import AES,DES,Blowfish,ARC2
  modules={'aes128':AES,'des':DES,'blowfish':Blowfish,'rc2':ARC2};keys={'aes128':runtime.KEY+b'\0'*9,'des':runtime.KEY+b'\0','blowfish':runtime.KEY,'rc2':runtime.KEY};kw={'effective_keylen':1024} if name=='rc2' else {}
  c=modules[name].new(keys[name],modules[name].MODE_CFB,iv=iv,segment_size=8,**kw);return c.decrypt(data) if decrypt else c.encrypt(data)
 if name=='bfcompat':
  from Crypto.Cipher import Blowfish
  rev=lambda x:x[3::-1]+x[7:3:-1];ecb=Blowfish.new(runtime.KEY,Blowfish.MODE_ECB);block=lambda x:rev(ecb.encrypt(rev(x)))
 else:block=obj.encrypt_block
 reg=iv;out=bytearray()
 for value in data:
  z=value^block(reg)[0];ct=value if decrypt else z;out.append(z);reg=reg[1:]+bytes([ct])
 return bytes(out)
def replay_candidate(outer,names,between,left,right,known,objects):
 layers=[objects[n] for n in names];rows=[]
 for suite in (1,2):
  ivs=suite_ivs(layers,suite);value=outer
  for i,(name,obj,iv) in enumerate(zip(names,layers,ivs)):
   value=reference_cfb(name,obj,value,iv,True)
   if i<len(between):value=transform(value,between[i])
  assert value[left:right]==known
  rec=value
  for i in range(len(names)-1,-1,-1):
   if i<len(between):rec=transform(rec,between[i])
   rec=reference_cfb(names[i],layers[i],rec,ivs[i],False)
  assert rec==outer
  rows.append({'iv_suite':suite,'ivs_hex':[x.hex() for x in ivs],'full_plaintext_sha256':hashlib.sha256(value).hexdigest(),'known_interval_matches':True,'full_reencryption_exact':True})
 return rows
def record_case(orientation,outer,names,between,left,right,data,objects):
 ep=endpoint(data,left,right,len(outer));row={'identity':IDENTITY,'case_id':path_id(orientation,names,between),'orientation':orientation,'depth':len(names),'backends':list(names),'interlayer_transforms':list(between),'known_interval':[left,right],'known_bytes':len(data),'known_sha256':hashlib.sha256(data).hexdigest(),'endpoint':ep}
 if ep['classification'] in ('retained','inconclusive_empty'):
  row['candidate_hex']=data.hex();row['two_iv_full_chain_replays']=replay_candidate(outer,names,between,left,right,data,objects)
 else:row['candidate_hex']=None;row['two_iv_full_chain_replays']=None
 return row
def traverse_grid(outer,orientation,objects,backend_choices_by_depth,transform_choices_by_boundary,on_case):
 """Traverse every registered path; `on_case` cannot prune descendants."""
 total=len(outer);count=0
 def walk(left,right,data,names,between):
  nonlocal count
  depth=len(names);assert depth<len(backend_choices_by_depth)
  for name in backend_choices_by_depth[depth]:
   obj=objects[name];z=obj.interval_decrypt(data,left);nl=z['offset'];nd=z['plaintext'];nn=names+(name,)
   on_case(orientation,outer,nn,between,nl,right,nd,objects);count+=1
   if len(nn)<len(backend_choices_by_depth):
    for t in transform_choices_by_boundary[len(nn)-1]:
     tl,tr,td=transform_interval(nl,right,nd,total,t);walk(tl,tr,td,nn,between+(t,))
 walk(0,total,outer,(),())
 return count
def atomic(path,value):
 tmp=path.with_name(path.name+'.tmp')
 if tmp.exists():raise RuntimeError('refusing stale temporary '+str(tmp))
 with tmp.open('x') as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
 os.replace(tmp,path)
def normalized_build(rows):return {n:{'source_command':rows[n]['command'][:-1]+['$TEMP/'+Path(rows[n]['path']).name],'binary_sha256':rows[n]['sha256']} for n in ('bfcompat','twofish','loki97')}|{'compiler':rows['compiler']}
def run(output,checkpoint):
 if output.exists() or checkpoint.exists():raise SystemExit('refusing existing output/checkpoint; this registered run has no resume mode')
 gate,gate_sha=require_gate();raw,oriented=extract()
 with tempfile.TemporaryDirectory(prefix='astra-cascade-target-') as td:
  builds=runtime.build_source_libraries(Path(td));objects=runtime.registry(builds);config={'scope':scope(),'gate_sha256':gate_sha,'driver_sha256':sha(Path(__file__)),'mdx_sha256':MDX_SHA,'canonical_text_sha256':TEXT_SHA,'artifact_hashes':gate['artifact_hashes'],'temporary_source_builds':normalized_build(builds)}
  result={'identity':IDENTITY,'target_evaluated':True,'status':'running','configuration':config,'cases':[]};done=set()
  def collect(orientation,outer,names,between,left,right,data,objs):
   cid=path_id(orientation,names,between);assert cid not in done;done.add(cid)
   result['cases'].append(record_case(orientation,outer,names,between,left,right,data,objs))
   if len(result['cases'])%1000==0:print(json.dumps({'identity':IDENTITY,'completed':len(result['cases']),'case_id':cid}),flush=True)
  for orientation in ORIENTATIONS:
   count=traverse_grid(oriented[orientation],orientation,objects,(BACKENDS,BACKENDS,BACKENDS),(TRANSFORMS,TRANSFORMS),collect)
   assert count==5691;atomic(checkpoint,result)
   print(json.dumps({'identity':IDENTITY,'orientation_complete':orientation,'completed':len(result['cases'])}),flush=True)
  ids=[x['case_id'] for x in result['cases']];expected=expected_ids();assert len(ids)==len(expected)==22764 and set(ids)==set(expected)
  classes={k:sum(x['endpoint']['classification']==k for x in result['cases']) for k in ('rejected_a105','rejected_fsa_transition','rejected_fsa_terminal','retained','inconclusive_empty')}
  result['status']='complete';result['summary']={'path_endpoints':len(ids),'unique_case_ids':len(set(ids)),'counts_by_depth':{str(d):sum(x['depth']==d for x in result['cases']) for d in (1,2,3)},'endpoint_classes':classes,'retained_candidates':classes['retained'],'empty_inconclusive':classes['inconclusive_empty'],'all_retained_or_empty_replayed_under_two_iv_suites':all(len(x['two_iv_full_chain_replays'])==2 for x in result['cases'] if x['endpoint']['classification'] in ('retained','inconclusive_empty')),'intermediate_rejections_did_not_prune_children':True}
  atomic(checkpoint,result);os.replace(checkpoint,output);print(json.dumps({'identity':IDENTITY,'output':str(output),'sha256':sha(output),'summary':result['summary']},indent=2))
def selftest():
 assert sha(MDX)==MDX_SHA;runtime.verify_sources();
 if GATE.exists():require_gate()
 ids=expected_ids();counts={str(d):sum('|d'+str(d)+'|' in x for x in ids) for d in (1,2,3)}
 assert len(ids)==len(set(ids))==22764 and counts=={'1':28,'2':784,'3':21952}
 # Pure geometry/FSA checks, with no extraction or parsing of MDX ciphertext.
 x=bytes.fromhex('e280a6');assert endpoint(x,1,4,9)['accepted'] and endpoint(x,0,3,3)['accepted']
 empty=endpoint(b'',8,8,20);assert empty['classification']=='inconclusive_empty' and empty['accepted'] is None
 print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'rev7_handling':'MDX bytes hashed only; target ciphertext not extracted, parsed, oriented, decrypted, or evaluated','driver_sha256':sha(Path(__file__)),'mdx_sha256':MDX_SHA,'runtime_sha256':sha(RUNTIME/'runtime.py'),'scope':scope(),'id_counts':counts,'gate_present':GATE.exists()},indent=2,sort_keys=True))
def main():
 ap=argparse.ArgumentParser();mode=ap.add_mutually_exclusive_group(required=True);mode.add_argument('--selftest',action='store_true');mode.add_argument('--run-target',action='store_true');ap.add_argument('--target-output',type=Path,default=HERE/'target_results.json');ap.add_argument('--checkpoint',type=Path,default=HERE/'target_checkpoint.json');a=ap.parse_args()
 if a.selftest:selftest()
 else:run(a.target_output,a.checkpoint)
if __name__=='__main__':main()

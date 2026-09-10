#!/usr/bin/env python3
"""Inert gated target driver for exhaustive byte-AMSCO all-IV CFB8 contexts."""
from __future__ import annotations
import argparse,hashlib,itertools,json,math,os,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;SEARCH=HERE.parent;BASE=SEARCH.parent;ROOT=HERE.parents[4];RUNTIME_DIR=ROOT/'research/rev7-20260909-codex/iv_independent/cascade/runtime'
sys.path[:0]=[str(SEARCH),str(BASE),str(RUNTIME_DIR)]
import engine,core,runtime
IDENTITY='ASTRA';MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';GATE=HERE/'target_gate.json';MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
BACKENDS=('aes128','des','blowfish','bfcompat','rc2','twofish','loki97');ORIENTATIONS=core.ORIENTATION_NAMES
REQUIRED_ARTIFACTS=(
 'research/byte_amsco/astra/core.py','research/byte_amsco/astra/controls.py','research/byte_amsco/astra/controls.json','research/byte_amsco/astra/README.md','research/byte_amsco/astra/REPORT.md',
 'research/byte_amsco/astra/search/engine.py','research/byte_amsco/astra/search/controls.py','research/byte_amsco/astra/search/controls.json','research/byte_amsco/astra/search/README.md','research/byte_amsco/astra/search/REPORT.md',
 'research/rev7-20260909-codex/iv_independent/cascade/proof.py','research/rev7-20260909-codex/iv_independent/cascade/controls.json','research/rev7-20260909-codex/iv_independent/cascade/interval_extension.py','research/rev7-20260909-codex/iv_independent/cascade/interval_extension.json',
 'research/rev7-20260909-codex/iv_independent/cascade/runtime/runtime.py','research/rev7-20260909-codex/iv_independent/cascade/runtime/controls.py','research/rev7-20260909-codex/iv_independent/cascade/runtime/controls.json','research/rev7-20260909-codex/iv_independent/cascade/runtime/README.md','research/rev7-20260909-codex/iv_independent/cascade/runtime/source/PROVENANCE.md',
 'research/rev7-20260909-codex/sources/rev9_source/controls.json','research/rev7-20260909-codex/hex_cfb/native_siblings/controls.json',
 'research/byte_amsco/astra/search/target/README.md','research/byte_amsco/astra/search/target/controls.py','research/byte_amsco/astra/search/target/controls.json','research/byte_amsco/astra/search/target/prepare_gate.py',
 *tuple('research/rev7-20260909-codex/iv_independent/cascade/runtime/source/'+rel for rel in runtime.SOURCE_HASHES),)
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def scope():return {'identity':IDENTITY,'input_bytes':546,'unit':'byte','widths':list(range(2,10)),'starts':[1,2],'orientations':list(ORIENTATIONS),'orders':'every width! permutation','transform_count':engine.grid_transform_count(),'backends':list(BACKENDS),'backend_contexts':engine.context_count(),'mode':'CFB8','external_iv':'every independent IV via suffix beginning at backend block size','endpoint':'A105 then five-sequence FSA; initial states {0,1,2}, terminal state 0','caps':'none; every geometry must report width! orders and width!*7 contexts','negative_storage':'canonical digest over every negative plus first three witness examples per geometry','retained_storage':'every order and full suffix, independently decrypted/re-encrypted under two IVs'}
def require_gate():
 gate=json.loads(GATE.read_text());assert gate['identity']==IDENTITY and gate['target_evaluated'] is False and gate['authorization']=='FABLE preregistered; root GO required' and isinstance(gate.get('fable_reference'),str) and gate['fable_reference'].strip();assert sha(MDX)==MDX_SHA
 assert gate['scope']==scope() and gate['driver_sha256']==sha(Path(__file__)) and gate['mdx_sha256']==MDX_SHA and gate['canonical_text_sha256']==TEXT_SHA and set(gate['artifact_hashes'])==set(REQUIRED_ARTIFACTS)
 for rel,want in gate['artifact_hashes'].items():assert sha(ROOT/rel)==want,rel
 return gate,sha(GATE)
def extract():
 text=MDX.read_text();a=text.index('`83 B57B2')+1;b=text.index('`',a);raw=''.join(text[a:b].split()).upper();assert len(raw)==1092 and hashlib.sha256(raw.encode()).hexdigest()==TEXT_SHA;data=bytes.fromhex(raw);return raw,{name:core.orient_bytes(data,name) for name in ORIENTATIONS}
def reference_cfb(name,obj,data,iv,decrypt):
 from Crypto.Cipher import AES,DES,Blowfish,ARC2
 if name in ('aes128','des','blowfish','rc2'):
  mods={'aes128':AES,'des':DES,'blowfish':Blowfish,'rc2':ARC2};keys={'aes128':b'Zombies'+b'\0'*9,'des':b'Zombies\0','blowfish':b'Zombies','rc2':b'Zombies'};kw={'effective_keylen':1024} if name=='rc2' else {};c=mods[name].new(keys[name],mods[name].MODE_CFB,iv=iv,segment_size=8,**kw);return c.decrypt(data) if decrypt else c.encrypt(data)
 if name=='bfcompat':
  rev=lambda x:x[3::-1]+x[7:3:-1];e=Blowfish.new(b'Zombies',Blowfish.MODE_ECB);block=lambda x:rev(e.encrypt(rev(x)))
 else:block=obj.encrypt_block
 reg=iv;out=bytearray()
 for value in data:
  z=value^block(reg)[0];ct=value if decrypt else z;out.append(z);reg=reg[1:]+bytes([ct])
 return bytes(out)
def validate_survivor(observed,width,start,order,row,objects):
 obj=objects[row['cipher']];natural=engine.Geometry.build(len(observed),width,start).gather(observed,order);suffix=bytes.fromhex(row['full_suffix_hex']);assert suffix and row['classification']=='retained' and row['accepted'] and row['tested_suffix_bytes']==len(natural)-obj.block_size
 checks=[]
 for suite in (1,2):
  iv=bytes(((suite*79+i*23+len(row['cipher']))&255) for i in range(obj.block_size));plain=reference_cfb(row['cipher'],obj,natural,iv,True);recipher=reference_cfb(row['cipher'],obj,plain,iv,False);assert plain[obj.block_size:]==suffix and recipher==natural
  checks.append({'iv_suite':suite,'iv_hex':iv.hex(),'full_plaintext_sha256':hashlib.sha256(plain).hexdigest(),'suffix_exact':True,'reencryption_exact':True})
 return {'cipher':row['cipher'],'order':list(order),'full_suffix_hex':row['full_suffix_hex'],'suffix_sha256':row['tested_suffix_sha256'],'suffix_bytes':row['tested_suffix_bytes'],'two_iv_full_reference':checks}
def canonical_negative(order,row):
 return json.dumps([list(order),row['cipher'],row['classification'],row['rejection'],row['tested_suffix_bytes'],row['tested_suffix_sha256'],row['recovered_cipher_prefix_bytes'],row['recovered_cipher_prefix_sha256']],sort_keys=True,separators=(',',':')).encode()+b'\n'
def scan_cell(observed,orientation,width,start,objects):
 expected_orders=math.factorial(width);negative=hashlib.sha256();examples=[];retained=[];by_backend={name:{} for name in BACKENDS};classes={};contexts=0
 def callback(_w,_s,order,row):
  nonlocal contexts;contexts+=1;name=row['cipher'];cl=row['classification'];classes[cl]=classes.get(cl,0)+1;by_backend[name][cl]=by_backend[name].get(cl,0)+1
  if row['accepted']:retained.append(validate_survivor(observed,width,start,order,row,objects))
  else:
   negative.update(canonical_negative(order,row))
   if len(examples)<3:examples.append({'order':list(order),'cipher':name,'classification':cl,'rejection':row['rejection'],'tested_suffix_sha256':row['tested_suffix_sha256'],'recovered_cipher_prefix_sha256':row['recovered_cipher_prefix_sha256']})
 summary=engine.scan_geometry(observed,width,start,objects,callback);assert summary['complete_geometry'] and summary['orders']==expected_orders and contexts==summary['backend_contexts']==expected_orders*len(BACKENDS)
 for name in BACKENDS:assert sum(by_backend[name].values())==expected_orders
 return {'identity':IDENTITY,'cell_id':orientation+'|w'+str(width)+'|s'+str(start),'orientation':orientation,'width':width,'start':start,'observed_sha256':hashlib.sha256(observed).hexdigest(),'orders_examined':expected_orders,'expected_orders':expected_orders,'backend_contexts_examined':contexts,'expected_backend_contexts':expected_orders*7,'unexamined_orders':0,'unexamined_backend_contexts':0,'complete_uncapped':True,'classification_counts':classes,'counts_by_backend':by_backend,'negative_count':contexts-len(retained),'negative_rows_sha256':negative.hexdigest(),'negative_digest_serialization':'UTF-8 canonical JSON array [order,cipher,class,rejection,tested_bytes,tested_sha,prefix_bytes,prefix_sha] plus LF in scan callback order','first_negative_examples':examples,'retained_count':len(retained),'retained':retained}
def normalized_build(builds):return {'compiler':builds['compiler'],**{n:{'binary_sha256':builds[n]['sha256'],'source_command':builds[n]['command'][:-1]+['$TEMP/'+Path(builds[n]['path']).name]} for n in ('bfcompat','twofish','loki97')}}
def atomic(path,value):
 tmp=path.with_name(path.name+'.tmp')
 if tmp.exists():raise RuntimeError('refusing stale temporary '+str(tmp))
 with tmp.open('x') as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
 os.replace(tmp,path)
def run(output,checkpoint):
 if output.exists() or checkpoint.exists():raise SystemExit('refusing existing output/checkpoint; no resume mode')
 gate,gate_sha=require_gate();raw,oriented=extract()
 with tempfile.TemporaryDirectory(prefix='astra-byte-amsco-target-') as td:
  builds=runtime.build_source_libraries(Path(td));objects=runtime.registry(builds);assert tuple(objects)==BACKENDS
  result={'identity':IDENTITY,'target_evaluated':True,'status':'running','configuration':{'scope':scope(),'gate_sha256':gate_sha,'driver_sha256':sha(Path(__file__)),'mdx_sha256':MDX_SHA,'canonical_text_sha256':TEXT_SHA,'artifact_hashes':gate['artifact_hashes'],'temporary_source_builds':normalized_build(builds)},'cells':[]}
  for orientation in ORIENTATIONS:
   for width in range(2,10):
    for start in (1,2):
     cell=scan_cell(oriented[orientation],orientation,width,start,objects);result['cells'].append(cell);atomic(checkpoint,result);print(json.dumps({'identity':IDENTITY,'cells':len(result['cells']),'cell_id':cell['cell_id'],'contexts':cell['backend_contexts_examined'],'retained':cell['retained_count']}),flush=True)
  assert len(result['cells'])==64 and len({x['cell_id'] for x in result['cells']})==64 and sum(x['orders_examined'] for x in result['cells'])==3272896 and sum(x['backend_contexts_examined'] for x in result['cells'])==22910272 and all(x['complete_uncapped'] and x['unexamined_orders']==x['unexamined_backend_contexts']==0 for x in result['cells'])
  total_classes={}
  for cell in result['cells']:
   for k,v in cell['classification_counts'].items():total_classes[k]=total_classes.get(k,0)+v
  result['status']='complete';result['summary']={'geometries':64,'orders_examined':3272896,'backend_contexts_examined':22910272,'unexamined':0,'classification_counts':total_classes,'retained_count':sum(x['retained_count'] for x in result['cells']),'all_complete_uncapped':True}
  atomic(checkpoint,result);os.replace(checkpoint,output);print(json.dumps({'identity':IDENTITY,'output':str(output),'sha256':sha(output),'summary':result['summary']},indent=2))
def selftest():
 assert sha(MDX)==MDX_SHA and engine.grid_transform_count()==3272896 and engine.context_count()==22910272;runtime.verify_sources()
 if GATE.exists():require_gate()
 ids={o+'|w'+str(w)+'|s'+str(s) for o in ORIENTATIONS for w in range(2,10) for s in (1,2)};assert len(ids)==64
 print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'rev7_handling':'MDX bytes hashed only; ciphertext not extracted, parsed, oriented, inverted, decrypted, or evaluated','driver_sha256':sha(Path(__file__)),'mdx_sha256':MDX_SHA,'scope':scope(),'geometry_ids':64,'gate_present':GATE.exists()},indent=2,sort_keys=True))
def main():
 ap=argparse.ArgumentParser();mode=ap.add_mutually_exclusive_group(required=True);mode.add_argument('--selftest',action='store_true');mode.add_argument('--run-target',action='store_true');ap.add_argument('--target-output',type=Path,default=HERE/'target_results.json');ap.add_argument('--checkpoint',type=Path,default=HERE/'target_checkpoint.json');a=ap.parse_args();selftest() if a.selftest else run(a.target_output,a.checkpoint)
if __name__=='__main__':main()

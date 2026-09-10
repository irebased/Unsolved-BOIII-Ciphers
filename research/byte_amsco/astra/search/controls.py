#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,importlib.util,itertools,json,math,platform,random,sys,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;BASE=HERE.parent;CORE_PY=BASE/'core.py';LEDGER=HERE/'controls.json';RUNTIME_DIR=HERE.parents[2]/'rev7-20260909-codex/iv_independent/cascade/runtime';TARGET_REF=HERE.parents[2]/'rev7-20260909-codex/iv_independent/cascade/target/run_target.py'
PINS={'base/core.py':'2e7b413cb01396c8c6c97f21ad4a1e46939c3c1488c27e1c48bed8e24a48b990','base/controls.py':'b187ab27bbde490399333c19ddf62f8cb13f514b90fb50614cb231b4a5f65ad0','base/controls.json':'767d651729055d1d6fa202e8983635d3afafd46d06729924569db7260ed21175','base/README.md':'cc25ff6fbba54f4125ea0ab82c68389f5da3feb0f792abfd6e235a07b108e20b','base/REPORT.md':'457887f63345831ea8c7d636318c5cb919c30e5f11e1fb709bf00c8916c8dbf0','runtime.py':'8b7899fc7aedb2de04cb900876987e6b3385922d4e2e53c913562659913818f4','runtime/controls.json':'483fa566e1030e489f5bb2958bcada9f1f95762f83104b7b9e8437c360787ee5','target/reference.py':'dea3bceff94993abb7f59993300f71552c3ca84b344e96b22d27479c3dc05d41'}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);assert spec.loader;sys.modules[name]=m;spec.loader.exec_module(m);return m
def verify_pins():
 paths={'base/core.py':CORE_PY,'base/controls.py':BASE/'controls.py','base/controls.json':BASE/'controls.json','base/README.md':BASE/'README.md','base/REPORT.md':BASE/'REPORT.md','runtime.py':RUNTIME_DIR/'runtime.py','runtime/controls.json':RUNTIME_DIR/'controls.json','target/reference.py':TARGET_REF}
 for k,p in paths.items():assert sha(p)==PINS[k],k
 return paths
def strict_plain(n=546):
 phrase='AMSCO SEARCH – — ‘ ’ … CONTROL. '.encode();tail=b'END.\n';room=n-len(tail);return phrase*(room//len(phrase))+b'A'*(room%len(phrase))+tail
def independent_classify(data):
 relaxed={9,10,13,*range(32,127),0xe2,0x80,0x93,0x94,0x98,0x99,0xa6};states={0,1,2}
 for i,v in enumerate(data):
  if v not in relaxed:return ('rejected_a105',i,v)
  nxt=set()
  for state in states:
   if state==0 and (v in (9,10,13) or 32<=v<=126):nxt.add(0)
   elif state==0 and v==0xe2:nxt.add(1)
   elif state==1 and v==0x80:nxt.add(2)
   elif state==2 and v in (0x93,0x94,0x98,0x99,0xa6):nxt.add(0)
  if not nxt:return ('rejected_fsa_transition',i,v)
  states=nxt
 return ('retained',None,None) if 0 in states else ('rejected_fsa_terminal',len(data),None)
def full_reference(name,obj,ciphertext,iv,decrypt=True):
 from Crypto.Cipher import AES,DES,Blowfish,ARC2
 if name in ('aes128','des','blowfish','rc2'):
  mods={'aes128':AES,'des':DES,'blowfish':Blowfish,'rc2':ARC2};keys={'aes128':b'Zombies'+b'\0'*9,'des':b'Zombies\0','blowfish':b'Zombies','rc2':b'Zombies'};kw={'effective_keylen':1024} if name=='rc2' else {};c=mods[name].new(keys[name],mods[name].MODE_CFB,iv=iv,segment_size=8,**kw);return c.decrypt(ciphertext) if decrypt else c.encrypt(ciphertext)
 if name=='bfcompat':
  rev=lambda x:x[3::-1]+x[7:3:-1];ecb=Blowfish.new(b'Zombies',Blowfish.MODE_ECB);block=lambda x:rev(ecb.encrypt(rev(x)))
 else:block=obj.encrypt_block
 reg=iv;out=bytearray()
 for value in ciphertext:
  z=value^block(reg)[0];ct=value if decrypt else z;out.append(z);reg=reg[1:]+bytes([ct])
 return bytes(out)
def geometry_controls(core,engine):
 count=0;digest=hashlib.sha256()
 for n in range(25):
  raw=bytes(range(n))
  for w in range(2,7):
   for start in (1,2):
    g=engine.Geometry.build(n,w,start)
    for order in itertools.permutations(range(w)):
     observed=core.amsco_forward(raw,w,order,start);actual=g.gather(observed,order);assert actual==raw==core.amsco_inverse(observed,w,order,start);digest.update(actual);count+=1
 return {'cases':count,'lengths':[0,24],'widths':[2,6],'both_starts':True,'all_permutations':True,'base_inverse_exact':True,'digest':digest.hexdigest()}
def plant_controls(core,engine,runtime,objects):
 order=(3,5,1,6,0,4,2);plain=strict_plain();rows=[]
 for bi,(name,obj) in enumerate(objects.items()):
  for start in (1,2):
   iv=bytes((bi*31+start*17+i*13)&255 for i in range(obj.block_size));ct=full_reference(name,obj,plain,iv,False);observed0=core.amsco_forward(ct,7,order,start);orows=[]
   for orient in core.ORIENTATION_NAMES:
    displayed=core.canonical_for_orientation(observed0,orient);observed=core.orient_bytes(displayed,orient);assert observed==observed0
    found=next(x for x in engine.evaluate_order(observed,engine.Geometry.build(546,7,start),order,objects) if x['cipher']==name);ref=full_reference(name,obj,ct,iv,True)[obj.block_size:];assert ref==plain[obj.block_size:] and found['classification']=='retained' and bytes.fromhex(found['full_suffix_hex'])==ref
    orows.append({'orientation':orient,'displayed_sha256':hashlib.sha256(displayed).hexdigest(),'classification':found['classification'],'suffix_sha256':found['tested_suffix_sha256'],'exact_full_reference':True})
   rows.append({'cipher':name,'start':start,'order':list(order),'orientations':orows})
 return {'plaintext_sha256':hashlib.sha256(plain).hexdigest(),'rows':rows,'all_7_backends_both_starts_all_4_orientations':len(rows)==14 and all(len(x['orientations'])==4 for x in rows)}
def reject_controls(core,engine,objects):
 raw=bytes((i*71+29)&255 for i in range(546));rows=[];order=(6,0,4,1,5,2,3)
 for orient in core.ORIENTATION_NAMES:
  observed=core.orient_bytes(raw,orient);g=engine.Geometry.build(546,7,2);natural=g.gather(observed,order)
  found=engine.evaluate_order(observed,g,order,objects)
  for row in found:
   obj=objects[row['cipher']];iv=bytes((i*19+3)&255 for i in range(obj.block_size));suffix=full_reference(row['cipher'],obj,natural,iv,True)[obj.block_size:];want=independent_classify(suffix);assert row['classification']==want[0]
   if want[1] is not None:assert row['rejection']['suffix_offset']==want[1] and row['rejection']['plaintext_byte']==want[2]
   rows.append({'orientation':orient,'cipher':row['cipher'],'classification':row['classification'],'rejection':row['rejection'],'independent_full_reference_and_first_failure':True})
 return rows
def boundary_controls(core,engine,objects):
 rows=[];order=(2,0,4,1,3);w=5;start=1
 for name,obj in objects.items():
  for state in (1,2):
   plain=bytearray(b'A'*546);seq=bytes.fromhex('e280a6');pos=obj.block_size-state;plain[pos:pos+3]=seq;plain[-5:]=b'END.\n';iv=bytes((i*7+state*41)&255 for i in range(obj.block_size));ct=full_reference(name,obj,bytes(plain),iv,False);observed=core.amsco_forward(ct,w,order,start);row=next(x for x in engine.evaluate_order(observed,engine.Geometry.build(546,w,start),order,objects) if x['cipher']==name);assert row['classification']=='retained' and bytes.fromhex(row['full_suffix_hex'])==bytes(plain)[obj.block_size:];rows.append({'cipher':name,'incoming_state':state,'classification':'retained','suffix_prefix_hex':bytes(plain)[obj.block_size:obj.block_size+3].hex()})
  plain=bytearray(b'A'*546);plain[-2:]=bytes.fromhex('e280');iv=b'0'*obj.block_size;ct=full_reference(name,obj,bytes(plain),iv,False);observed=core.amsco_forward(ct,w,order,start);row=next(x for x in engine.evaluate_order(observed,engine.Geometry.build(546,w,start),order,objects) if x['cipher']==name);assert row['classification']=='rejected_fsa_terminal';rows.append({'cipher':name,'incoming_state':'terminal_fixture','classification':row['classification'],'terminal_prior_states':row['rejection']['prior_states']})
 return rows
def benchmark(engine,objects):
 observed=bytes((i*29+113)&255 for i in range(546));g=engine.Geometry.build(546,9,1);count=20000;classes={};digest=hashlib.sha256();began=time.perf_counter()
 def collect(_w,_start,_order,row):digest.update(row['tested_suffix_sha256'].encode())
 summary=engine.scan_geometry(observed,9,1,objects,collect,order_limit=count);classes=summary['classification_counts']
 elapsed=time.perf_counter()-began;contexts=summary['backend_contexts'];total=engine.context_count(len(objects))
 return {'orders':count,'backend_contexts':contexts,'seconds':elapsed,'orders_per_second':count/elapsed,'contexts_per_second':contexts/elapsed,'exact_prospective_contexts':total,'linear_seconds_estimate':elapsed*total/contexts,'classification_counts':classes,'digest':digest.hexdigest(),'limits':'Synthetic width-9 sample only; linear estimate excludes survivor output, checkpoints, target extraction, and platform variance.'}
def regenerate(out):
 if out.exists():raise SystemExit('refusing existing output: '+str(out))
 paths=verify_pins();core=load(CORE_PY,'amsco_base_core');engine=load(HERE/'engine.py','amsco_search_engine');runtime=load(RUNTIME_DIR/'runtime.py','amsco_runtime')
 with tempfile.TemporaryDirectory(prefix='astra-amsco-search-') as td:
  builds=runtime.build_source_libraries(Path(td));objects=runtime.registry(builds);geometry=geometry_controls(core,engine);plants=plant_controls(core,engine,runtime,objects);rejects=reject_controls(core,engine,objects);boundaries=boundary_controls(core,engine,objects);bench=benchmark(engine,objects)
 result={'identity':'ASTRA','target_evaluated':False,'rev7_read':False,'scope':'Synthetic-only lazy byte-AMSCO inverse plus all-IV seven-backend CFB8 endpoint search controls; widths 2..9 prospective only.','prospective_scope':{'widths':list(range(2,10)),'starts':[1,2],'orientations':list(core.ORIENTATION_NAMES),'orders':'all width!','transform_count':engine.grid_transform_count(),'backends':list(objects),'context_cases':engine.context_count(len(objects)),'mode':'CFB8 every external IV by block-boundary suffix'},'geometry':geometry,'plants':plants,'early_rejections':rejects,'utf8_boundaries':boundaries,'benchmark':bench,'dependency_hashes':{k:sha(v) for k,v in paths.items()}|{'engine.py':sha(HERE/'engine.py'),'controls.py':sha(Path(__file__))},'environment':{'python':platform.python_version(),'compiler':builds['compiler']},'assertions':{'all_passed':True,'index_gather_matches_accepted_base_inverse':True,'full_plants_all_backends_starts_orientations':plants['all_7_backends_both_starts_all_4_orientations'],'early_reject_matches_independent_full_cfb':all(x['independent_full_reference_and_first_failure'] for x in rejects),'utf8_initial_states_1_2_and_terminal':len(boundaries)==21,'exact_transform_count':engine.grid_transform_count()==3272896,'exact_context_count':engine.context_count()==22910272,'no_target_read_or_evaluation':True}}
 out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':'ASTRA','output':str(out),'sha256':sha(out),'benchmark':bench},indent=2))
def verify(path=LEDGER):
 paths=verify_pins();d=json.loads(path.read_text());assert d['identity']=='ASTRA' and d['target_evaluated'] is False and d['rev7_read'] is False
 assert d['dependency_hashes']==({k:sha(v) for k,v in paths.items()}|{'engine.py':sha(HERE/'engine.py'),'controls.py':sha(Path(__file__))}) and d['prospective_scope']['transform_count']==3272896 and d['prospective_scope']['context_cases']==22910272 and all(d['assertions'].values())
 assert len(d['plants']['rows'])==14 and len(d['early_rejections'])==28 and len(d['utf8_boundaries'])==21 and d['benchmark']['orders']==20000
 print(json.dumps({'identity':'ASTRA','verified':True,'verification_scope':'stdlib source/dependency/ledger structure only; no cryptographic replay','ledger_sha256':sha(path),'target_evaluated':False},sort_keys=True))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);ap.add_argument('--ledger',type=Path,default=LEDGER);a=ap.parse_args();regenerate(a.regenerate) if a.regenerate else verify(a.ledger)
if __name__=='__main__':main()

#!/usr/bin/env python3
from __future__ import annotations
import argparse,base64,hashlib,importlib.util,itertools,json,platform,subprocess,sys,tempfile,time,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent;LEDGER=HERE/'controls.json';CORE=HERE/'core.py';GEOM=HERE.parent/'amsco_geometry.py';GEOM_LEDGER=HERE.parent/'geometry.json'
RDIR=HERE.parents[2]/'rev7-20260909-codex/rijndael256_cfb';RUNTIME=RDIR/'runtime.py';RAW=RDIR/'controls.json';PACK=RDIR/'controls.pack.json';PACKER=RDIR/'pack_controls.py'
PINS={'geometry.py':'c43e6412cbf2ac34e137801e1fd9c13e8c46bb89296bb89484c01d28a505cae6','geometry.json':'5e61da73d918e2e4b52d81927f01227152bd15ad6e8a9b8f7732ec9ad81939b7','r256_runtime.py':'115ea9b644a8fa3f62d2ea17afb85434966cea5c76ebdeb3582697d2d176bae0','r256_pack.json':'32cce50eea314037ad4df0c87839ffef67e8c6dcf029203f74065ef8346b6fe4','r256_packer.py':'6a34904f599189c9ed3181e59263afb3e213debcfe595391702146b9e6246002'}
BACKENDS=('aes128','des','blowfish','bfcompat','rc2','twofish','loki97','rijndael256_key16','rijndael256_key24','rijndael256_key32');ORIENTS=('forward','full_hex_reverse','byte_reverse','nibble_swap');PREFIXES=(b'',b'\xc2',b'\xe1',b'\xf1')
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;assert spec.loader;spec.loader.exec_module(m);return m
def unpack_primitive():
 assert sha(PACK)==PINS['r256_pack.json'] and sha(PACKER)==PINS['r256_packer.py'];env=json.loads(PACK.read_text());compressed=base64.b85decode(env['payload_base85']);assert hashlib.sha256(compressed).hexdigest()==env['compressed_sha256'];raw=zlib.decompress(compressed);assert len(raw)==env['raw_bytes'] and hashlib.sha256(raw).hexdigest()==env['raw_sha256']=='511aad6d309c05b16a8b2281f69bc748f180af499988016659554324b7f135d3'
 if RAW.exists():assert RAW.read_bytes()==raw
 return raw,json.loads(raw)
def verify_sources():
 direct={'geometry.py':GEOM,'geometry.json':GEOM_LEDGER,'r256_runtime.py':RUNTIME,'r256_pack.json':PACK,'r256_packer.py':PACKER}
 for label,path in direct.items():assert sha(path)==PINS[label],(label,sha(path))
 raw,_adapter_ledger=unpack_primitive();paths=dict(direct);primitive_dir=RDIR.parent/'rijndael256_controls';primitive=json.loads((primitive_dir/'controls.json').read_text())
 for rel,want in primitive['source_hashes'].items():
  path=primitive_dir/rel;assert sha(path)==want;paths['primitive/'+rel]=path
 cascade_dir=RDIR.parent/'iv_independent/cascade/runtime';cascade=json.loads((cascade_dir/'controls.json').read_text())
 assert sha(cascade_dir/'runtime.py')=='8b7899fc7aedb2de04cb900876987e6b3385922d4e2e53c913562659913818f4'
 paths['cascade/runtime.py']=cascade_dir/'runtime.py';paths['cascade/controls.json']=cascade_dir/'controls.json'
 for rel,want in cascade['source']['files'].items():
  path=cascade_dir/'source'/rel;assert sha(path)==want;paths['cascade/source/'+rel]=path
 return paths,raw
def build_registry(temp):
 runtime=load('astra_utf8_r256_runtime',RUNTIME);builder=load('astra_utf8_r256_builder',RDIR.parent/'rijndael256_controls/build_source.py');cascade=load('astra_utf8_cascade_runtime',RDIR.parent/'iv_independent/cascade/runtime/runtime.py');builder.verify_sources();cascade.verify_sources();rlib=temp/'r256.dylib';rcmd=builder.build(rlib);existing=cascade.build_source_libraries(temp/'cascade');registry=runtime.extended_registry(rlib,cascade,existing);assert tuple(registry)==BACKENDS;return registry,rcmd,existing,rlib
def strict(data):
 try:data.decode('utf-8','strict');return True
 except UnicodeDecodeError:return False
def cut_oracle(data):return any(strict(prefix+data) for prefix in PREFIXES)
def dfa(core,data,initial):
 mask=initial
 for value in data:mask=core.step(mask,value)
 return bool(mask&core.TERMINAL_MASK),mask
def exhaustive_short(core):
 digest=hashlib.sha256();counts={'strings':0,'complete_accept':0,'cut_accept':0}
 for length in (1,2):
  for values in itertools.product(range(256),repeat=length):
   data=bytes(values);a,m=dfa(core,data,1<<core.B);b,n=dfa(core,data,core.INITIAL_MASK);assert a==strict(data) and b==cut_oracle(data);counts['strings']+=1;counts['complete_accept']+=a;counts['cut_accept']+=b;digest.update(data+bytes((a,b)))
 counts['digest']=digest.hexdigest();return counts
def class_products(core):
 reps=(0,0x7f,0x80,0x8f,0x90,0x9f,0xa0,0xbf,0xc0,0xc1,0xc2,0xdf,0xe0,0xe1,0xec,0xed,0xee,0xef,0xf0,0xf1,0xf3,0xf4,0xf5,0xff);cont=(0x7f,0x80,0x8f,0x90,0x9f,0xa0,0xbf,0xc0);leads=(0xc2,0xdf,0xe0,0xe1,0xed,0xee,0xf0,0xf1,0xf4,0xf5)
 values=set(itertools.product(reps,repeat=3))
 cores=[bytes((lead,)+tail) for lead in leads for tail in itertools.product(cont,repeat=3)]
 values.update(tuple(x) for x in cores);values.update(tuple(b'Z'+x) for x in cores);values.update(tuple(x+b'Z') for x in cores)
 digest=hashlib.sha256();bylen={};complete=cut=0
 for tup in sorted(values,key=lambda x:(len(x),x)):
  data=bytes(tup);a,_=dfa(core,data,1<<core.B);b,_=dfa(core,data,core.INITIAL_MASK);assert a==strict(data) and b==cut_oracle(data);bylen[str(len(data))]=bylen.get(str(len(data)),0)+1;complete+=a;cut+=b;digest.update(bytes((len(data),))+data+bytes((a,b)))
 return {'cases':len(values),'by_length':bylen,'complete_accept':complete,'cut_accept':cut,'digest':digest.hexdigest()}
def all_scalars(core):
 digest=hashlib.sha256();count=0;lengths={}
 for value in range(0x110000):
  if 0xd800<=value<=0xdfff:continue
  encoded=chr(value).encode('utf-8');ok,mask=dfa(core,encoded,1<<core.B);assert ok and mask==1;digest.update(value.to_bytes(4,'big')+encoded);count+=1;lengths[str(len(encoded))]=lengths.get(str(len(encoded)),0)+1
 return {'scalar_count':count,'encoded_length_counts':lengths,'digest':digest.hexdigest()}
def geometry_controls(core,geom):
 raw=bytes((i*37+11)&255 for i in range(546));text=raw.hex().upper();rows=[];cross=0
 for width in range(2,10):
  for start in ('12','21'):
   layout=core.IndexedLayout.compile(1092,width,start,geom)
   for label,order in geom.order_variants(width,start,'utf8_search'):
    observed,labels=geom.forward(list(text),order,start);observed=''.join(observed);full=''.join(geom.inverse(list(observed),order,start,1092));oracle=''.join(geom.oracle_inverse(list(observed),order,start,1092));gathered=layout.gather_bytes(observed,order);assert full==oracle==text and gathered==raw;starts=layout.starts(order);assert all(labels[layout.observed_index(i,starts)]==i for i in range(1092));c=sum(layout.column_of[2*i]!=layout.column_of[2*i+1] for i in range(546));cross+=c;rows.append([width,start,label,list(order),c,hashlib.sha256(observed.encode()).hexdigest()])
 return {'cases':len(rows),'cross_column_byte_pairs':cross,'digest':hashlib.sha256(json.dumps(rows,separators=(',',':')).encode()).hexdigest(),'examples':rows[:2]+rows[-2:]}
def dense_plain(cut,state):
 phrase='UTF8 Ω € 😀 CONTROL\0\t\n\r BOM:\ufeff '.encode();head=b'A'*64;tail=b'END.\n';room=546-len(head)-len(tail);value=bytearray(head+phrase*(room//len(phrase))+b'A'*(room%len(phrase))+tail)
 leads={'boundary':None,'remain1':b'\xc2\xa2','remain2':b'\xe1\x80\x80','remain3':b'\xf1\x80\x80\x80'}
 seq=leads[state]
 if seq:value[cut-1:cut-1+len(seq)]=seq
 assert len(value)==546 and strict(bytes(value));return bytes(value)
def iv(backend,suite,index):return bytes((suite*73+index*29+j*19)&255 for j in range(backend.block_size))
def orient(text,name,geom):return geom.orientations(text)[name]
def plants(core,geom,registry):
 rows=[];state_names=('boundary','remain1','remain2','remain3');retained_total=0
 for index,name in enumerate(BACKENDS):
  backend=registry[name];state=state_names[index%4];plain=dense_plain(backend.block_size,state);order=geom.deterministic_order(9,'21','utf8|'+name);layout=core.IndexedLayout.compile(1092,9,'21',geom)
  for orientation in ORIENTS:
   for suite in (1,2):
    vector_iv=iv(backend,suite,index);cipher=backend.encrypt_cfb8(plain,vector_iv);trans=''.join(geom.forward(list(cipher.hex().upper()),order,'21')[0]);display=orient(trans,orientation,geom);processed=orient(display,orientation,geom);assert processed==trans and ''.join(geom.inverse(list(processed),order,'21',1092))==cipher.hex().upper();outcome=core.Search(layout,processed,registry).evaluate_order(order);kept={r['backend']:r for r in outcome['retained']};assert name in kept;suffix=bytes.fromhex(kept[name]['suffix_hex']);assert suffix==plain[backend.block_size:] and cut_oracle(suffix);alt=iv(backend,3-suite,index);p2=backend.decrypt_cfb8(cipher,alt);assert p2[backend.block_size:]==suffix and backend.encrypt_cfb8(p2,alt)==cipher;retained_total+=len(kept);rows.append({'id':f'{name}_{orientation}_iv{suite}','backend':name,'block_size':backend.block_size,'cut_initial_state':state,'orientation':orientation,'order':list(order),'iv_hex':vector_iv.hex(),'alternate_iv_hex':alt.hex(),'display_sha256':hashlib.sha256(display.encode()).hexdigest(),'cipher_sha256':hashlib.sha256(cipher).hexdigest(),'outcome':outcome,'suffix_hex':suffix.hex(),'suffix_sha256':hashlib.sha256(suffix).hexdigest(),'independent_cut_oracle_accepts':True,'fixed_cipher_alternate_iv_suffix_equal':True,'alternate_iv_reencrypt_exact':True})
 assert len(rows)==80
 return {'cases':80,'contexts':800,'retained_contexts':retained_total,'rows':rows}
def negatives(core,geom,registry):
 rows=[]
 for index,name in enumerate(BACKENDS):
  backend=registry[name];plain=bytearray(dense_plain(backend.block_size,'boundary'));bad=backend.block_size+11;plain[bad]=0xff;vector_iv=iv(backend,1,index);cipher=backend.encrypt_cfb8(bytes(plain),vector_iv);order=geom.deterministic_order(9,'21','bad|'+name);trans=''.join(geom.forward(list(cipher.hex().upper()),order,'21')[0]);out=core.Search(core.IndexedLayout.compile(1092,9,'21',geom),trans,{name:backend}).evaluate_order(order);assert not out['retained'];w=out['rejection_witnesses'][name];assert w['kind']=='byte_rejection' and w['plaintext_offset']==bad;rows.append({'backend':name,'malformed_offset':bad,'witness':w,'rejected':True})
 # Force a terminal-only incomplete sequence through a tiny deterministic mock backend.
 return rows
def terminal_failure(core,geom):
 class ZeroBackend:
  block_size=1
  def encrypt_block(self,value):assert len(value)==1;return b'\0'
 natural=b'X'+b'ASCII'+b'\xc2';order=(1,0);observed=''.join(geom.forward(list(natural.hex().upper()),order,'21')[0]);out=core.Search(core.IndexedLayout.compile(len(observed),2,'21',geom),observed,{'zero_oracle':ZeroBackend()}).evaluate_order(order);assert not out['retained'];w=out['rejection_witnesses']['zero_oracle'];assert w['kind']=='terminal_rejection' and w['reason']=='incomplete_utf8_at_true_end';return {'natural_ciphertext_hex':natural.hex(),'order':list(order),'outcome':out,'terminal_failure_recorded_separately':True}
def benchmark(core,geom,registry):
 material=bytearray();counter=0
 while len(material)<546:material.extend(hashlib.sha256(('ASTRA char AMSCO benchmark|'+str(counter)).encode()).digest());counter+=1
 raw=bytes(material[:546]);observed=raw.hex().upper();search=core.Search(core.IndexedLayout.compile(1092,9,'21',geom),observed,registry);began=time.perf_counter();scan=search.scan(itertools.islice(itertools.permutations(range(9)),20000));elapsed=time.perf_counter()-began;assert scan['totals']['orders']==20000 and scan['totals']['contexts']==200000
 prospective=4*sum(__import__('math').factorial(w) for w in range(2,10));return {'fixture_formula':"concat SHA256(UTF8('ASTRA char AMSCO benchmark|'+decimal_counter)); first546 bytes; uppercase hex",'fixture_bytes_sha256':hashlib.sha256(raw).hexdigest(),'fixture_hex_sha256':hashlib.sha256(observed.encode()).hexdigest(),'fixture_hex':observed,'width':9,'start':'21','orientation':'forward','orders':'first 20000 lexicographic','scan':scan,'elapsed_seconds':elapsed,'orders_per_second':20000/elapsed,'prospective_orders':prospective,'prospective_contexts':prospective*10,'linear_projection_seconds':prospective/(20000/elapsed),'projection_limit':'synthetic input heuristic only'}
def normalize(v,temp):
 if isinstance(v,dict):return {k:normalize(x,temp) for k,x in v.items()}
 if isinstance(v,list):return [normalize(x,temp) for x in v]
 return v.replace(str(temp.resolve()),'<temporary-build>').replace(str(temp),'<temporary-build>') if isinstance(v,str) else v
def produce(output):
 paths,_=verify_sources();core=load('astra_utf8_core',CORE);geom=load('astra_utf8_geom',GEOM)
 with tempfile.TemporaryDirectory(prefix='astra-utf8-search-') as td:
  temp=Path(td);registry,rcmd,existing,rlib=build_registry(temp);short=exhaustive_short(core);classes=class_products(core);scalars=all_scalars(core);g=geometry_controls(core,geom);boundary=[]
  samples={'ascii_nul_controls':b'A\0\t\n\r','valid_max':bytes.fromhex('f48fbfbf'),'overlong':bytes.fromhex('c080'),'surrogate':bytes.fromhex('eda080'),'above_max':bytes.fromhex('f4908080'),'truncated2':bytes.fromhex('c2'),'truncated3':bytes.fromhex('e180'),'truncated4':bytes.fromhex('f18080'),'cut_remain1':bytes.fromhex('8041'),'cut_remain2':bytes.fromhex('808041'),'cut_remain3':bytes.fromhex('80808041')}
  for name,data in samples.items():
   complete,cm=dfa(core,data,1<<core.B);cut,km=dfa(core,data,core.INITIAL_MASK);assert complete==strict(data) and cut==cut_oracle(data);boundary.append({'id':name,'hex':data.hex(),'complete':complete,'cut':cut,'complete_states':core.states(cm),'cut_states':core.states(km)})
  planted=plants(core,geom,registry);negative=negatives(core,geom,registry);terminal=terminal_failure(core,geom);bench=benchmark(core,geom,registry);source_hashes={label:sha(path) for label,path in paths.items()};source_hashes.update({'core.py':sha(CORE),'controls.py':sha(Path(__file__))})
  result={'identity':'ASTRA','target_evaluated':False,'rev7_read':False,'scope':'Synthetic RFC3629 indexed character-AMSCO CFB8 suffix controls and bounded benchmark.','rfc':'https://www.rfc-editor.org/rfc/rfc3629#section-4','short_exhaustive':short,'bounded_class_products':classes,'all_unicode_scalars':scalars,'boundary_vectors':boundary,'geometry':g,'plants':planted,'malformed_negative_plants':negative,'terminal_failure_control':terminal,'benchmark':bench,'model':{'states':list(core.STATE_NAMES),'initial_states':['boundary','remain1','remain2','remain3'],'terminal_state':'boundary','ascii':'00..7F including NUL and controls','scalar_range':'U+0000..U+10FFFF excluding surrogates','backends':list(BACKENDS),'target_candidate':'valid original-PHP permutations widths2..9,start21,4 orientations,10 backends; not executed'},'source_hashes':source_hashes,'build':{'r256_command':normalize(rcmd,temp),'r256_binary_sha_machine_evidence':sha(rlib),'cascade':normalize(existing,temp)},'runtime':{'python':platform.python_version(),'compiler':subprocess.check_output(['clang','--version'],text=True).splitlines()[0]},'assertions':{'all_passed':True,'rfc3629_builtin_oracle_agreement':True,'all_unicode_scalars_accept':True,'indexed_geometry_matches_full_two_inverses':True,'all80_crypto_plants_retain_exact_suffix':True,'alternate_iv_suffix_and_reencrypt_exact':True,'all10_malformed_plants_first_witness_recorded':True,'terminal_failure_recorded_separately':True,'streaming_benchmark_exact20000orders':True,'source_header_shim_license_hashes_checked_before_build':True,'no_target_read_or_evaluation':True},'limits':['Synthetic only; no Rev7 or target driver.','UTF-8 validity is a necessary byte condition, not English scoring.','Known suffix does not recover IV-dependent prefix.','Original-PHP valid permutations only are a future proposal; lossy repeated keys remain separate.']}
  output.write_text(json.dumps(result,sort_keys=True,separators=(',',':'))+'\n')
def verify():
 paths,_=verify_sources();d=json.loads(LEDGER.read_text());assert d['identity']=='ASTRA' and d['target_evaluated'] is False and d['rev7_read'] is False and d['source_hashes']['core.py']==sha(CORE) and d['source_hashes']['controls.py']==sha(Path(__file__))
 for label,path in paths.items():assert d['source_hashes'][label]==sha(path)
 assert d['short_exhaustive']['strings']==65792 and d['all_unicode_scalars']['scalar_count']==1112064 and d['geometry']['cases']==48 and d['plants']['cases']==80 and d['plants']['contexts']==800 and len(d['malformed_negative_plants'])==10 and d['terminal_failure_control']['outcome']['rejection_witnesses']['zero_oracle']['kind']=='terminal_rejection' and d['benchmark']['scan']['totals']['orders']==20000 and d['benchmark']['scan']['totals']['contexts']==200000 and d['benchmark']['prospective_orders']==1636448 and d['benchmark']['prospective_contexts']==16364480 and all(d['assertions'].values())
 for row in d['plants']['rows']:
  suffix=bytes.fromhex(row['suffix_hex']);assert hashlib.sha256(suffix).hexdigest()==row['suffix_sha256'];kept={x['backend']:x for x in row['outcome']['retained']};assert kept[row['backend']]['suffix_hex']==row['suffix_hex']
 for row in d['malformed_negative_plants']:assert row['witness']['kind']=='byte_rejection' and row['witness']['plaintext_offset']==row['malformed_offset']
 print(json.dumps({'identity':'ASTRA','verified':True,'read_only':True,'ledger_sha256':sha(LEDGER),'ledger_bytes':LEDGER.stat().st_size,'short_strings':65792,'unicode_scalars':1112064,'plant_cases':80,'benchmark_orders':20000,'target_evaluated':False},indent=2))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args()
 if a.regenerate is None:verify();return
 out=a.regenerate.resolve()
 if out.exists():raise SystemExit('refusing existing output: '+str(out))
 out.parent.mkdir(parents=True,exist_ok=True);produce(out);print(json.dumps({'identity':'ASTRA','output':str(out),'sha256':sha(out),'bytes':out.stat().st_size,'target_evaluated':False},indent=2))
if __name__=='__main__':main()

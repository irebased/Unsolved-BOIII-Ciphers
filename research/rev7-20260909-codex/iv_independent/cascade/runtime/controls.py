#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,json,platform,sys,tempfile,time
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import runtime
IDENTITY='ASTRA'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def word_reverse(x):
 assert len(x)==8
 return x[3::-1]+x[7:3:-1]
def compat_reference(block,key=b'Zombies'):
 from Crypto.Cipher import Blowfish
 return word_reverse(Blowfish.new(key,Blowfish.MODE_ECB).encrypt(word_reverse(block)))
def independent_cfb(module,key,data,iv,decrypt,**kwargs):
 e=module.new(key,module.MODE_ECB,**kwargs);reg=iv;out=bytearray()
 for value in data:
  transformed=value^e.encrypt(reg)[0];ct=value if decrypt else transformed
  out.append(transformed);reg=reg[1:]+bytes([ct])
 return bytes(out)
def fsa_valid(data):
 state=0;third={0x93,0x94,0x98,0x99,0xa6}
 for v in data:
  if state==0:
   if v in (9,10,13) or 32<=v<=126:continue
   if v==0xe2:state=1;continue
   return False
  if state==1:
   if v==0x80:state=2;continue
   return False
  if v in third:state=0;continue
  return False
 return state==0
def verify_default(path):
 data=json.loads(path.read_text());assert data['identity']==IDENTITY and data['target_evaluated'] is False
 assert data['artifact_hashes']['runtime.py']==sha(HERE/'runtime.py')
 assert data['artifact_hashes']['controls.py']==sha(Path(__file__))
 runtime.verify_sources();assert data['source']['files']==runtime.SOURCE_HASHES
 base=HERE.parents[2]
 expected_prior={'sources/rev9_source/controls.json':'8c21ea6e275cf5989616ea9d77a19d910e55431626a83339641421ca59947f10','hex_cfb/native_siblings/controls.json':'731f874d9bf66ec55160b10a0663627609cd2b4c55930f870b314c503cc20043'}
 expected_proofs={'iv_independent/cascade/proof.py':'1152ff62572b5914c1840ddd4af14efdc1ff26c58051a566c62bfb2ed1a1f8c0','iv_independent/cascade/controls.json':'2b0b75c096da6e3333dfe3d7390cb1d8a458d551d895ab215401c32155408b87','iv_independent/cascade/interval_extension.py':'b704413c6fddd24128fe1d2185de2aff780a6d8b7c5924f9dfebb35fcf561dae','iv_independent/cascade/interval_extension.json':'43b7f352f14cc87b1c0452338334f9dbde3db74abdfd16dab2ff726adb269037'}
 assert data['source']['prior_evidence_hashes']==expected_prior and data['accepted_cascade_proof_hashes']==expected_proofs
 for rel,want in expected_prior.items():assert sha(base/rel)==want
 for rel,want in expected_proofs.items():assert sha(base/rel)==want
 ids=['aes128','des','blowfish','bfcompat','rc2','twofish','loki97'];assert [x['cipher'] for x in data['full_byte_cfb8']]==ids and [x['cipher'] for x in data['known_interval_controls']]==ids
 expected_keys={'aes128':'Zombies + 9 NUL (16 bytes)','des':'Zombies + NUL (8 bytes)','blowfish':'raw 7-byte Zombies','bfcompat':'raw 7-byte Zombies','rc2':'raw 7-byte Zombies, effective_keylen=1024','twofish':'Zombies + 25 NUL backing; declared/consumed 16','loki97':'Zombies + 25 NUL backing; declared 16, pinned source reads all 32 backing bytes'};assert data['key_conventions']==expected_keys
 blocks={x['cipher']:x['block_size'] for x in data['full_byte_cfb8']}
 for row in data['known_interval_controls']:
  b=blocks[row['cipher']];ranges=[(0,256),(17,230),(31,31+b-1),(31,31+b),(31,32+b)];assert [tuple(x['input_interval']) for x in row['cases']]==ranges
  for case,(left,right) in zip(row['cases'],ranges):assert case['block_size']==b and case['output_offset']==min(left+b,right) and len(bytes.fromhex(case['plaintext_hex']))==max(0,right-left-b)
 chain=data['cascade_control'];assert chain['decryption_order']==ids and len(set(ids))==7 and chain['all_seven_backends_once'] and chain['two_iv_suites_interval_equal']
 assert chain['sum_block_sizes']==sum(blocks.values())==80 and len(chain['rows'])==2
 for row in chain['rows']:
  assert [x['cipher'] for x in row['steps']]==ids and [x['offset'] for x in row['steps']]==[16,24,32,40,48,64,80]
 assert data['assertions']['all_passed'] and len(data['full_byte_cfb8'])==7 and len(data['known_interval_controls'])==7
 print(json.dumps({'identity':IDENTITY,'verified':True,'verification_scope':'source and structural integrity only; no cryptographic replay','ledger_sha256':sha(path),'target_evaluated':False},sort_keys=True))
def regenerate(out):
 if out.exists():raise SystemExit(f'refusing to overwrite {out}')
 from Crypto.Cipher import AES,DES,Blowfish,ARC2
 with tempfile.TemporaryDirectory(prefix='astra-cascade-runtime-') as td:
  builds=runtime.build_source_libraries(Path(td)); back=runtime.registry(builds)
  # Source embedded known-answer tests.
  kats=[]
  tfkey=bytes.fromhex('9f589f5cf6122c32b6bfec2f2ae8c35a'); tf=runtime.SourceBackend('twofish',builds['twofish']['path'],tfkey)
  pt=bytes.fromhex('d491db16e7b1c39e86cb086b789f5419');got=tf.encrypt_block(pt);assert got.hex()=='019f9809de1711858faac3a3ba20fbc3'
  kats.append({'cipher':'twofish','key_hex':tfkey.hex(),'plaintext_hex':pt.hex(),'ciphertext_hex':got.hex(),'matches_source_embedded_kat':True})
  lkkey=bytes((j*2+10)%256 for j in range(32));lk=runtime.SourceBackend('loki97',builds['loki97']['path'],lkkey)
  pt=bytes(range(16));got=lk.encrypt_block(pt);assert got.hex()=='8cb28c958024bae27a94c698f96f12a9'
  kats.append({'cipher':'loki97','key_hex':lkkey.hex(),'plaintext_hex':pt.hex(),'ciphertext_hex':got.hex(),'matches_source_embedded_kat':True})
  # Exact C BF-compat relation across a complete byte-pattern suite.
  compat_rows=[]
  for i in range(32):
   block=bytes(((i*19+j*37)&255) for j in range(8));a=back['bfcompat'].encrypt_block(block);b=compat_reference(block);assert a==b
   compat_rows.append({'block_hex':block.hex(),'ciphertext_hex':a.hex()})
  allbytes=bytes(range(256)); ivs={n:bytes(((17*i+len(n))&255) for i in range(x.block_size)) for n,x in back.items()}
  module_cfg={'aes128':(AES,runtime.KEY+b'\0'*9,{}),'des':(DES,runtime.KEY+b'\0',{}),'blowfish':(Blowfish,runtime.KEY,{}),'rc2':(ARC2,runtime.KEY,{'effective_keylen':1024})}
  old_tf=HERE.parents[2]/'sources/rev9_source/controls.json';old_sib=HERE.parents[2]/'hex_cfb/native_siblings/controls.json'
  prior={'twofish':json.loads(old_tf.read_text()),'siblings':json.loads(old_sib.read_text())}
  prior_hashes={'sources/rev9_source/controls.json':sha(old_tf),'hex_cfb/native_siblings/controls.json':sha(old_sib)}
  expected_prior={
   'sources/rev9_source/controls.json':'8c21ea6e275cf5989616ea9d77a19d910e55431626a83339641421ca59947f10',
   'hex_cfb/native_siblings/controls.json':'731f874d9bf66ec55160b10a0663627609cd2b4c55930f870b314c503cc20043'}
  assert prior_hashes==expected_prior
  full=[]
  for name,obj in back.items():
   iv=ivs[name];ct=obj.encrypt_cfb8(allbytes,iv);assert obj.decrypt_cfb8(ct,iv)==allbytes
   evidence='manual ECB-window recurrence roundtrip'
   if name in module_cfg:
    mod,key,kw=module_cfg[name];lib=mod.new(key,mod.MODE_CFB,iv=iv,segment_size=8,**kw).encrypt(allbytes)
    ref=independent_cfb(mod,key,allbytes,iv,False,**kw);assert ct==lib==ref;evidence='PyCryptodome MODE_CFB and separate ECB-window recurrence'
   elif name=='bfcompat':
    reg=iv;o=bytearray()
    for v in allbytes:
     z=v^compat_reference(reg)[0];o.append(z);reg=reg[1:]+bytes([z])
    assert ct==bytes(o);evidence='actual pinned C and independent standard-Blowfish word conjugation recurrence'
   elif name=='twofish':
    row=prior['twofish']['full_byte_twofish_cfb8'];assert bytes.fromhex(row['ciphertext_hex'])[:256]==obj.encrypt_cfb8(allbytes,b'0'*16)
    evidence='pinned C recurrence and exact prefix of frozen solved-source control'
   elif name=='loki97':
    row=next(x for x in prior['siblings']['full_byte_cfb8'] if x['cipher']=='loki97');assert bytes.fromhex(row['ciphertext_hex'])[:256]==obj.encrypt_cfb8(allbytes,b'0'*16)
    evidence='pinned C recurrence and exact prefix of frozen solved-source control'
   full.append({'cipher':name,'block_size':obj.block_size,'iv_hex':iv.hex(),'plaintext_hex':allbytes.hex(),'ciphertext_hex':ct.hex(),'ciphertext_sha256':hashlib.sha256(ct).hexdigest(),'decrypt_roundtrip':True,'independent_evidence':evidence})
  intervals=[]
  for name,obj in back.items():
   iv=ivs[name];ct=obj.encrypt_cfb8(allbytes,iv);cases=[]
   for L,R in ((0,len(ct)),(17,230),(31,31+obj.block_size-1),(31,31+obj.block_size),(31,32+obj.block_size)):
    z=obj.interval_decrypt(ct[L:R],L);want=allbytes[min(L+obj.block_size,R):R];assert z['offset']==min(L+obj.block_size,R) and z['plaintext']==want
    cases.append({'input_interval':[L,R],'output_offset':z['offset'],'block_size':z['block_size'],'plaintext_hex':z['plaintext'].hex(),'matches_full_decryption_slice':True})
   intervals.append({'cipher':name,'cases':cases})
  # A chain whose decryption path visits each backend exactly once.
  order=['aes128','des','blowfish','bfcompat','rc2','twofish','loki97'];plain=(b'Cascade runtime ASCII\tUTF8 en\xe2\x80\x93 em\xe2\x80\x94 ellipsis\xe2\x80\xa6.\n'*8)[:500];assert fsa_valid(plain)
  chain=[]
  recovered=[]
  for suite in (1,2):
   suite_ivs={n:bytes(((suite*29+i*11+len(n))&255) for i in range(back[n].block_size)) for n in order}
   value=plain
   for n in reversed(order):value=back[n].encrypt_cfb8(value,suite_ivs[n])
   known=value;off=0;steps=[]
   for n in order:
    z=back[n].interval_decrypt(known,off);known=z['plaintext'];off=z['offset'];steps.append({'cipher':n,'offset':off,'known_bytes':len(known),'sha256':hashlib.sha256(known).hexdigest()})
   assert known==plain[sum(back[n].block_size for n in order):] and off==sum(back[n].block_size for n in order)
   recovered.append(known);chain.append({'iv_suite':suite,'outer_ciphertext_sha256':hashlib.sha256(value).hexdigest(),'steps':steps,'final_offset':off,'final_known_hex':known.hex()})
  assert recovered[0]==recovered[1]
  # Representative cost measurement, not a search or target projection guarantee.
  samples=24;known=bytes((i*73+19)&255 for i in range(500));bench=[]
  for name,obj in back.items():
   t=time.perf_counter();digest=hashlib.sha256()
   for j in range(samples):
    z=obj.interval_decrypt(bytes((x+j)&255 for x in known),j);digest.update(z['plaintext'])
   elapsed=time.perf_counter()-t;bench.append({'cipher':name,'samples':samples,'input_bytes_each':500,'seconds':elapsed,'edges_per_second':samples/elapsed,'linear_seconds_for_22764_edges':elapsed*22764/samples,'digest':digest.hexdigest()})
  result={'identity':IDENTITY,'target_evaluated':False,'rev7_file_read':False,'scope':'Synthetic-only seven-backend block/CFB8/known-interval runtime controls; no search or target driver.',
   'key_conventions':{'aes128':'Zombies + 9 NUL (16 bytes)','des':'Zombies + NUL (8 bytes)','blowfish':'raw 7-byte Zombies','bfcompat':'raw 7-byte Zombies','rc2':'raw 7-byte Zombies, effective_keylen=1024','twofish':'Zombies + 25 NUL backing; declared/consumed 16','loki97':'Zombies + 25 NUL backing; declared 16, pinned source reads all 32 backing bytes'},
   'source':{'repository':'https://github.com/Distrotech/libmcrypt','commit':runtime.SOURCE_COMMIT,'license':'GNU Lesser General Public License v2.1 or later as distributed in each source subdirectory COPYING.LIB','files':runtime.SOURCE_HASHES,'temporary_builds':builds,'prior_evidence_hashes':prior_hashes},
   'accepted_cascade_proof_hashes':{'iv_independent/cascade/proof.py':'1152ff62572b5914c1840ddd4af14efdc1ff26c58051a566c62bfb2ed1a1f8c0','iv_independent/cascade/controls.json':'2b0b75c096da6e3333dfe3d7390cb1d8a458d551d895ab215401c32155408b87','iv_independent/cascade/interval_extension.py':'b704413c6fddd24128fe1d2185de2aff780a6d8b7c5924f9dfebb35fcf561dae','iv_independent/cascade/interval_extension.json':'43b7f352f14cc87b1c0452338334f9dbde3db74abdfd16dab2ff726adb269037'},
   'source_kats':kats,'bfcompat_conjugation_rows':compat_rows,'full_byte_cfb8':full,'known_interval_controls':intervals,
   'cascade_control':{'decryption_order':order,'plaintext_sha256':hashlib.sha256(plain).hexdigest(),'plaintext_bytes':len(plain),'sum_block_sizes':sum(back[n].block_size for n in order),'all_seven_backends_once':True,'two_iv_suites_interval_equal':True,'rows':chain},
   'benchmark':{'method':'24 synthetic 500-byte interval decryptions per backend; projected time is linear scaling only, excludes graph/solver overhead','prospective_edge_count':22764,'rows':bench},
   'environment':{'python':sys.version,'platform':platform.platform(),'compiler':builds['compiler']},
   'artifact_hashes':{'runtime.py':sha(HERE/'runtime.py'),'controls.py':sha(Path(__file__))},
   'assertions':{'all_passed':True,'sources_hash_pinned':True,'source_kats':True,'standard_four_mode_cfb_matches_pycryptodome':True,'bfcompat_c_matches_independent_conjugation':True,'twofish_loki_match_frozen_source_controls':True,'all_256_byte_roundtrips':True,'known_interval_offsets_and_bytes':True,'cascade_all_backends_two_iv_suites':True}}
  out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
  print(json.dumps({'identity':IDENTITY,'written':str(out),'sha256':sha(out),'benchmark':bench},indent=2))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);ap.add_argument('--ledger',type=Path,default=HERE/'controls.json');a=ap.parse_args()
 if a.regenerate:regenerate(a.regenerate)
 else:verify_default(a.ledger)
if __name__=='__main__':main()

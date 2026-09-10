#!/usr/bin/env python3
"""Inert gated four-orientation Rijndael-256 global hex-bijection target driver."""
from pathlib import Path
import argparse,hashlib,json,math,os,subprocess
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;ROOT=HERE.parents[4];IDENTITY='ASTRA';ORIENTATIONS=('forward','full_hex_reverse','byte_reverse','nibble_swap');CAP=1_000_000_000;KEY=b'Zombies'+b'\0'*9;IV=b'0'*32
BIN=HERE/'native_r256';BUILD=HERE/'native_build.json';GATE=HERE/'target_gate.json';RESULT=HERE/'target_results.json';MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json';JS=ROOT/'research/rev7-20260909-codex/rijndael256_cfb/js_cfb8.js'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c';BIN_SHA='24b323b9eac28b438bac3760baad4683704884e12288407719390daed2db923c';BUILD_SHA='71f0a7746e11db988cfe83dd5aa543d3daad5b568faacafdf300ee92db82212c';PARENT_CONTROLS_SOURCE_SHA='eef73fc1b4abec92fc86158054bc22dc6b428328f4028eda7f894508df28b17f';PARENT_CONTROLS_SHA='097fe51f0ade0b430684cd7555d5d3dcfdc76b4dbac27177fac967473f882b56';NATIVE_SOURCE_SHA='da036a3e55a1f771bc31bb4795be85e1acc2ed58b6f744085e6c01525b3abf2a'
REQUIRED=('research/rev7-20260909-codex/hex_cfb/native_text5/native_text5.cpp','research/rev7-20260909-codex/hex_cfb/native_text5/endpoint5.py','research/rev7-20260909-codex/hex_cfb/prototype.py','research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/native.cpp','research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/PARENT_DIFF.patch','research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/controls.py','research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/controls.json','research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/README.md','research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/target/build_native.py','research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/target/native_build.json','research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/target/driver_controls.py','research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/target/controls.json','research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/target/README.md','research/rev7-20260909-codex/hex_cfb/native_text5_rijndael256_controls/target/prepare_gate.py','research/rev7-20260909-codex/rijndael256_controls/build_source.py','research/rev7-20260909-codex/rijndael256_controls/controls.json','research/rev7-20260909-codex/rijndael256_controls/controls.py','research/rev7-20260909-codex/rijndael256_controls/js_blocks.js','research/rev7-20260909-codex/rijndael256_controls/source/COPYING.LIB','research/rev7-20260909-codex/rijndael256_controls/source/aes.js','research/rev7-20260909-codex/rijndael256_controls/source/rijndael-256.c','research/rev7-20260909-codex/rijndael256_controls/source/rijndael.h','research/rev7-20260909-codex/rijndael256_controls/source/libdefs.h','research/rev7-20260909-codex/rijndael256_controls/source/mcrypt_modules.h','research/rev7-20260909-codex/rijndael256_cfb/runtime.py','research/rev7-20260909-codex/rijndael256_cfb/js_cfb8.js','lavender/src/data/ciphers/revelations.json')
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def orient(text,name):
 if name=='forward':return text
 if name=='full_hex_reverse':return text[::-1]
 pairs=[text[i:i+2] for i in range(0,len(text),2)]
 if name=='byte_reverse':return ''.join(reversed(pairs))
 if name=='nibble_swap':return ''.join(x[::-1] for x in pairs)
 raise ValueError(name)
def endpoint(data):
 state=0
 for b in data:
  if state==0:state=0 if b in (9,10,13) or 32<=b<=126 else 1 if b==0xe2 else -1
  elif state==1:state=2 if b==0x80 else -1
  elif state==2:state=0 if b in (0x93,0x94,0x98,0x99,0xa6) else -1
  if state<0:return False
 return state==0
def decode(display,mapping):
 vals={c:mapping[i] for i,c in enumerate('0123456789ABCDEF')};return bytes((vals[display[i]]<<4)|vals[display[i+1]] for i in range(0,len(display),2))
def js_jobs(jobs):return json.loads(subprocess.run(['node',str(JS)],input=json.dumps({'jobs':jobs}).encode(),capture_output=True,check=True).stdout)
def native(display,cap=CAP,seed=None):
 cmd=[str(BIN),str(cap),display,'-' if seed is None else ','.join(f'{k}:{v}' for k,v in sorted(seed.items()))];return json.loads(subprocess.check_output(cmd,text=True))
def validate(row,display):
 assert row['identity']==IDENTITY and row['cipher']=='rijndael256_key16' and row['node_limit']>0 and row['expected_completion_weight']==math.factorial(16-len(row.get('seed_mapping',{}))) and row['certificate_weight']==row['rejected_completion_weight']+row['terminal_completion_weight'] and row['complete']==len(row['solutions'])
 if not row['aborted_at_node_limit']:assert row['certificate_weight']==row['expected_completion_weight']
 decrypt=[];encrypt=[];material=bytearray()
 for sol in row['solutions']:
  m=sol['mapping'];assert sorted(m)==list(range(16));ct=decode(display,m);pt=bytes.fromhex(sol['plaintext_hex']);assert len(ct)==len(pt) and endpoint(pt);decrypt.append({'key_hex':KEY.hex(),'iv_hex':IV.hex(),'data_hex':ct.hex(),'operation':'decrypt'});encrypt.append({'key_hex':KEY.hex(),'iv_hex':IV.hex(),'data_hex':pt.hex(),'operation':'encrypt'});material.extend(bytes(m));material.extend(ct);material.extend(pt)
 if decrypt:
  dr=js_jobs(decrypt);er=js_jobs(encrypt)
  for sol,d,e,dc,ec in zip(row['solutions'],dr,er,decrypt,encrypt):assert d['plaintext_hex']==sol['plaintext_hex'] and e['ciphertext_hex']==dc['data_hex']
 return {'all_mapping_permutations':True,'all_display_reconstructions_exact':True,'all_endpoint_terminal0':True,'all_independent_js_decryptions_exact':True,'all_independent_js_reencryptions_exact':True,'solution_material_sha256':hb(bytes(material))}
def execute_cell(canonical,orientation,cap=CAP,seed=None):
 display=orient(canonical,orientation);assert orient(display,orientation)==canonical;row=native(display,cap,seed);row['seed_mapping']={} if seed is None else {str(k):v for k,v in sorted(seed.items())};v=validate(row,display);return {'id':orientation,'orientation':orientation,'display_sha256':hb(display.encode()),'display_length':len(display),'inverse_orientation_exact':True,'validation':v,**row}
def scope():return {'identity':IDENTITY,'contexts':4,'orientations':list(ORIENTATIONS),'cipher':'Rijndael-256 block32','key_hex':KEY.hex(),'iv_hex':IV.hex(),'mapping':'global bijection of 16 displayed hex symbols to nibble values','endpoint':'TAB/LF/CR, ASCII32..126, UTF-8 E280 93/94/98/99/A6; terminal state0','node_limit_per_cell':CAP,'cap_semantics':'fresh root per cell; capped results are INCOMPLETE and certificate weights are lower bounds','retention':'every terminal mapping and full plaintext'}
def extract_target():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA;t=MDX.read_text();a=t.index('`83 B57B2')+1;b=t.index('`',a);s=''.join(t[a:b].split()).upper();d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper();assert s==d and len(s)==1092 and hb(s.encode())==TEXT_SHA;return s
def require_gate():
 g=json.loads(GATE.read_text());assert g['identity']==IDENTITY and g['target_evaluated'] is False and g['scope']==scope() and g['driver_sha256']==sha(Path(__file__)) and g['native_binary_sha256']==sha(BIN)==BIN_SHA and g['native_build_sha256']==sha(BUILD)==BUILD_SHA and g['mdx_sha256']==MDX_SHA and g['dataset_sha256']==DATA_SHA and g['canonical_text_sha256']==TEXT_SHA and set(g['artifact_hashes'])==set(REQUIRED)
 for rel,want in g['artifact_hashes'].items():assert sha(ROOT/rel)==want,(rel,sha(ROOT/rel),want)
 return g
def checkpoint_path(o):return HERE/f'cell_{o}.json'
def run_target():
 tmp=RESULT.with_suffix('.json.tmp')
 if RESULT.exists() or tmp.exists():raise SystemExit('refusing existing final or temporary result')
 g=require_gate();canonical=extract_target();cells=[]
 for o in ORIENTATIONS:
  cp=checkpoint_path(o)
  if cp.exists():
   row=json.loads(cp.read_text());assert row['configuration']=={'gate_sha256':sha(GATE),'driver_sha256':sha(Path(__file__)),'native_binary_sha256':BIN_SHA} and row['cell']['id']==o
  else:
   row={'identity':IDENTITY,'target_evaluated':True,'configuration':{'gate_sha256':sha(GATE),'driver_sha256':sha(Path(__file__)),'native_binary_sha256':BIN_SHA},'cell':execute_cell(canonical,o)};ct=cp.with_suffix('.json.tmp');ct.write_text(json.dumps(row,indent=2,sort_keys=True)+'\n');os.replace(ct,cp)
  cells.append(row['cell'])
 out={'identity':IDENTITY,'target_evaluated':True,'scope':scope(),'configuration':{'gate_sha256':sha(GATE),'driver_sha256':sha(Path(__file__)),'native_binary_sha256':BIN_SHA,'native_build_sha256':BUILD_SHA,'artifact_hashes':g['artifact_hashes'],'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_text_sha256':TEXT_SHA},'cells':cells,'summary':{'contexts':4,'complete_cells':sum(not x['aborted_at_node_limit'] for x in cells),'capped_cells':sum(x['aborted_at_node_limit'] for x in cells),'terminal_solutions':sum(len(x['solutions']) for x in cells),'nodes':sum(x['nodes'] for x in cells),'rejected_completion_weight':sum(x['rejected_completion_weight'] for x in cells)}};tmp.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');os.replace(tmp,RESULT);print(json.dumps({'identity':IDENTITY,'result_sha256':sha(RESULT),**out['summary']},sort_keys=True))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--run-target',action='store_true');a=ap.parse_args();assert sha(BIN)==BIN_SHA and sha(BUILD)==BUILD_SHA and sha(PACKAGE/'native.cpp')==NATIVE_SOURCE_SHA and sha(PACKAGE/'controls.py')==PARENT_CONTROLS_SOURCE_SHA and sha(PACKAGE/'controls.json')==PARENT_CONTROLS_SHA
 if a.run_target:run_target()
 else:
  if GATE.exists():require_gate()
  assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
  print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'handling':'MDX and dataset bytes hashed only; ciphertext not extracted or evaluated','gate_present':GATE.exists(),'driver_sha256':sha(Path(__file__)),'scope':scope()},indent=2,sort_keys=True))
if __name__=='__main__':main()

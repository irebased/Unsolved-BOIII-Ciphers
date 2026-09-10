#!/usr/bin/env python3
"""Read-only integrity/accounting verifier for the saved four-cell target result; no DFS replay."""
from pathlib import Path
import hashlib,json,math,subprocess
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4];IDENTITY='ASTRA';RESULT=HERE/'target_results.json';GATE=HERE/'target_gate.json';BIN=HERE/'native_r256';BUILD=HERE/'native_build.json';JS=ROOT/'research/rev7-20260909-codex/rijndael256_cfb/js_cfb8.js';MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
RESULT_SHA='85dc54daab3f08440820e1d22c10abb771320aea0e81f6706f3d9a03adc756cc';GATE_SHA='902e5db5430987f3e30a6b0b03f588b7ede226caeaaba0c620ffdbed6d749bb7';DRIVER_SHA='27fe449a575826c871ae619a39e74f4394c5de6e349b4f0a756d6d5ff5a63277';BIN_SHA='24b323b9eac28b438bac3760baad4683704884e12288407719390daed2db923c';BUILD_SHA='71f0a7746e11db988cfe83dd5aa543d3daad5b568faacafdf300ee92db82212c';MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c';KEY=b'Zombies'+b'\0'*9;IV=b'0'*32;ORIENTATIONS=('forward','full_hex_reverse','byte_reverse','nibble_swap');CAP=1_000_000_000
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
  else:state=0 if b in (0x93,0x94,0x98,0x99,0xa6) else -1
  if state<0:return False
 return state==0
def decode(display,mapping):
 h='0123456789ABCDEF';m={h[i]:v for i,v in enumerate(mapping)};return bytes((m[display[i]]<<4)|m[display[i+1]] for i in range(0,len(display),2))
def js(jobs):return json.loads(subprocess.run(['node',str(JS)],input=json.dumps({'jobs':jobs}).encode(),capture_output=True,check=True).stdout)
def canonical():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA;t=MDX.read_text();a=t.index('`83 B57B2')+1;b=t.index('`',a);s=''.join(t[a:b].split()).upper();d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper();assert s==d and len(s)==1092 and hb(s.encode())==TEXT_SHA;return s
def main():
 assert sha(RESULT)==RESULT_SHA and sha(GATE)==GATE_SHA and sha(HERE/'run_target.py')==DRIVER_SHA and sha(BIN)==BIN_SHA and sha(BUILD)==BUILD_SHA
 result=json.loads(RESULT.read_text());gate=json.loads(GATE.read_text());build=json.loads(BUILD.read_text());assert result['identity']==gate['identity']==build['identity']==IDENTITY and result['target_evaluated'] is True and gate['target_evaluated'] is False and build['binary_sha256']==BIN_SHA and build['source_pins']['native.cpp']=='da036a3e55a1f771bc31bb4795be85e1acc2ed58b6f744085e6c01525b3abf2a'
 assert result['configuration']['gate_sha256']==GATE_SHA and result['configuration']['driver_sha256']==DRIVER_SHA and result['configuration']['native_binary_sha256']==BIN_SHA and result['configuration']['native_build_sha256']==BUILD_SHA and result['configuration']['artifact_hashes']==gate['artifact_hashes']
 for rel,want in gate['artifact_hashes'].items():assert sha(ROOT/rel)==want,(rel,sha(ROOT/rel),want)
 assert result['scope']==gate['scope'] and result['scope']['contexts']==4 and result['scope']['orientations']==list(ORIENTATIONS) and result['scope']['node_limit_per_cell']==CAP and result['scope']['key_hex']==KEY.hex() and result['scope']['iv_hex']==IV.hex()
 source=canonical();decrypt=[];encrypt=[];terminal=0
 assert [c['id'] for c in result['cells']]==list(ORIENTATIONS)
 for c in result['cells']:
  o=c['id'];display=orient(source,o);assert orient(display,o)==source and c['orientation']==o and c['display_sha256']==hb(display.encode()) and c['display_length']==1092 and c['inverse_orientation_exact']
  assert c['identity']==IDENTITY and c['cipher']=='rijndael256_key16' and c['node_limit']==CAP and c['expected_completion_weight']==math.factorial(16) and c['certificate_weight']==c['rejected_completion_weight']+c['terminal_completion_weight']==math.factorial(16) and not c['aborted_at_node_limit'] and c['nodes']<CAP and c['complete']==len(c['solutions']) and c['terminal_completion_weight']==c['complete']
  assert all(c['validation'][k] for k in ('all_mapping_permutations','all_display_reconstructions_exact','all_endpoint_terminal0','all_independent_js_decryptions_exact','all_independent_js_reencryptions_exact'))
  material=bytearray()
  for sol in c['solutions']:
   m=sol['mapping'];assert sorted(m)==list(range(16));ct=decode(display,m);pt=bytes.fromhex(sol['plaintext_hex']);assert endpoint(pt) and len(pt)==546;material.extend(bytes(m));material.extend(ct);material.extend(pt);decrypt.append({'key_hex':KEY.hex(),'iv_hex':IV.hex(),'data_hex':ct.hex(),'operation':'decrypt'});encrypt.append({'key_hex':KEY.hex(),'iv_hex':IV.hex(),'data_hex':pt.hex(),'operation':'encrypt'});terminal+=1
  assert hb(bytes(material))==c['validation']['solution_material_sha256']
  cp=HERE/f'cell_{o}.json';saved=json.loads(cp.read_text());assert saved['identity']==IDENTITY and saved['target_evaluated'] is True and saved['configuration']=={'gate_sha256':GATE_SHA,'driver_sha256':DRIVER_SHA,'native_binary_sha256':BIN_SHA} and saved['cell']==c
 if decrypt:
  dr=js(decrypt);er=js(encrypt)
  for d,e,dj,ej in zip(decrypt,encrypt,dr,er):assert dj['plaintext_hex']==e['data_hex'] and ej['ciphertext_hex']==d['data_hex']
 assert terminal==0 and result['summary']=={'contexts':4,'complete_cells':4,'capped_cells':0,'terminal_solutions':0,'nodes':sum(c['nodes'] for c in result['cells']),'rejected_completion_weight':sum(c['rejected_completion_weight'] for c in result['cells'])}
 print(json.dumps({'identity':IDENTITY,'verified':True,'verification_kind':'saved-artifact integrity, scope, orientation, factorial-accounting, checkpoint, and retained-survivor replay; the 752,784,570-node DFS is not rerun','result_sha256':RESULT_SHA,'gate_sha256':GATE_SHA,'contexts':4,'complete_cells':4,'capped_cells':0,'terminal_solutions':0,'nodes':result['summary']['nodes']},sort_keys=True))
if __name__=='__main__':main()

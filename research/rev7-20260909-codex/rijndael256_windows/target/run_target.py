#!/usr/bin/env python3
"""Inert gated Rijndael-256 ECB/CBC known-window target driver."""
from __future__ import annotations
from pathlib import Path
import argparse,hashlib,importlib.util,json,os,re,subprocess,sys,tempfile
HERE=Path(__file__).resolve().parent;WINDOWS=HERE.parent;PRIM=WINDOWS.parent/'rijndael256_controls';ROOT=HERE.parents[3]
IDENTITY='ASTRA';GATE=HERE/'target_gate.json';MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
KEY_SIZES=(16,24,32);ORIENTATIONS=('forward','full_hex_reverse','byte_reverse','nibble_swap');MODES=('ecb','cbc')
REQUIRED_ARTIFACTS=(
 'research/rev7-20260909-codex/rijndael256_windows/engine.py','research/rev7-20260909-codex/rijndael256_windows/controls.py',
 'research/rev7-20260909-codex/rijndael256_windows/controls.json','research/rev7-20260909-codex/rijndael256_windows/README.md',
 'research/rev7-20260909-codex/rijndael256_controls/controls.py','research/rev7-20260909-codex/rijndael256_controls/controls.json',
 'research/rev7-20260909-codex/rijndael256_controls/README.md','research/rev7-20260909-codex/rijndael256_controls/build_source.py',
 'research/rev7-20260909-codex/rijndael256_controls/js_blocks.js','research/rev7-20260909-codex/rijndael256_controls/provenance.json',
 'research/rev7-20260909-codex/rijndael256_controls/source/rijndael-256.c','research/rev7-20260909-codex/rijndael256_controls/source/rijndael.h',
 'research/rev7-20260909-codex/rijndael256_controls/source/COPYING.LIB','research/rev7-20260909-codex/rijndael256_controls/source/aes.js',
 'research/rev7-20260909-codex/rijndael256_controls/source/libdefs.h','research/rev7-20260909-codex/rijndael256_controls/source/mcrypt_modules.h',
 'research/rev7-20260909-codex/rijndael256_windows/target/README.md','research/rev7-20260909-codex/rijndael256_windows/target/prepare_gate.py',
 'research/rev7-20260909-codex/rijndael256_windows/target/controls.py','research/rev7-20260909-codex/rijndael256_windows/target/controls.json')
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
engine=load(WINDOWS/'engine.py','rijndael_window_engine')
def keys():return {n:b'Zombies'+b'\0'*(n-7) for n in KEY_SIZES}
def orient(data,name):
 if name=='forward':return data
 if name=='byte_reverse':return data[::-1]
 if name=='nibble_swap':return bytes(((x&15)<<4)|(x>>4) for x in data)
 if name=='full_hex_reverse':return bytes.fromhex(data.hex()[::-1])
 raise ValueError(name)
def independent_cut_regex(data):
 token=re.compile(rb'(?:[\x09\x0a\x0d\x20-\x7e]|\xe2\x80[\x93\x94\x98\x99\xa6])*\Z')
 return any(token.fullmatch(a+data+b) is not None for a in (b'',b'\xe2',b'\xe2\x80') for b in (b'',b'\x80\x93',b'\x93'))
def cell_id(key_bytes,orientation,mode):return f'k{key_bytes*8}|{orientation}|{mode}'
def expected_ids():return [cell_id(k,o,m) for k in KEY_SIZES for o in ORIENTATIONS for m in MODES]
def scope():
 return {'identity':IDENTITY,'input_bytes':546,'block_bytes':32,'key_construction':{str(n):v.hex() for n,v in keys().items()},
  'orientations':list(ORIENTATIONS),'modes':{'ecb':{'window_bytes':64,'offsets':483,'returned_bytes':64},'cbc':{'window_bytes':96,'offsets':451,'returned_bytes':64,'external_iv':'every IV; returned D(C1)^C0 || D(C2)^C1'}},
  'cells':24,'context_rows':11208,'caps':'none','row_evidence':'every context retains full64 plaintext, two decrypted blocks, input-window SHA256, classification and witness',
  'candidates':'every retained window independently replayed with untouched JavaScript blocks and a separate cut-boundary regex oracle; no trim/unpad/framing fit'}
def require_gate():
 d=json.loads(GATE.read_text());assert d['identity']==IDENTITY and d['target_evaluated'] is False and d['authorization']=='FABLE preregistered; root GO required'
 assert isinstance(d.get('fable_reference'),str) and d['fable_reference'].strip();assert sha(MDX)==MDX_SHA
 assert d['scope']==scope() and d['driver_sha256']==sha(Path(__file__)) and d['mdx_sha256']==MDX_SHA and d['canonical_text_sha256']==TEXT_SHA
 assert set(d['artifact_hashes'])==set(REQUIRED_ARTIFACTS)
 for rel,want in d['artifact_hashes'].items():assert sha(ROOT/rel)==want,rel
 return d,sha(GATE)
def extract():
 text=MDX.read_text();a=text.index('`83 B57B2')+1;b=text.index('`',a);raw=''.join(text[a:b].split()).upper()
 assert len(raw)==1092 and hashlib.sha256(raw.encode()).hexdigest()==TEXT_SHA
 data=bytes.fromhex(raw);assert len(data)==546
 return raw,{o:orient(data,o) for o in ORIENTATIONS}
def js_decrypt_blocks(key,blocks):
 ops=[{'op':'decrypt','key_hex':key.hex(),'data_hex':x.hex()} for x in blocks]
 cp=subprocess.run(['node',str(PRIM/'js_blocks.js')],input=json.dumps({'operations':ops}),text=True,capture_output=True,check=True)
 out=[bytes.fromhex(x) for x in json.loads(cp.stdout)];assert len(out)==len(blocks);return out
def replay_candidates(stream,mode,key,rows):
 jobs=[];refs=[];window=64 if mode=='ecb' else 96
 for row in rows:
  if not row['accepted']:continue
  raw=stream[row['offset']:row['offset']+window];blocks=(raw[:32],raw[32:]) if mode=='ecb' else (raw[32:64],raw[64:96])
  refs.append((row,raw,len(jobs)));jobs.extend(blocks)
 outs=js_decrypt_blocks(key,jobs) if jobs else [];result=[]
 for row,raw,i in refs:
  a,b=outs[i:i+2]
  returned=[a,b] if mode=='ecb' else [bytes(x^y for x,y in zip(a,raw[:32])),bytes(x^y for x,y in zip(b,raw[32:64]))]
  plain=b''.join(returned)
  assert [x.hex() for x in returned]==row['decrypted_blocks_hex'] and plain.hex()==row['plaintext_hex'] and independent_cut_regex(plain)
  result.append({'offset':row['offset'],'javascript_primitive_decrypt_hex':[a.hex(),b.hex()],'javascript_returned_blocks_hex':[x.hex() for x in returned],'javascript_plaintext_exact':True,'independent_regex_oracle':True})
 return result
def execute_cell(stream,key_bytes,orientation,mode,primitive):
 assert len(stream)==546 and key_bytes in KEY_SIZES and orientation in ORIENTATIONS and mode in MODES
 key=keys()[key_bytes];scan=engine.scan(stream,mode,lambda b:primitive.crypt(b,True),collect_all=True);rows=scan.pop('rows')
 assert len(rows)==scan['tested_offsets'] and [x['offset'] for x in rows]==list(range(scan['tested_offsets']))
 assert sum(scan['class_counts'].values())==len(rows) and scan['class_counts']['retained']==len(scan['retained'])
 for row in rows:
  assert len(bytes.fromhex(row['plaintext_hex']))==64 and len(row['decrypted_blocks_hex'])==2 and all(len(bytes.fromhex(x))==32 for x in row['decrypted_blocks_hex'])
  assert ((row['witness'] is None)==row['accepted'])
 candidates=replay_candidates(stream,mode,key,rows)
 assert len(candidates)==scan['class_counts']['retained']
 return {'identity':IDENTITY,'cell_id':cell_id(key_bytes,orientation,mode),'key_bytes':key_bytes,'key_hex':key.hex(),'orientation':orientation,'mode':mode,
  'oriented_input_sha256':hashlib.sha256(stream).hexdigest(),'window_bytes':scan['window_bytes'],'context_rows':len(rows),'class_counts':scan['class_counts'],
  'rows':rows,'retained_candidates':candidates,'all_rows_preserved':True,'all_candidates_independent_js_and_regex_replayed':True}
def atomic(path,value):
 tmp=path.with_name(path.name+'.tmp')
 if tmp.exists():raise RuntimeError('refusing stale temporary '+str(tmp))
 with tmp.open('x') as f:json.dump(value,f,indent=2,sort_keys=True);f.write('\n')
 os.replace(tmp,path)
def run(output,checkpoint):
 if output.exists() or checkpoint.exists():raise SystemExit('refusing existing output/checkpoint; no resume')
 gate,gsha=require_gate();raw,streams=extract();sys.path.insert(0,str(PRIM));pc=load(PRIM/'controls.py','rijndael_primitive');builder=load(PRIM/'build_source.py','rijndael_builder');pc.verify_pins()
 with tempfile.TemporaryDirectory(prefix='rijndael256-window-target-') as td:
  lib=Path(td)/'rijndael256.dylib';cmd=builder.build(lib);objects={n:pc.CPrimitive(lib,k) for n,k in keys().items()}
  result={'identity':IDENTITY,'target_evaluated':True,'status':'running','configuration':{'scope':scope(),'gate_sha256':gsha,'driver_sha256':sha(Path(__file__)),'mdx_sha256':MDX_SHA,'canonical_text_sha256':TEXT_SHA,'canonical_text_length':len(raw),'artifact_hashes':gate['artifact_hashes'],'temporary_build':{'command':cmd[:-1]+['<temporary-output>'],'source_sha256':sha(PRIM/'source/rijndael-256.c')}},'cells':[]}
  for k in KEY_SIZES:
   for o in ORIENTATIONS:
    for m in MODES:
     result['cells'].append(execute_cell(streams[o],k,o,m,objects[k]));atomic(checkpoint,result)
     print(json.dumps({'identity':IDENTITY,'cell':result['cells'][-1]['cell_id'],'cells_complete':len(result['cells']),'contexts_complete':sum(x['context_rows'] for x in result['cells'])}),flush=True)
  ids=[x['cell_id'] for x in result['cells']];assert ids==expected_ids() and len(ids)==len(set(ids))==24
  classes={k:sum(x['class_counts'][k] for x in result['cells']) for k in ('rejected_a105','rejected_fsa_transition','retained')}
  assert sum(x['context_rows'] for x in result['cells'])==11208
  result['status']='complete';result['summary']={'cells':24,'unique_cell_ids':24,'context_rows':11208,'class_counts':classes,'retained_candidates':classes['retained'],'all_rows_preserved':True,'all_candidates_independent_js_and_regex_replayed':True}
  atomic(checkpoint,result);os.replace(checkpoint,output);print(json.dumps({'identity':IDENTITY,'output':str(output),'sha256':sha(output),'summary':result['summary']},indent=2))
def selftest():
 assert sha(MDX)==MDX_SHA
 if GATE.exists():require_gate()
 ids=expected_ids();assert len(ids)==len(set(ids))==24 and sum(483 if x.endswith('|ecb') else 451 for x in ids)==11208
 assert all(orient(orient(bytes(range(256)),o),o)==bytes(range(256)) for o in ORIENTATIONS)
 print(json.dumps({'identity':IDENTITY,'target_evaluated':False,'rev7_handling':'MDX bytes hashed only; ciphertext not extracted, parsed, oriented, decrypted, or evaluated','driver_sha256':sha(Path(__file__)),'mdx_sha256':MDX_SHA,'scope':scope(),'cell_ids':ids,'gate_present':GATE.exists()},indent=2,sort_keys=True))
def main():
 ap=argparse.ArgumentParser();g=ap.add_mutually_exclusive_group(required=True);g.add_argument('--selftest',action='store_true');g.add_argument('--run-target',action='store_true');ap.add_argument('--output',type=Path,default=HERE/'target_results.json');ap.add_argument('--checkpoint',type=Path,default=HERE/'target_checkpoint.json');a=ap.parse_args()
 selftest() if a.selftest else run(a.output,a.checkpoint)
if __name__=='__main__':main()

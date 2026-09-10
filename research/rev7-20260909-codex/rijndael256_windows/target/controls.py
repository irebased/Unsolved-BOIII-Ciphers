#!/usr/bin/env python3
"""Synthetic-only full driver-path controls for Rijndael-256 windows."""
from __future__ import annotations
from pathlib import Path
import argparse,hashlib,importlib.util,json,sys,tempfile
HERE=Path(__file__).resolve().parent;WINDOWS=HERE.parent;PRIM=WINDOWS.parent/'rijndael256_controls';LEDGER=HERE/'controls.json';IDENTITY='ASTRA'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
sys.path.insert(0,str(HERE));import run_target as driver
PINS={'../engine.py':'7d32315f2d874fefe0c758b932a102e4c71f809370ba5a9df182bf8e8a5bf373','../controls.py':'08e9f4f44375f6636c68e74bd4d0e56c364639d4242a599cad705a042ad7a514','../controls.json':'56cfdfc7245b3f28b819858b40e537d787ed4bac664be6677edba30c4cdc480b','../README.md':'141221f4308faf699dd62ac438c5964ed8b2653a448a12163e597b5d57a4a946'}
def verify_pins():
 for rel,want in PINS.items():assert sha(HERE/rel)==want,(rel,sha(HERE/rel),want)
def deterministic(label,n):
 out=b'';i=0
 while len(out)<n:out+=hashlib.sha256(f'{label}:{i}'.encode()).digest();i+=1
 return out[:n]
def strict64():
 x='EN – EM — LEFT ‘ RIGHT ’ ELLIPSIS … '.encode()+b'ALIGNED TEXT.\n';return x+b'X'*(64-len(x))
def cbc_encrypt(block,plain,iv):
 out=[];reg=iv
 for i in range(0,len(plain),32):
  reg=block(bytes(a^b for a,b in zip(plain[i:i+32],reg)));out.append(reg)
 return b''.join(out)
def compact(cell,known_offset,expected):
 assert cell['all_rows_preserved'] and cell['all_candidates_independent_js_and_regex_replayed']
 assert len(cell['rows'])==cell['context_rows'] and [x['offset'] for x in cell['rows']]==list(range(cell['context_rows']))
 assert sum(cell['class_counts'].values())==cell['context_rows'] and len(cell['retained_candidates'])==cell['class_counts']['retained']
 planted=[x for x in cell['rows'] if x['offset']==known_offset];assert len(planted)==1 and bytes.fromhex(planted[0]['plaintext_hex'])==expected and planted[0]['accepted']
 replay=[x for x in cell['retained_candidates'] if x['offset']==known_offset];assert len(replay)==1 and replay[0]['javascript_plaintext_exact'] and replay[0]['independent_regex_oracle']
 serial=[[x['offset'],x['input_window_sha256'],x['classification'],x['witness'],hashlib.sha256(bytes.fromhex(x['plaintext_hex'])).hexdigest(),x['decrypted_blocks_hex']] for x in cell['rows']]
 return {'cell_id':cell['cell_id'],'context_rows':cell['context_rows'],'class_counts':cell['class_counts'],'known_offset':known_offset,'known_plaintext_hex':expected.hex(),
  'all_rows_digest':hashlib.sha256(json.dumps(serial,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'retained_candidates':cell['retained_candidates'],
  'known_row_exact':True,'row_offsets_complete_and_ordered':True,'all_evidence_fields_checked':True}
def regenerate(outdir):
 if outdir.exists():raise SystemExit('refusing existing regeneration directory')
 verify_pins();sys.path.insert(0,str(PRIM));pc=load(PRIM/'controls.py','target_primitive');builder=load(PRIM/'build_source.py','target_builder');pc.verify_pins();outdir.mkdir(parents=True)
 with tempfile.TemporaryDirectory(prefix='rijndael-window-driver-controls-') as td:
  lib=Path(td)/'r.dylib';cmd=builder.build(lib);text=strict64();ks=driver.keys()
  # ECB plant, forward orientation, 16-byte key.
  c1=pc.CPrimitive(lib,ks[16]);ecbct=c1.crypt(text[:32])+c1.crypt(text[32:]);off1=19;stream1=bytearray(deterministic('driver-ecb',546));stream1[off1:off1+64]=ecbct
  ecb=driver.execute_cell(bytes(stream1),16,'forward','ecb',c1);ecb_summary=compact(ecb,off1,text)
  # CBC plant, nibble-swap orientation, 24-byte key. Canonical inversion is exercised explicitly.
  c2=pc.CPrimitive(lib,ks[24]);iv=bytes((13*i+5)&255 for i in range(32));p0=b'CBC PREFIX BLOCK IS NOT RETURNED'[:32];cbcct=cbc_encrypt(lambda b:c2.crypt(b),p0+text,iv);off2=27
  oriented=bytearray(deterministic('driver-cbc',546));oriented[off2:off2+96]=cbcct;canonical=driver.orient(bytes(oriented),'nibble_swap');assert driver.orient(canonical,'nibble_swap')==bytes(oriented)
  cbc=driver.execute_cell(bytes(oriented),24,'nibble_swap','cbc',c2);cbc_summary=compact(cbc,off2,text)
  assert ecb['context_rows']==483 and cbc['context_rows']==451
  result={'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'scope':{'synthetic_cells':['k128|forward|ecb','k192|nibble_swap|cbc'],'stream_bytes':546,'driver_scope':driver.scope()},
   'ecb':ecb_summary,'cbc':cbc_summary,'orientation_involution_checked':True,'source_hashes':{'run_target.py':sha(HERE/'run_target.py'),'controls.py':sha(Path(__file__)),'prepare_gate.py':sha(HERE/'prepare_gate.py'),'README.md':sha(HERE/'README.md'),**PINS},
   'temporary_build':{'command':cmd[:-1]+['<temporary-output>'],'source_sha256':sha(PRIM/'source/rijndael-256.c'),'binary_hash_not_recorded':True},
   'assertions':{'all_passed':True,'same_execute_cell_path':True,'ecb_483_rows_complete':True,'cbc_451_rows_complete':True,'all_rows_evidence_checked':True,'planted_candidates_independent_js_regex_replayed':True,'orientation_inverse_checked':True,'no_target_read_or_evaluation':True}}
 out=outdir/'controls.json';out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(out),'sha256':sha(out),'counts':[ecb['context_rows'],cbc['context_rows']]},sort_keys=True))
def verify(path=LEDGER):
 d=json.loads(path.read_text());assert d['identity']==IDENTITY and d['target_evaluated'] is False and d['rev7_read'] is False;verify_pins()
 for rel,want in d['source_hashes'].items():assert sha(HERE/rel)==want,(rel,sha(HERE/rel),want)
 assert d['scope']['synthetic_cells']==['k128|forward|ecb','k192|nibble_swap|cbc'] and d['scope']['driver_scope']==driver.scope()
 for name,n in (('ecb',483),('cbc',451)):
  x=d[name];assert x['context_rows']==n and x['known_row_exact'] and x['row_offsets_complete_and_ordered'] and x['all_evidence_fields_checked']
  assert sum(x['class_counts'].values())==n and len(bytes.fromhex(x['known_plaintext_hex']))==64 and len(x['retained_candidates'])==x['class_counts']['retained']
  assert all(r['javascript_plaintext_exact'] and r['independent_regex_oracle'] for r in x['retained_candidates'])
 assert d['orientation_involution_checked'] and all(d['assertions'].values()) and d['temporary_build']['binary_hash_not_recorded']
 print(json.dumps({'identity':IDENTITY,'verified':True,'target_evaluated':False,'ledger_sha256':sha(path),'verification_scope':'stdlib source and structural ledger checks; no cryptographic regeneration'},sort_keys=True))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate-dir',type=Path);ap.add_argument('--ledger',type=Path,default=LEDGER);a=ap.parse_args();regenerate(a.regenerate_dir) if a.regenerate_dir else verify(a.ledger)
if __name__=='__main__':main()

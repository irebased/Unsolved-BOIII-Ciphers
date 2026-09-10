#!/usr/bin/env python3
"""Synthetic four-orientation wiring controls for the inert target driver."""
from pathlib import Path
import argparse,hashlib,importlib.util,json,random,sys
HERE=Path(__file__).resolve().parent;LEDGER=HERE/'controls.json';IDENTITY='ASTRA'
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
def display_encode(cipher,mapping):
 inverse=[None]*16
 for shown,actual in enumerate(mapping):inverse[actual]=shown
 h='0123456789ABCDEF';return ''.join(h[inverse[n]] for b in cipher for n in (b>>4,b&15))
def generate():
 d=load(HERE/'run_target.py','astra_r256_target_controls');rng=random.Random(20260910);mapping=list(range(16));rng.shuffle(mapping);plain=(b'ORIENTATION CONTROL ASCII\tLINE\r\n'+bytes.fromhex('e28093e28094e28098e28099e280a6')+b' END. ')*3
 js=d.js_jobs([{'key_hex':d.KEY.hex(),'iv_hex':d.IV.hex(),'data_hex':plain.hex(),'operation':'encrypt'}])[0];cipher=bytes.fromhex(js['ciphertext_hex']);source=display_encode(cipher,mapping);assert len(set(source))==16
 unknown=sorted(set('0123456789ABCDEF'.index(x) for x in source))[-4:];seed={i:v for i,v in enumerate(mapping) if i not in unknown};rows=[]
 for o in d.ORIENTATIONS:
  canonical=d.orient(source,o);assert d.orient(canonical,o)==source;row=d.execute_cell(canonical,o,cap=100000,seed=seed);truth=[x for x in row['solutions'] if x['mapping']==mapping and x['plaintext_hex']==plain.hex()];assert not row['aborted_at_node_limit'] and row['certificate_weight']==row['expected_completion_weight']==24 and len(truth)==1
  rows.append({'id':o,'canonical_sha256':hb(canonical.encode()),'source_display_sha256':hb(source.encode()),'inverse_exact':True,'nodes':row['nodes'],'rejected_plaintext':row['rejected_plaintext'],'complete':row['complete'],'certificate_weight':row['certificate_weight'],'expected_completion_weight':row['expected_completion_weight'],'solution_count':len(row['solutions']),'truth_retained_once':True,'validation':row['validation']})
 capped=d.execute_cell(d.orient(source,'forward'),'forward',cap=1,seed=seed);assert capped['aborted_at_node_limit'] and capped['nodes']==1 and not capped['solutions'] and capped['validation']['solution_material_sha256']==hb(b'')
 return {'identity':IDENTITY,'target_evaluated':False,'crypto_evaluated':True,'scope':'Synthetic exact production-wrapper wiring for four orientations with a seeded four-unknown map; no target extraction.','driver_sha256':sha(HERE/'run_target.py'),'native_binary_sha256':d.BIN_SHA,'native_build_sha256':d.BUILD_SHA,'parent_controls_source_sha256':d.PARENT_CONTROLS_SOURCE_SHA,'parent_controls_sha256':d.PARENT_CONTROLS_SHA,'plant':{'plaintext_hex':plain.hex(),'plaintext_sha256':hb(plain),'ciphertext_sha256':hb(cipher),'mapping':mapping,'unknown_symbols':unknown,'seed_mapping':{str(k):v for k,v in sorted(seed.items())},'display_sha256':hb(source.encode())},'orientation_rows':rows,'tiny_cap':{'orientation':'forward','node_limit':1,'nodes':capped['nodes'],'aborted':capped['aborted_at_node_limit'],'solution_count':len(capped['solutions']),'certificate_weight':capped['certificate_weight'],'expected_completion_weight':capped['expected_completion_weight']},'assertions':{'exact_four_orientation_ids':[x['id'] for x in rows]==list(d.ORIENTATIONS),'all_orientation_inverses_exact':True,'all_seeded_24_certificates_complete':all(x['certificate_weight']==24 for x in rows),'truth_mapping_plaintext_retained_once_each':True,'all_survivors_independent_js_decrypt_reencrypt':True,'tiny_cap_incomplete_without_solution':capped['aborted_at_node_limit'] and not capped['solutions'],'no_target_read_or_evaluation':True}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();out=generate()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)},sort_keys=True))
 else:
  assert json.loads(LEDGER.read_text())==out;print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(LEDGER),'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()

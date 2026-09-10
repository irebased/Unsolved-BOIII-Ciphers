#!/usr/bin/env python3
"""Bounded lossless transport and read-only evidence verifier for controls.json."""
from pathlib import Path
import argparse,base64,hashlib,importlib.util,json,zlib
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent;PACK=HERE/'controls.pack.json';IDENTITY='ASTRA'
RAW_LEN=44_489_987;RAW_SHA='7ac6af27db0ef3a30cf77b410f58be335f54f3ec3ddb26000ac24ecf1636d241'
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def unpack_bytes():
 envelope=json.loads(PACK.read_text());assert envelope['identity']==IDENTITY and envelope['format']=='zlib-level9/base64' and envelope['raw_name']=='controls.json' and envelope['raw_length']==RAW_LEN and envelope['raw_sha256']==RAW_SHA
 comp=base64.b64decode(envelope['payload_base64'],validate=True);assert len(comp)==envelope['compressed_length'] and hb(comp)==envelope['compressed_sha256']
 d=zlib.decompressobj();raw=d.decompress(comp,RAW_LEN+1)
 # Do not flush an unfinished stream: this bounds decompressed output to RAW_LEN+1.
 assert len(raw)==RAW_LEN and d.eof and not d.unconsumed_tail and not d.unused_data and d.flush()==b'' and hb(raw)==RAW_SHA
 return raw
def verify_row_accounting(row):
 total=row['initial_registers_total'];partial=row['partial_root'] is not None
 assert row['accepted_states']==sum(row['accepted_states_by_suffix_byte'])
 assert row['roots_started']==row['roots_completed']+partial
 assert row['roots_completed']+row['roots_unexamined']+partial==total
 assert row['complete']==(row['roots_completed']==total and not partial)
 assert row['solutions_are_terminal_only'] and row['solution_count']==len(row['solutions'])
def verify_evidence(data):
 controls=load(HERE/'controls.py','astra_lossy4_pack_evidence');core=controls.core
 assert data['identity']==IDENTITY and data['target_evaluated'] is False and data['rev7_read'] is False and all(data['assertions'].values())
 assert data['controls_source_sha256']==sha(HERE/'controls.py') and data['core_source_sha256']==sha(HERE/'core.py')
 assert len(data['class_metadata'])==len(data['short_all_class_plants'])==len(data['random_nulls_all_classes'])==12
 assert {x['root_count'] for x in data['class_metadata']}=={256,4096} and sum(len(x['orientation_wiring']) for x in data['class_metadata'])==48
 validated=0
 for group in ('short_all_class_plants','full_length_shape_plants'):
  for item in data[group]:
   row=item['search'];verify_row_accounting(row);key=item['representative_key'];n=item['natural_bytes']
   truth=next(x for x in row['solutions'] if x['ciphertext_sha256']==item['truth_ciphertext_sha256'])
   observed=controls.source_emit(bytes.fromhex(truth['ciphertext_hex']).hex().upper(),key)
   assert len(observed)==item['observation_length'] and hb(observed.encode())==item['observation_sha256']
   controls.validate(row,observed,n,key);validated+=row['solution_count']
 for item in data['random_nulls_all_classes']:
  row=item['search'];verify_row_accounting(row);observed=controls.deterministic_hex(item['observation_length'],'ASTRA lossy4 null '+item['id']+' ')
  assert hb(observed.encode())==item['observation_sha256'];controls.validate(row,observed,655,item['representative_key']);validated+=row['solution_count']
 for item in data['tiny_caps_both_root_shapes']:
  row=item['search'];verify_row_accounting(row);assert not row['complete'] and row['capped_reason'] and row['solution_count']==0 and row['partial_root']['next_valid_candidate_not_added']
 assert validated==20_622
 return {'terminal_candidates_revalidated':validated,'class_maps':12,'orientation_wirings':48,'nulls':12,'tiny_caps':2}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--unpack',type=Path);a=ap.parse_args();raw=unpack_bytes();summary=verify_evidence(json.loads(raw))
 if a.unpack:
  if a.unpack.exists():raise SystemExit('refusing existing output')
  a.unpack.write_bytes(raw);assert sha(a.unpack)==RAW_SHA
 print(json.dumps({'identity':IDENTITY,'verified':True,'pack_sha256':sha(PACK),'raw_sha256':RAW_SHA,'raw_length':RAW_LEN,**summary},sort_keys=True))
if __name__=='__main__':main()

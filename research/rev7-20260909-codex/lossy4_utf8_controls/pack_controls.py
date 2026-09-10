#!/usr/bin/env python3
"""Bounded lossless transport and read-only cryptographic verifier for the UTF-8 controls ledger."""
from pathlib import Path
import argparse,base64,hashlib,importlib.util,json,zlib
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent;PACK=HERE/'controls.pack.json';RAW_LEN=41_519_030;RAW_SHA='83e144d09a92b2e88c504c85cc482fcaeca3a330a9e19b393c59b2064c85c5f0';IDENTITY='ASTRA'
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def load(path,name):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def unpack_bytes():
 env=json.loads(PACK.read_text());assert env['identity']==IDENTITY and env['format']=='zlib-level9/base64' and env['raw_name']=='controls.json' and env['raw_length']==RAW_LEN and env['raw_sha256']==RAW_SHA
 comp=base64.b64decode(env['payload_base64'],validate=True);assert len(comp)==env['compressed_length'] and hb(comp)==env['compressed_sha256'];d=zlib.decompressobj();raw=d.decompress(comp,RAW_LEN+1);assert len(raw)==RAW_LEN and d.eof and not d.unconsumed_tail and not d.unused_data and d.flush()==b'' and hb(raw)==RAW_SHA;return raw
def accounting(row):
 partial=row['partial_root'] is not None;assert row['accepted_states']==sum(row['accepted_states_by_suffix_byte']) and row['roots_started']==row['roots_completed']+partial and row['roots_completed']+row['roots_unexamined']+partial==row['initial_registers_total'] and row['complete']==(row['roots_completed']==row['initial_registers_total'] and not partial) and row['solution_count']==len(row['solutions']) and row['solutions_are_terminal_only']
def verify(data):
 c=load(HERE/'controls.py','astra_l4_utf8_pack_controls');assert data['identity']==IDENTITY and data['target_evaluated'] is False and all(data['assertions'].values()) and data['controls_source_sha256']==sha(HERE/'controls.py') and data['source']['core_sha256']==sha(HERE/'core.py')
 assert c.endpoint_controls()==data['automaton_controls']
 assert len(data['geometry_all_12_maps'])==12 and {x['root_count'] for x in data['geometry_all_12_maps']}=={256,4096}
 total=0
 for item in data['plants']:
  n=item['natural_bytes'];plain=c.build_plain(n,item['cut_at_suffix_start'],item['full_endpoint_inventory_present']);ct=DES.new(c.core.KEY,DES.MODE_CFB,iv=bytes.fromhex(item['original_iv_hex']),segment_size=8).encrypt(plain);obs=c.source_emit(ct.hex().upper(),item['representative_key']);assert hb(plain)==item['plaintext_sha256'] and hb(ct)==item['truth_ciphertext_sha256'] and hb(obs.encode())==item['observation_sha256'];row=item['search'];accounting(row);c.validate(row,obs,n,item['representative_key']);total+=row['solution_count']
 for item in data['random_nulls']:
  obs=c.deterministic_hex(1092,'ASTRA lossy4 UTF8 null '+item['id']+' ');assert hb(obs.encode())==item['observation_sha256'];accounting(item['search']);c.validate(item['search'],obs,655,item['representative_key']);total+=item['search']['solution_count']
 for item in data['tiny_caps']:
  row=item['search'];accounting(row);assert not row['complete'] and row['capped_reason']=='max_accepted' and row['solution_count']==0 and row['partial_root']['next_valid_candidate_not_added']
 assert total==13_796
 return {'terminal_candidates_revalidated':total,'automaton_oracle_cases':65_793,'codewords':201,'map_classes':12,'nulls':2,'tiny_caps':2}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--unpack',type=Path);a=ap.parse_args();raw=unpack_bytes();summary=verify(json.loads(raw))
 if a.unpack:
  if a.unpack.exists():raise SystemExit('refusing existing output')
  a.unpack.write_bytes(raw);assert sha(a.unpack)==RAW_SHA
 print(json.dumps({'identity':IDENTITY,'verified':True,'pack_sha256':sha(PACK),'raw_sha256':RAW_SHA,'raw_length':RAW_LEN,**summary},sort_keys=True))
if __name__=='__main__':main()

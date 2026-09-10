#!/usr/bin/env python3
"""Losslessly pack, bounded-unpack, and structurally verify the frozen controls ledger."""
from __future__ import annotations
from pathlib import Path
import argparse,base64,hashlib,json,re,zlib
HERE=Path(__file__).resolve().parent;RAW=HERE/'controls.json';PACK=HERE/'controls.pack.json';IDENTITY='ASTRA'
RAW_BYTES=6094712;RAW_SHA='511aad6d309c05b16a8b2281f69bc748f180af499988016659554324b7f135d3'
def h(data):return hashlib.sha256(data).hexdigest()
def sha(path):return h(Path(path).read_bytes())
def unpack_bytes(pack_path=PACK):
 envelope=json.loads(pack_path.read_text())
 assert envelope['identity']==IDENTITY and envelope['target_evaluated'] is False
 assert envelope['format']=='zlib-9 + RFC1924 base85 of exact original JSON bytes'
 assert envelope['raw_bytes']==RAW_BYTES and envelope['raw_sha256']==RAW_SHA
 compressed_bytes=envelope['compressed_bytes'];assert isinstance(compressed_bytes,int) and 0<compressed_bytes<=RAW_BYTES+1024
 payload=envelope['payload_base85'];assert isinstance(payload,str) and payload.isascii()
 assert len(payload)==(compressed_bytes//4)*5+(0 if compressed_bytes%4==0 else compressed_bytes%4+1)
 compressed=base64.b85decode(payload.encode('ascii'));assert len(compressed)==compressed_bytes
 assert base64.b85encode(compressed).decode('ascii')==payload and h(compressed)==envelope['compressed_sha256']
 dec=zlib.decompressobj();raw=dec.decompress(compressed,RAW_BYTES+1)
 assert len(raw)==RAW_BYTES and dec.eof and not dec.unused_data and not dec.unconsumed_tail
 assert dec.flush()==b'' and h(raw)==RAW_SHA
 return raw,envelope
def basic_ledger(raw):
 d=json.loads(raw);assert d['identity']==IDENTITY and d['target_evaluated'] is False and d['rev7_read'] is False
 assert d['primitive_count']==len(d['primitive'])==6
 assert d['interval_vector_count']==len(d['interval_vectors'])==21
 assert d['cascade_recipe_count']==len(d['cascade_recipes'])==1176
 assert d['cascade_execution_count']==2352 and d['depth2_recipe_count']==168 and d['depth3_recipe_count']==1008
 assert d['direct_fixed_ciphertext_two_iv_count']==len(d['direct_fixed_ciphertext_two_iv'])==3
 assert d['assertions']['all_passed'] and d['assertions']['no_target_read_or_evaluation']
 return d
def create(source,output):
 if output.exists():raise SystemExit('refusing existing output: '+str(output))
 raw=source.read_bytes();assert len(raw)==RAW_BYTES and h(raw)==RAW_SHA;basic_ledger(raw)
 compressed=zlib.compress(raw,9);payload=base64.b85encode(compressed).decode('ascii')
 env={'identity':IDENTITY,'target_evaluated':False,'format':'zlib-9 + RFC1924 base85 of exact original JSON bytes',
  'raw_bytes':RAW_BYTES,'raw_sha256':RAW_SHA,'compressed_bytes':len(compressed),'compressed_sha256':h(compressed),'payload_base85':payload}
 output.write_text(json.dumps(env,sort_keys=True,separators=(',',':'))+'\n')
 rebuilt,_=unpack_bytes(output);assert rebuilt==raw
 print(json.dumps({'identity':IDENTITY,'output':str(output),'sha256':sha(output),'raw_bytes':len(raw),'compressed_bytes':len(compressed)},sort_keys=True))
def verify():
 raw,envelope=unpack_bytes();d=basic_ledger(raw)
 if RAW.exists():assert RAW.stat().st_size==RAW_BYTES and sha(RAW)==RAW_SHA and RAW.read_bytes()==raw
 print(json.dumps({'identity':IDENTITY,'verified':True,'pack_sha256':sha(PACK),'raw_sha256':RAW_SHA,'raw_bytes':RAW_BYTES,
  'compressed_bytes':envelope['compressed_bytes'],'basic_counts':{'primitive':d['primitive_count'],'interval_vectors':d['interval_vector_count'],'cascade_recipes':d['cascade_recipe_count'],'cascade_executions':d['cascade_execution_count']},
  'verification_scope':'lossless bounded byte reconstruction, exact raw hash, and basic frozen-ledger identity/counts; no cryptographic or target evaluation'},indent=2,sort_keys=True))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--create',type=Path);ap.add_argument('--output',type=Path);ap.add_argument('--unpack',type=Path);a=ap.parse_args()
 if a.create:
  if a.output is None or a.unpack:ap.error('--create requires --output and excludes --unpack')
  create(a.create,a.output)
 elif a.unpack:
  if a.output:ap.error('--unpack excludes --output')
  if a.unpack.exists():raise SystemExit('refusing existing output: '+str(a.unpack))
  raw,_=unpack_bytes();basic_ledger(raw);a.unpack.write_bytes(raw)
  print(json.dumps({'identity':IDENTITY,'output':str(a.unpack),'bytes':len(raw),'sha256':sha(a.unpack)},sort_keys=True))
 else:
  if a.output:ap.error('--output requires --create')
  verify()
if __name__=='__main__':main()

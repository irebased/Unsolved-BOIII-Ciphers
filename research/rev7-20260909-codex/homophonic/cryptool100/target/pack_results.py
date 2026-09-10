#!/usr/bin/env python3
"""Losslessly pack/unpack the exact target NDJSON with bounded zlib decoding."""
from pathlib import Path
import argparse,base64,hashlib,json,zlib
HERE=Path(__file__).resolve().parent;RAW=HERE/'target_results.ndjson';PACK=HERE/'results.pack.json';IDENTITY='ASTRA';EXPECTED_RAW_SHA='426a5be079cf553ba657e3bb3f9d4e8153ee15422efc0e8793e1840249dcac39';EXPECTED_RAW_LEN=67783676
def h(b):return hashlib.sha256(b).hexdigest()
def unpack_obj(o):
 assert o['identity']==IDENTITY and o['codec']=='zlib-9+base85' and o['raw_sha256']==EXPECTED_RAW_SHA and o['raw_length']==EXPECTED_RAW_LEN
 enc=o['payload'].encode('ascii');assert len(enc)<=EXPECTED_RAW_LEN*2
 comp=base64.b85decode(enc);assert h(comp)==o['compressed_sha256'] and len(comp)==o['compressed_length']
 d=zlib.decompressobj();raw=d.decompress(comp,EXPECTED_RAW_LEN+1);assert len(raw)<=EXPECTED_RAW_LEN
 raw+=d.flush(EXPECTED_RAW_LEN+1-len(raw));assert d.eof and not d.unused_data and not d.unconsumed_tail
 assert len(raw)==EXPECTED_RAW_LEN and h(raw)==EXPECTED_RAW_SHA
 return raw
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--create',type=Path);ap.add_argument('--unpack',type=Path);a=ap.parse_args()
 if a.create:
  if a.create.exists():raise SystemExit('refusing existing pack')
  raw=RAW.read_bytes();assert len(raw)==EXPECTED_RAW_LEN and h(raw)==EXPECTED_RAW_SHA;comp=zlib.compress(raw,9)
  o={'identity':IDENTITY,'target_evaluated':True,'codec':'zlib-9+base85','raw_name':RAW.name,'raw_length':len(raw),'raw_sha256':h(raw),'compressed_length':len(comp),'compressed_sha256':h(comp),'payload':base64.b85encode(comp).decode('ascii')}
  a.create.write_text(json.dumps(o,sort_keys=True,separators=(',',':'))+'\n');print(h(a.create.read_bytes()));return
 raw=unpack_obj(json.loads(PACK.read_text()))
 if RAW.exists():assert RAW.read_bytes()==raw
 if a.unpack:
  if a.unpack.exists():raise SystemExit('refusing existing unpack path')
  a.unpack.write_bytes(raw)
 print('PASS',EXPECTED_RAW_SHA,len(raw))
if __name__=='__main__':main()

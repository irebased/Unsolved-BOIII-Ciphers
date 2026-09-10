#!/usr/bin/env python3
"""Losslessly pack and bounded-unpack the frozen Rijndael-256 window result."""
from pathlib import Path
import argparse,base64,hashlib,json,zlib
HERE=Path(__file__).resolve().parent;FULL=HERE/'target_results.json';PACK=HERE/'target_results.pack.json';IDENTITY='ASTRA'
FULL_BYTES=8339129;FULL_SHA='c50a7103736310aa6aba1c58834d62554d11aaec22bbf1430e35d56efbb4890d'
def h(x):return hashlib.sha256(x).hexdigest()
def sha(p):return h(Path(p).read_bytes())
def unpack_bytes(path=PACK):
 e=json.loads(path.read_text());assert e['identity']==IDENTITY and e['target_evaluated'] is True and e['format']=='zlib-9 + RFC1924 base85 of exact original JSON bytes'
 assert e['full_bytes']==FULL_BYTES and e['full_sha256']==FULL_SHA
 n=e['compressed_bytes'];assert isinstance(n,int) and 0<n<=FULL_BYTES+1024
 payload=e['payload_base85'];assert isinstance(payload,str) and payload.isascii() and len(payload)==(n//4)*5+(0 if n%4==0 else n%4+1)
 compressed=base64.b85decode(payload.encode('ascii'));assert len(compressed)==n and base64.b85encode(compressed).decode('ascii')==payload and h(compressed)==e['compressed_sha256']
 dec=zlib.decompressobj();raw=dec.decompress(compressed,FULL_BYTES+1)
 assert len(raw)==FULL_BYTES and dec.eof and not dec.unused_data and not dec.unconsumed_tail and dec.flush()==b'' and h(raw)==FULL_SHA
 return raw,e
def create(source,output):
 if output.exists():raise SystemExit('refusing existing output: '+str(output))
 raw=source.read_bytes();assert len(raw)==FULL_BYTES and h(raw)==FULL_SHA
 d=json.loads(raw);assert d['identity']==IDENTITY and d['target_evaluated'] is True and d['status']=='complete'
 c=zlib.compress(raw,9);e={'identity':IDENTITY,'target_evaluated':True,'format':'zlib-9 + RFC1924 base85 of exact original JSON bytes','full_bytes':FULL_BYTES,'full_sha256':FULL_SHA,'compressed_bytes':len(c),'compressed_sha256':h(c),'payload_base85':base64.b85encode(c).decode('ascii')}
 output.write_text(json.dumps(e,sort_keys=True,separators=(',',':'))+'\n');rebuilt,_=unpack_bytes(output);assert rebuilt==raw
 print(json.dumps({'identity':IDENTITY,'output':str(output),'sha256':sha(output),'full_bytes':FULL_BYTES,'compressed_bytes':len(c)},sort_keys=True))
def verify():
 raw,e=unpack_bytes();d=json.loads(raw);assert d['identity']==IDENTITY and d['target_evaluated'] is True and d['status']=='complete'
 if FULL.exists():assert FULL.stat().st_size==FULL_BYTES and sha(FULL)==FULL_SHA and FULL.read_bytes()==raw
 print(json.dumps({'identity':IDENTITY,'verified':True,'pack_sha256':sha(PACK),'full_sha256':FULL_SHA,'full_bytes':FULL_BYTES,'compressed_bytes':e['compressed_bytes'],'verification_scope':'bounded lossless byte reconstruction only'},indent=2,sort_keys=True))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--create',type=Path);ap.add_argument('--output',type=Path);ap.add_argument('--unpack',type=Path);a=ap.parse_args()
 if a.create:
  if a.output is None or a.unpack:ap.error('--create requires --output and excludes --unpack')
  create(a.create,a.output)
 elif a.unpack:
  if a.output:ap.error('--unpack excludes --output')
  if a.unpack.exists():raise SystemExit('refusing existing output: '+str(a.unpack))
  raw,_=unpack_bytes();a.unpack.write_bytes(raw);print(json.dumps({'identity':IDENTITY,'output':str(a.unpack),'bytes':len(raw),'sha256':sha(a.unpack)},sort_keys=True))
 else:
  if a.output:ap.error('--output requires --create')
  verify()
if __name__=='__main__':main()

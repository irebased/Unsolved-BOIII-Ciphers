#!/usr/bin/env python3
"""Deterministic lossless transport for the frozen even-period target ledger."""
import argparse,base64,gzip,hashlib,json,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent;PACK=HERE/'target_results.pack.json';RAW=HERE/'target_results.json'
RAW_LEN=7_464_776;RAW_SHA='acc7df78f141e79b9d3c4e23dba3124ddb7665d5cb5f7450eabd5d9a88ce1dc8';PACK_SHA='3d9913b1253fc9acb52520dc2098ada980f16ad9b38958df891247033236fb12';COMP_SHA='a5fb5d169a4f21ba70367b9cc46fd5e652db577e8683cb1cff68bc18dd08c706';COMP_LEN=468_922
def hb(b):return hashlib.sha256(b).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def unpack():
 assert sha(PACK)==PACK_SHA
 e=json.loads(PACK.read_text());assert e=={**e,'identity':'ASTRA','target_evaluated':True,'format':'gzip-level9-mtime0/base64','raw_name':'target_results.json','raw_length':RAW_LEN,'raw_sha256':RAW_SHA,'compressed_length':COMP_LEN,'compressed_sha256':COMP_SHA}
 comp=base64.b64decode(e['payload_base64'],validate=True);assert len(comp)==COMP_LEN and hb(comp)==COMP_SHA
 d=zlib.decompressobj(16+zlib.MAX_WBITS);raw=d.decompress(comp,RAW_LEN+1)+d.flush();assert d.eof and not d.unused_data and not d.unconsumed_tail
 assert len(raw)==RAW_LEN and hb(raw)==RAW_SHA
 x=json.loads(raw);assert x['identity']=='ASTRA' and x['target_evaluated'] is True and x['status']=='complete' and len(x['cells'])==2184
 return raw
def pack(raw):
 comp=gzip.compress(raw,compresslevel=9,mtime=0);assert len(comp)==COMP_LEN and hb(comp)==COMP_SHA
 e={'identity':'ASTRA','target_evaluated':True,'format':'gzip-level9-mtime0/base64','raw_name':'target_results.json','raw_length':RAW_LEN,'raw_sha256':RAW_SHA,'compressed_length':COMP_LEN,'compressed_sha256':COMP_SHA,'payload_base64':base64.b64encode(comp).decode()}
 return (json.dumps(e,sort_keys=True,separators=(',',':'))+'\n').encode()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--restore',type=Path);ap.add_argument('--build',type=Path);a=ap.parse_args();raw=unpack()
 if RAW.exists():assert RAW.stat().st_size==RAW_LEN and sha(RAW)==RAW_SHA
 if a.restore:
  if a.restore.exists():raise SystemExit(f'refusing existing restore path: {a.restore}')
  a.restore.write_bytes(raw);assert sha(a.restore)==RAW_SHA
 if a.build:
  if a.build.exists():raise SystemExit(f'refusing existing pack path: {a.build}')
  if not RAW.exists():raise SystemExit('building requires pinned raw result')
  b=pack(RAW.read_bytes());assert hb(b)==PACK_SHA;a.build.write_bytes(b)
 print(json.dumps({'identity':'ASTRA','verified':True,'pack_sha256':PACK_SHA,'pack_bytes':PACK.stat().st_size,'compressed_sha256':COMP_SHA,'compressed_bytes':COMP_LEN,'raw_sha256':RAW_SHA,'raw_bytes':RAW_LEN,'existing_raw_checked':RAW.exists()},sort_keys=True))
if __name__=='__main__':main()

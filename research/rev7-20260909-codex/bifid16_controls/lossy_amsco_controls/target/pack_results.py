#!/usr/bin/env python3
import argparse,base64,gzip,hashlib,json,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent;PACK=HERE/'target_results.pack.json';RAW=HERE/'target_results.json';RAW_LEN=41_705_746;RAW_SHA='cbe78dd96151e19e1e79a689030e436a670fa490075a894150ebfa30183c3744';PACK_SHA='4cfbd6604c318abe77091df6965464bec85696e6a913e06d0bf9122389f5d9c9';COMP_LEN=5_721_579;COMP_SHA='200831e63d0f6a97db34642461b61a4d7d795a44b9a75bafd5321c02f422f8d3'
def hb(b):return hashlib.sha256(b).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def unpack():
 assert sha(PACK)==PACK_SHA;e=json.loads(PACK.read_text());assert e['identity']=='ASTRA' and e['target_evaluated'] is True and e['format']=='gzip-level9-mtime0/base64' and e['raw_name']=='target_results.json' and e['raw_length']==RAW_LEN and e['raw_sha256']==RAW_SHA and e['compressed_length']==COMP_LEN and e['compressed_sha256']==COMP_SHA
 c=base64.b64decode(e['payload_base64'],validate=True);assert len(c)==COMP_LEN and hb(c)==COMP_SHA;d=zlib.decompressobj(16+zlib.MAX_WBITS);raw=d.decompress(c,RAW_LEN+1)+d.flush();assert d.eof and not d.unused_data and not d.unconsumed_tail and len(raw)==RAW_LEN and hb(raw)==RAW_SHA;x=json.loads(raw);assert x['identity']=='ASTRA' and x['target_evaluated'] is True and len(x['cells'])==31440;return raw
def pack(raw):
 c=gzip.compress(raw,9,mtime=0);assert len(c)==COMP_LEN and hb(c)==COMP_SHA;e={'identity':'ASTRA','target_evaluated':True,'format':'gzip-level9-mtime0/base64','raw_name':'target_results.json','raw_length':RAW_LEN,'raw_sha256':RAW_SHA,'compressed_length':COMP_LEN,'compressed_sha256':COMP_SHA,'payload_base64':base64.b64encode(c).decode()};return (json.dumps(e,sort_keys=True,separators=(',',':'))+'\n').encode()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--restore',type=Path);ap.add_argument('--build',type=Path);a=ap.parse_args();raw=unpack()
 if RAW.exists():assert RAW.stat().st_size==RAW_LEN and sha(RAW)==RAW_SHA
 if a.restore:
  if a.restore.exists():raise SystemExit('refusing existing restore path')
  a.restore.write_bytes(raw);assert sha(a.restore)==RAW_SHA
 if a.build:
  if a.build.exists():raise SystemExit('refusing existing build path')
  if not RAW.exists():raise SystemExit('building requires pinned raw result')
  b=pack(RAW.read_bytes());assert hb(b)==PACK_SHA;a.build.write_bytes(b)
 print(json.dumps({'identity':'ASTRA','verified':True,'raw_sha256':RAW_SHA,'raw_bytes':RAW_LEN,'pack_sha256':PACK_SHA,'pack_bytes':PACK.stat().st_size,'compressed_sha256':COMP_SHA,'compressed_bytes':COMP_LEN},sort_keys=True))
if __name__=='__main__':main()

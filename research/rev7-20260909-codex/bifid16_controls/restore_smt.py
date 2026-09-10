#!/usr/bin/env python3
"""ASTRA verified restoration of frozen SMT artifacts. No solver execution."""
import argparse,base64,hashlib,json,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent
PACK=HERE/'smt_transport.json'
PACK_SHA='ce690dd39d5d530da4e22d86ffcde89c361fe2742b3e63f200cf76ad8c896964'
def hb(b):return hashlib.sha256(b).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--restore',action='store_true');a=ap.parse_args()
 assert hb(PACK.read_bytes())==PACK_SHA
 data=json.loads(PACK.read_text());assert data['identity']=='ASTRA' and data['format']=='gzip-level9-mtime0/base64'
 assert len(data['files'])==27
 decoded=[];paths=set()
 for row in data['files']:
  rel=Path(row['path']);assert not rel.is_absolute() and '..' not in rel.parts and str(rel) not in paths;paths.add(str(rel))
  assert 0<row['raw_bytes']<=10000000 and 0<row['gzip_bytes']<=10000000
  comp=base64.b64decode(row['gzip_base64'],validate=True);assert len(comp)==row['gzip_bytes'] and hb(comp)==row['gzip_sha256']
  d=zlib.decompressobj(16+zlib.MAX_WBITS);raw=d.decompress(comp,row['raw_bytes']+1)
  assert not d.unconsumed_tail and d.eof and not d.unused_data and len(raw)==row['raw_bytes'] and hb(raw)==row['sha256']
  dst=HERE/rel
  if dst.exists():assert dst.is_file() and dst.read_bytes()==raw
  decoded.append((dst,raw))
 restored=0
 if a.restore:
  for dst,raw in decoded:
   if not dst.exists():
    dst.parent.mkdir(parents=True,exist_ok=True)
    with dst.open('xb') as f:f.write(raw)
    restored+=1
 print(json.dumps({'identity':'ASTRA','verified':True,'pack_sha256':PACK_SHA,'files':len(decoded),'restored':restored,'solver_executed':False},sort_keys=True))
if __name__=='__main__':main()

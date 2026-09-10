#!/usr/bin/env python3
"""Lossless deterministic transport for the frozen periodic byte-bag result."""
import argparse,base64,gzip,hashlib,json,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent;PACK=HERE/"target_results.pack.json";RAW=HERE/"target_results.json"
RAW_LEN=8_583_401;RAW_SHA="008966a182ee38ff9ffac569e715d91bab8c05cf37ae5c2c6043dc0d6b1c9acc";PACK_SHA="36e439807210c9ae9b8973022b1b65320e57d96fd3433ef3b89c7829c8b28adc";COMP_SHA="c8712e3499e03188d3acb7063a682a5628833bf4c9c4a2abff028498c30fd6e9";COMP_LEN=424_256
def sha_bytes(x):return hashlib.sha256(x).hexdigest()
def sha(p):return sha_bytes(p.read_bytes())
def unpack():
 assert sha(PACK)==PACK_SHA
 env=json.loads(PACK.read_text());assert env["identity"]=="ASTRA" and env["target_evaluated"] is True and env["format"]=="gzip-level9-mtime0/base64" and env["raw_name"]=="target_results.json"
 assert env["raw_length"]==RAW_LEN and env["raw_sha256"]==RAW_SHA and env["compressed_length"]==COMP_LEN and env["compressed_sha256"]==COMP_SHA
 comp=base64.b64decode(env["payload_base64"],validate=True);assert len(comp)==COMP_LEN and sha_bytes(comp)==COMP_SHA
 d=zlib.decompressobj(16+zlib.MAX_WBITS);raw=d.decompress(comp,RAW_LEN+1)+d.flush();assert d.eof and not d.unused_data and not d.unconsumed_tail
 assert len(raw)==RAW_LEN and sha_bytes(raw)==RAW_SHA
 parsed=json.loads(raw);assert parsed["identity"]=="ASTRA" and parsed["target_evaluated"] is True and len(parsed["cells"])==512
 return raw
def deterministic_pack(raw):
 comp=gzip.compress(raw,compresslevel=9,mtime=0);assert len(comp)==COMP_LEN and sha_bytes(comp)==COMP_SHA
 env={"identity":"ASTRA","target_evaluated":True,"format":"gzip-level9-mtime0/base64","raw_name":"target_results.json","raw_length":RAW_LEN,"raw_sha256":RAW_SHA,"compressed_length":COMP_LEN,"compressed_sha256":COMP_SHA,"payload_base64":base64.b64encode(comp).decode()}
 return (json.dumps(env,sort_keys=True,separators=(",",":"))+"\n").encode()
def main():
 p=argparse.ArgumentParser();p.add_argument("--restore",type=Path);p.add_argument("--build",type=Path);a=p.parse_args();raw=unpack()
 if RAW.exists():assert RAW.stat().st_size==RAW_LEN and sha(RAW)==RAW_SHA
 if a.restore:
  if a.restore.exists():raise SystemExit(f"refusing existing restore path: {a.restore}")
  a.restore.write_bytes(raw);assert sha(a.restore)==RAW_SHA
 if a.build:
  if a.build.exists():raise SystemExit(f"refusing existing pack path: {a.build}")
  if not RAW.exists():raise SystemExit("building requires the pinned raw result")
  packed=deterministic_pack(RAW.read_bytes());assert sha_bytes(packed)==PACK_SHA;a.build.write_bytes(packed)
 print(json.dumps({"identity":"ASTRA","verified":True,"pack_sha256":PACK_SHA,"pack_bytes":PACK.stat().st_size,"compressed_sha256":COMP_SHA,"compressed_bytes":COMP_LEN,"raw_sha256":RAW_SHA,"raw_bytes":RAW_LEN,"existing_raw_checked":RAW.exists(),"restored_to":str(a.restore) if a.restore else None,"rebuilt_to":str(a.build) if a.build else None},sort_keys=True))
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Synthetic-only controls for exact gzip transport codec."""
from __future__ import annotations
import argparse,base64,hashlib,json,lzma,os,tempfile
from pathlib import Path
import codec
HERE=Path(__file__).resolve().parent;OUT=HERE/"codec_controls.json"
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,indent=2)+"\n"
def reject(label,fn):
 try:fn()
 except (ValueError,FileExistsError,json.JSONDecodeError,lzma.LZMAError):return label
 raise AssertionError(f"did not reject {label}")
def rewrap(inner,template):
 ib=codec.canonical(inner);compressed=lzma.compress(ib,format=lzma.FORMAT_XZ,preset=6);outer=dict(template);outer.update({"inner_json_bytes":len(ib),"inner_json_sha256":codec.sha(ib),"compressed_xz_bytes":len(compressed),"compressed_xz_sha256":codec.sha(compressed),"compressed_xz_base64":base64.b64encode(compressed).decode()});return codec.canonical(outer)
def build():
 records=[(f"complete_periods/smt/forward_p{i}.smt2.gz",hashlib.sha256(f"record-{i}".encode()).digest()*(20+i)) for i in range(1,7)]
 envelopes=codec.pack(records,raw_limit=1800);assert len(envelopes)>=2
 restored=[]
 for part in envelopes:restored.extend(codec.unpack(part,max_file_bytes=codec.MAX_FILE_BYTES))
 assert restored==records
 with tempfile.TemporaryDirectory() as td:
  first=[]
  for part in envelopes:first.append(codec.restore(part,td))
  second=[]
  for part in envelopes:second.append(codec.restore(part,td))
  assert sum(len(x["written"]) for x in first)==len(records) and sum(len(x["already_identical"]) for x in second)==len(records)
  victim=Path(td)/records[0][0];victim.write_bytes(b"wrong")
  overwrite=reject("nonidentical_existing",lambda:codec.restore(envelopes[0],td))
 outer=json.loads(envelopes[0]);compressed=base64.b64decode(outer["compressed_xz_base64"])
 bad=bytearray(compressed);bad[len(bad)//2]^=1;corrupt=dict(outer);corrupt["compressed_xz_base64"]=base64.b64encode(bytes(bad)).decode();corruption=reject("compressed_corruption",lambda:codec.unpack(codec.canonical(corrupt)))
 trunc=dict(outer);cut=compressed[:-1];trunc.update({"compressed_xz_base64":base64.b64encode(cut).decode(),"compressed_xz_bytes":len(cut),"compressed_xz_sha256":codec.sha(cut)});truncation=reject("truncated_xz",lambda:codec.unpack(codec.canonical(trunc)))
 trailing=dict(outer);trail=compressed+b"X";trailing.update({"compressed_xz_base64":base64.b64encode(trail).decode(),"compressed_xz_bytes":len(trail),"compressed_xz_sha256":codec.sha(trail)});trailing_result=reject("trailing_xz",lambda:codec.unpack(codec.canonical(trailing)))
 inner=json.loads(codec.bounded_xz(compressed,outer["inner_json_bytes"]));dup=json.loads(json.dumps(inner));dup["records"].append(dict(dup["records"][0]));duplicate=reject("duplicate_path",lambda:codec.unpack(rewrap(dup,outer)))
 traversal=json.loads(json.dumps(inner));traversal["records"][0]["path"]="complete_periods/smt/../escape.smt2.gz";pathbad=reject("path_traversal",lambda:codec.unpack(rewrap(traversal,outer)))
 noncanonical=json.dumps(outer,sort_keys=False,indent=1).encode()+b"\n";outer_noncanonical=reject("noncanonical_outer",lambda:codec.unpack(noncanonical))
 memory=reject("decoder_memlimit",lambda:codec.bounded_xz(compressed,outer["inner_json_bytes"],memlimit=1024*1024))
 oversized=dict(outer);oversized["inner_json_bytes"]=codec.MAX_INNER_BYTES+1;oversize=reject("oversized_declared_inner",lambda:codec.unpack(codec.canonical(oversized)))
 rawlarge=dict(outer);rawlarge["original_gzip_bytes"]=codec.PART_RAW_LIMIT+1;rawoversize=reject("oversized_declared_raw",lambda:codec.unpack(codec.canonical(rawlarge)))
 with tempfile.TemporaryDirectory() as td:
  root=Path(td);destination=root/"destination";outside=root/"outside";outside.mkdir();destination.mkdir();(destination/"complete_periods").symlink_to(outside,target_is_directory=True)
  symlink=reject("symlink_parent",lambda:codec.restore(envelopes[0],destination))
  assert not (outside/"smt").exists()
 return {"identity":"ASTRA","target_evaluated":False,"synthetic_only":True,"configuration":{"production_part_original_gzip_limit":codec.PART_RAW_LIMIT,"xz_preset":6,"schema":codec.SCHEMA},"multipart":{"input_records":len(records),"parts":len(envelopes),"exact_record_roundtrip":True,"part_sha256":[hashlib.sha256(x).hexdigest() for x in envelopes],"first_restore_written":len(records),"second_restore_verified_identical":len(records)},"rejections":[corruption,truncation,trailing_result,duplicate,pathbad,outer_noncanonical,memory,oversize,rawoversize,symlink,overwrite],"source_hashes":{"codec.py":sha(HERE/"codec.py"),"codec_controls.py":sha(Path(__file__))},"assertions":{"all_passed":True,"multipart":len(envelopes)>=2,"all_records_exact":restored==records,"all_eleven_negative_cases":len({corruption,truncation,trailing_result,duplicate,pathbad,outer_noncanonical,memory,oversize,rawoversize,symlink,overwrite})==11}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--regenerate",type=Path);a=ap.parse_args();got=build()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit(f"refusing existing output: {a.regenerate}")
  a.regenerate.write_text(canonical(got));print(json.dumps({"identity":"ASTRA","output":str(a.regenerate),"sha256":sha(a.regenerate)}));return
 assert got==json.loads(OUT.read_text());print(json.dumps({"identity":"ASTRA","verified":True,"ledger_sha256":sha(OUT),"multipart_parts":got["multipart"]["parts"],"negative_cases":11}))
if __name__=="__main__":main()

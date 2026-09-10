#!/usr/bin/env python3
"""Deterministic bounded xz(JSON/base64) transport for exact gzip records."""
from __future__ import annotations
import base64,binascii,hashlib,json,lzma,re
from pathlib import Path
IDENTITY="ASTRA";SCHEMA="astra-exact-gzip-xz-json-v1";PART_RAW_LIMIT=8*1024*1024;MAX_FILE_BYTES=PART_RAW_LIMIT;MAX_INNER_BYTES=12*1024*1024;MAX_COMPRESSED_BYTES=12*1024*1024;MAX_DECOMPRESS_MEMORY=128*1024*1024
PATH_RE=re.compile(r"complete_periods/smt/(?:forward|reverse|byte_reverse|nibble_swap)_p[1-9][0-9]*[.]smt2[.]gz")
def sha(data):return hashlib.sha256(data).hexdigest()
def canonical(value):return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def safe_path(name):
 if not isinstance(name,str) or not PATH_RE.fullmatch(name):raise ValueError("unsafe or noncanonical record path")
 p=Path(name)
 if p.is_absolute() or ".." in p.parts or "." in p.parts:raise ValueError("unsafe record path")
 return p
def normalize_records(records,max_file_bytes=MAX_FILE_BYTES):
 out=[];seen=set()
 for name,data in records:
  safe_path(name)
  if name in seen:raise ValueError("duplicate record path")
  seen.add(name)
  if not isinstance(data,bytes) or len(data)>max_file_bytes:raise ValueError("invalid/oversize record")
  out.append((name,data))
 if not out:raise ValueError("empty records")
 if [x[0] for x in out]!=sorted(x[0] for x in out):raise ValueError("records must be lexicographically sorted")
 return out
def partition(records,raw_limit=PART_RAW_LIMIT,max_file_bytes=MAX_FILE_BYTES):
 if not 0<raw_limit<=PART_RAW_LIMIT:raise ValueError("invalid part raw limit")
 rows=normalize_records(records,max_file_bytes);parts=[];current=[];size=0
 for row in rows:
  if len(row[1])>raw_limit:raise ValueError("record exceeds part raw limit")
  if current and size+len(row[1])>raw_limit:parts.append(current);current=[];size=0
  current.append(row);size+=len(row[1])
 if current:parts.append(current)
 return parts
def inner_object(rows):
 records=[{"path":name,"gzip_bytes":len(data),"gzip_sha256":sha(data),"gzip_base64":base64.b64encode(data).decode("ascii")} for name,data in rows]
 return {"identity":IDENTITY,"schema":SCHEMA,"records":records}
def pack(records,raw_limit=PART_RAW_LIMIT):
 parts=partition(records,raw_limit);result=[];total=len(parts)
 for index,rows in enumerate(parts,1):
  inner=canonical(inner_object(rows))
  if len(inner)>MAX_INNER_BYTES:raise ValueError("inner JSON exceeds bound")
  compressed=lzma.compress(inner,format=lzma.FORMAT_XZ,preset=6)
  if len(compressed)>MAX_COMPRESSED_BYTES:raise ValueError("compressed part exceeds bound")
  manifest=[{"path":name,"gzip_bytes":len(data),"gzip_sha256":sha(data)} for name,data in rows]
  outer={"identity":IDENTITY,"schema":SCHEMA,"part_id":f"part-{index:04d}-of-{total:04d}","part_index":index,"part_count":total,"record_count":len(rows),"original_gzip_bytes":sum(len(x[1]) for x in rows),"inner_json_bytes":len(inner),"inner_json_sha256":sha(inner),"compressed_xz_bytes":len(compressed),"compressed_xz_sha256":sha(compressed),"records":manifest,"compressed_xz_base64":base64.b64encode(compressed).decode("ascii")}
  result.append(canonical(outer))
 return result
def bounded_xz(compressed,expected,max_inner=MAX_INNER_BYTES,memlimit=MAX_DECOMPRESS_MEMORY):
 if not 0<=expected<=max_inner or len(compressed)>MAX_COMPRESSED_BYTES:raise ValueError("declared size outside bound")
 if not 0<memlimit<=MAX_DECOMPRESS_MEMORY:raise ValueError("invalid decoder memory limit")
 dec=lzma.LZMADecompressor(format=lzma.FORMAT_XZ,memlimit=memlimit);raw=dec.decompress(compressed,max_length=expected+1)
 if len(raw)!=expected or not dec.eof or dec.unused_data:raise ValueError("truncated, oversized, or trailing xz stream")
 return raw
def unpack(envelope,max_file_bytes=MAX_FILE_BYTES):
 if not isinstance(envelope,bytes) or len(envelope)>20*1024*1024:raise ValueError("outer envelope must be bounded bytes")
 outer=json.loads(envelope)
 if canonical(outer)!=envelope:raise ValueError("noncanonical outer JSON")
 if outer.get("identity")!=IDENTITY or outer.get("schema")!=SCHEMA:raise ValueError("wrong identity/schema")
 required={"identity","schema","part_id","part_index","part_count","record_count","original_gzip_bytes","inner_json_bytes","inner_json_sha256","compressed_xz_bytes","compressed_xz_sha256","records","compressed_xz_base64"}
 if set(outer)!=required:raise ValueError("unexpected outer fields")
 if outer["part_id"]!=f"part-{outer['part_index']:04d}-of-{outer['part_count']:04d}" or not 1<=outer["part_index"]<=outer["part_count"]:raise ValueError("bad part id")
 if not 0<=outer["original_gzip_bytes"]<=PART_RAW_LIMIT:raise ValueError("declared original bytes outside part bound")
 try:compressed=base64.b64decode(outer["compressed_xz_base64"],validate=True)
 except (binascii.Error,ValueError):raise ValueError("invalid base64")
 if len(compressed)!=outer["compressed_xz_bytes"] or sha(compressed)!=outer["compressed_xz_sha256"]:raise ValueError("compressed length/hash mismatch")
 inner_bytes=bounded_xz(compressed,outer["inner_json_bytes"])
 if sha(inner_bytes)!=outer["inner_json_sha256"]:raise ValueError("inner hash mismatch")
 inner=json.loads(inner_bytes)
 if canonical(inner)!=inner_bytes or inner.get("identity")!=IDENTITY or inner.get("schema")!=SCHEMA or set(inner)!={"identity","schema","records"}:raise ValueError("noncanonical/wrong inner JSON")
 records=[];manifest=[];seen=set();total=0
 for row in inner["records"]:
  if set(row)!={"path","gzip_bytes","gzip_sha256","gzip_base64"}:raise ValueError("unexpected record fields")
  name=row["path"];safe_path(name)
  if name in seen:raise ValueError("duplicate record path")
  seen.add(name)
  try:data=base64.b64decode(row["gzip_base64"],validate=True)
  except (binascii.Error,ValueError):raise ValueError("invalid record base64")
  if len(data)!=row["gzip_bytes"] or len(data)>max_file_bytes or sha(data)!=row["gzip_sha256"]:raise ValueError("record length/hash/bound mismatch")
  records.append((name,data));manifest.append({"path":name,"gzip_bytes":len(data),"gzip_sha256":sha(data)});total+=len(data)
 if [x[0] for x in records]!=sorted(x[0] for x in records):raise ValueError("records not sorted")
 if total>PART_RAW_LIMIT:raise ValueError("part raw bytes exceed bound")
 if outer["records"]!=manifest or outer["record_count"]!=len(records) or outer["original_gzip_bytes"]!=total:raise ValueError("outer manifest mismatch")
 return records
def restore(envelope,destination):
 destination=Path(destination);records=unpack(envelope);written=[];identical=[]
 if destination.is_symlink():raise ValueError("symlink destination rejected")
 if destination.exists() and not destination.is_dir():raise ValueError("destination is not directory")
 destination.mkdir(parents=True,exist_ok=True)
 for name,data in records:
  relative=safe_path(name);cursor=destination
  for component in relative.parts[:-1]:
   cursor=cursor/component
   if cursor.is_symlink():raise ValueError(f"symlink path component rejected: {cursor}")
   if cursor.exists() and not cursor.is_dir():raise ValueError(f"nondirectory path component rejected: {cursor}")
   cursor.mkdir(exist_ok=True)
  target=destination/relative
  if target.is_symlink():raise ValueError(f"symlink target rejected: {target}")
  if target.exists():
   if not target.is_file() or target.read_bytes()!=data:raise FileExistsError(f"refusing nonidentical existing path: {target}")
   identical.append(str(target));continue
  with target.open("xb") as handle:handle.write(data)
  written.append(str(target))
 return {"written":written,"already_identical":identical}

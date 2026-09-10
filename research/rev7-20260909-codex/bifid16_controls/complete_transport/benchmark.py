#!/usr/bin/env python3
"""ASTRA: bounded exact-gzip transport benchmark; no solver or target evaluation."""
from __future__ import annotations
import argparse,base64,gzip,hashlib,json,lzma,struct,time
from pathlib import Path
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;SMT=PACKAGE/"complete_periods/smt";OUT=HERE/"results.json";COUNT=64
IDENTITY="ASTRA"
def sha_bytes(x):return hashlib.sha256(x).hexdigest()
def sha_file(p):return sha_bytes(Path(p).read_bytes())
def canonical(x):return (json.dumps(x,sort_keys=True,separators=(",",":"))+"\n").encode()
def timed(fn):
 t=time.perf_counter();value=fn();return value,time.perf_counter()-t
def sample():
 paths=sorted(SMT.glob("*.smt2.gz"),key=lambda p:p.name)[:COUNT];assert len(paths)==COUNT
 return paths
def exact_records(paths):
 return [{"path":str(p.relative_to(PACKAGE)),"gzip_bytes":len(raw),"gzip_sha256":sha_bytes(raw),"gzip_base64":base64.b64encode(raw).decode("ascii")} for p in paths for raw in [p.read_bytes()]]
def framed(payloads):
 out=bytearray(b"ASTRA-GZIP-RECORDS-1\n")
 for name,raw in payloads:
  nb=name.encode();out.extend(struct.pack(">IQ",len(nb),len(raw)));out.extend(nb);out.extend(raw)
 return bytes(out)
def framed_raw_smt(paths):return framed([(str(p.relative_to(PACKAGE)).removesuffix(".gz"),gzip.decompress(p.read_bytes())) for p in paths])
def build():
 paths=sample();payloads=[(str(p.relative_to(PACKAGE)),p.read_bytes()) for p in paths];records=exact_records(paths)
 json_bytes,t_json=timed(lambda:canonical({"identity":IDENTITY,"schema":"exact-gzip-json-base64-v1","records":records}))
 json_gz,t_gz=timed(lambda:gzip.compress(json_bytes,compresslevel=9,mtime=0))
 json_xz,t_xz=timed(lambda:lzma.compress(json_bytes,format=lzma.FORMAT_XZ,preset=9))
 binary=framed(payloads);binary_xz,t_bxz=timed(lambda:lzma.compress(binary,format=lzma.FORMAT_XZ,preset=9))
 raw_smt=framed_raw_smt(paths);raw_smt_xz,t_rawxz=timed(lambda:lzma.compress(raw_smt,format=lzma.FORMAT_XZ,preset=9))
 decoded=json.loads(json_bytes);restored=[(x["path"],base64.b64decode(x["gzip_base64"],validate=True)) for x in decoded["records"]]
 assert len(restored)==COUNT
 for (name,raw),(expected_name,expected) in zip(restored,payloads):assert name==expected_name and raw==expected and sha_bytes(raw)==next(x["gzip_sha256"] for x in records if x["path"]==name)
 assert gzip.decompress(json_gz)==json_bytes and lzma.decompress(json_xz)==json_bytes and lzma.decompress(binary_xz)==binary and lzma.decompress(raw_smt_xz)==raw_smt
 total=sum(len(x[1]) for x in payloads);names=[x[0] for x in payloads]
 sample_rows=[{"path":name,"gzip_bytes":len(raw),"gzip_sha256":sha_bytes(raw),"raw_smt_bytes":len(gzip.decompress(raw)),"raw_smt_sha256":sha_bytes(gzip.decompress(raw))} for name,raw in payloads]
 return {"identity":IDENTITY,"target_evaluated":False,"solver_run":False,"sample":{"selection":"first 64 lexicographically sorted existing complete_periods/smt/*.smt2.gz","count":COUNT,"paths":names,"path_list_sha256":sha_bytes(canonical(names)),"records":sample_rows,"exact_gzip_total_bytes":total},"formats":{"plain_json_base64":{"bytes":len(json_bytes),"sha256":sha_bytes(json_bytes),"build_seconds":t_json,"exact_gzip_restore":True},"gzip_json_base64":{"bytes":len(json_gz),"sha256":sha_bytes(json_gz),"compress_seconds":t_gz,"exact_gzip_restore":True},"xz_json_base64":{"bytes":len(json_xz),"sha256":sha_bytes(json_xz),"compress_seconds":t_xz,"exact_gzip_restore":True},"xz_binary_exact_records":{"bytes":len(binary_xz),"sha256":sha_bytes(binary_xz),"compress_seconds":t_bxz,"uncompressed_framed_bytes":len(binary),"exact_gzip_restore":True,"note":"smallest exact-record comparison, but requires a documented binary framing decoder"},"xz_raw_smt_framed":{"bytes":len(raw_smt_xz),"sha256":sha_bytes(raw_smt_xz),"compress_seconds":t_rawxz,"uncompressed_raw_smt_framed_bytes":len(raw_smt),"exact_gzip_restore":False,"note":"restores SMT text, not the original gzip byte records; excluded as primary transport"}},"roundtrip":{"all_64_original_gzip_bytes_exact":True,"all_outer_envelopes_decode":True},"source_hashes":{"benchmark.py":sha_file(Path(__file__))},"limits":"64-file transport benchmark only. It does not run Z3, inspect solver truth, or pack the still-running full corpus."}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--regenerate",type=Path);args=ap.parse_args();got=build()
 if args.regenerate:
  if args.regenerate.exists():raise SystemExit(f"refusing existing output: {args.regenerate}")
  args.regenerate.write_bytes(json.dumps(got,sort_keys=True,indent=2).encode()+b"\n");print(json.dumps({"identity":IDENTITY,"output":str(args.regenerate),"sha256":sha_file(args.regenerate)}));return
 frozen=json.loads(OUT.read_text())
 assert set(got)==set(frozen)
 for name in got["formats"]:
  timing="build_seconds" if "build_seconds" in got["formats"][name] else "compress_seconds"
  assert got["formats"][name].pop(timing)>=0 and frozen["formats"][name].pop(timing)>=0
 assert got==frozen
 print(json.dumps({"identity":IDENTITY,"verified":True,"ledger_sha256":sha_file(OUT),"sample_files":COUNT,"exact_restore":True,"timings_checked_nonnegative_not_exact":True}))
if __name__=="__main__":main()

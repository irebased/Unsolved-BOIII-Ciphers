#!/usr/bin/env python3
"""Tiny synthetic path/order/part-union controls for bundle wrapper."""
from __future__ import annotations
import argparse,gzip,hashlib,json,tempfile
from pathlib import Path
import bundle
HERE=Path(__file__).resolve().parent;OUT=HERE/"bundle_controls.json"
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,indent=2)+"\n"
def reject(label,fn):
 try:fn()
 except (AssertionError,ValueError,FileExistsError):return label
 raise AssertionError(f"did not reject {label}")
def build():
 with tempfile.TemporaryDirectory() as td:
  root=Path(td);smt=root/"smt";smt.mkdir();rows=[];cells=[]
  orientations=("forward","reverse","byte_reverse","nibble_swap")
  for i in range(bundle.EXPECTED):
   orient=orientations[i%4];period=i//4+1;name=f"{orient}_p{period}.smt2.gz";raw=(f"(set-info :source ASTRA-{i})\n"*(1+i%3)).encode();data=gzip.compress(raw,compresslevel=9,mtime=0);(smt/name).write_bytes(data);relative="complete_periods/smt/"+name;dump={"path":"smt/"+name,"gzip_bytes":len(data),"gzip_sha256":hashlib.sha256(data).hexdigest(),"smt2_sha256":hashlib.sha256(raw).hexdigest()};cell={"cell_id":f"synthetic_{i}","smt_dump":dump};cells.append(cell);rows.append(relative)
  checkpoint=root/"checkpoint.jsonl";checkpoint.write_text("".join(json.dumps(x,sort_keys=True,separators=(",",":"))+"\n" for x in cells));result=root/"result.json";result.write_text(json.dumps({"identity":"ASTRA","target_evaluated":True,"status":"complete","checkpoint_sha256":sha(checkpoint),"cells":cells},sort_keys=True,indent=2)+"\n")
  package=root/"package";manifest,mp=bundle.build_package(package,None,result,checkpoint,smt,raw_limit=4096);verified=bundle.verify_package(package,None,result,checkpoint)
  assert verified["records"]==bundle.EXPECTED and manifest["record_count"]==bundle.EXPECTED and len({p for part in manifest["parts"] for p in part["record_paths"]})==bundle.EXPECTED
  assert [p for part in manifest["parts"] for p in part["record_paths"]]==sorted(rows)
  destination=root/"restore";restored_package=bundle.restore_package(package,destination,None,result,checkpoint);assert restored_package["written"]==bundle.EXPECTED
  for relative in rows:assert (destination/relative).read_bytes()==(smt/Path(relative).name).read_bytes()
  manifest_path=package/"manifest.json";good_manifest=manifest_path.read_bytes();good=json.loads(good_manifest);first=good["parts"][0];first_path=package/first["file"];first_payload=first_path.read_bytes()
  def test_manifest(label,mutate):
   value=json.loads(good_manifest);mutate(value);manifest_path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
   outcome=reject(label,lambda:bundle.verify_package(package,None,result,checkpoint));manifest_path.write_bytes(good_manifest);return outcome
  order_rejected=test_manifest("reversed_part_order",lambda x:x.update(parts=list(reversed(x["parts"]))))
  malformed=test_manifest("malformed_part_filename",lambda x:x["parts"][0].update(file="../escape.json"))
  bad_count=test_manifest("manifest_record_count_mismatch",lambda x:x["parts"][0].update(record_count=x["parts"][0]["record_count"]+1))
  bad_bytes=test_manifest("manifest_original_bytes_mismatch",lambda x:x["parts"][0].update(original_gzip_bytes=x["parts"][0]["original_gzip_bytes"]+1))
  bad_limit=test_manifest("invalid_partition_limit",lambda x:x.update(partition_original_gzip_limit=0))
  with first_path.open("wb") as f:f.truncate(bundle.MAX_ENVELOPE_BYTES+1)
  oversized=reject("oversized_part_file",lambda:bundle.verify_package(package,None,result,checkpoint));first_path.write_bytes(first_payload)
  rejections=[order_rejected,malformed,bad_count,bad_bytes,bad_limit,oversized]

 return {"identity":"ASTRA","target_evaluated":False,"synthetic_only":True,"records":bundle.EXPECTED,"parts":manifest["part_count"],"exact_order_and_union":True,"exact_restore":True,"restore_package_entrypoint":True,"rejections":rejections,"source_hashes":{"bundle.py":sha(HERE/"bundle.py"),"bundle_controls.py":sha(Path(__file__)),"codec.py":sha(HERE/"codec.py"),"codec_controls.json":sha(HERE/"codec_controls.json")},"assertions":{"all_passed":True,"exact_2175_record_set":True,"unique_paths":True,"ordered_parts":True,"six_manifest_and_file_rejections":len(set(rejections))==6}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--regenerate",type=Path);a=ap.parse_args();got=build()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit(f"refusing existing output: {a.regenerate}")
  a.regenerate.write_text(canonical(got));print(json.dumps({"identity":"ASTRA","output":str(a.regenerate),"sha256":sha(a.regenerate)}));return
 assert got==json.loads(OUT.read_text());print(json.dumps({"identity":"ASTRA","verified":True,"ledger_sha256":sha(OUT),"records":bundle.EXPECTED,"parts":got["parts"]}))
if __name__=="__main__":main()

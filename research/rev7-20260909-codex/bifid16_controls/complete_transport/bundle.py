#!/usr/bin/env python3
"""Gate-locked full-corpus exact-record bundle wrapper; no solver calls."""
from __future__ import annotations
import argparse,gzip,hashlib,json,os,sys,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;REPO=HERE.parents[3]
sys.path.insert(0,str(HERE));import codec
GATE=HERE/"pack_gate.json";RESULT=PACKAGE/"complete_periods/target_results.json";CHECKPOINT=PACKAGE/"complete_periods/checkpoint.jsonl";SMT=PACKAGE/"complete_periods/smt";EXPECTED=2175;MAX_RAW_SMT=10_000_000
IDENTITY="ASTRA";MANIFEST_SCHEMA="astra-complete-periods-bundle-v1";MAX_ENVELOPE_BYTES=20*1024*1024
REQUIRED_GATE_ARTIFACTS={"research/rev7-20260909-codex/bifid16_controls/complete_transport/bundle.py","research/rev7-20260909-codex/bifid16_controls/complete_transport/bundle_controls.py","research/rev7-20260909-codex/bifid16_controls/complete_transport/bundle_controls.json","research/rev7-20260909-codex/bifid16_controls/complete_transport/codec.py","research/rev7-20260909-codex/bifid16_controls/complete_transport/codec_controls.py","research/rev7-20260909-codex/bifid16_controls/complete_transport/codec_controls.json","research/rev7-20260909-codex/bifid16_controls/complete_periods/verify_results.py"}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def sha_bytes(x):return hashlib.sha256(x).hexdigest()
def canonical(x):return (json.dumps(x,sort_keys=True,separators=(",",":"))+"\n").encode()
def require_gate():
 if not GATE.exists():raise SystemExit("inert: root-created pack_gate.json is absent")
 g=json.loads(GATE.read_text());assert g["identity"]==IDENTITY and g["pack_authorized"] is True
 assert g["target_result_sha256"]==sha(RESULT)=="736a34aed38826a8c1a1bf5e4fcd24d6f4aad817a435f2e09384fe493d4d35d6"
 assert g["checkpoint_sha256"]==sha(CHECKPOINT)
 assert set(g["artifact_hashes"])==set(g["required_artifacts"]) and REQUIRED_GATE_ARTIFACTS<=set(g["artifact_hashes"])
 for rel,digest in g["artifact_hashes"].items():assert sha(REPO/rel)==digest,rel
 receipt=REPO/g["verification_receipt_path"];assert sha(receipt)==g["verification_receipt_sha256"]
 vr=json.loads(receipt.read_text());assert vr["identity"]==IDENTITY and vr["ok"] is True and vr["verification_only"] is True and vr["new_target_search"] is False and vr["complete_cells"]==EXPECTED and vr["formulas_reconstructed"]==EXPECTED and vr["result_sha256"]==g["target_result_sha256"]
 return g
def bounded_gzip(data):
 dec=zlib.decompressobj(16+zlib.MAX_WBITS);raw=dec.decompress(data,MAX_RAW_SMT+1)
 if len(raw)>MAX_RAW_SMT or not dec.eof or dec.unused_data or dec.unconsumed_tail:raise ValueError("invalid, trailing, or oversized gzip record")
 return raw
def expected_rows(result_path=RESULT,checkpoint_path=CHECKPOINT):
 result=json.loads(Path(result_path).read_text());assert result["identity"]==IDENTITY and result["target_evaluated"] is True and result["status"]=="complete" and len(result["cells"])==EXPECTED
 assert result["checkpoint_sha256"]==sha(checkpoint_path)
 checkpoint=[json.loads(x) for x in Path(checkpoint_path).read_text().splitlines()];assert checkpoint==result["cells"]
 rows=[];seen=set()
 for cell in result["cells"]:
  dump=cell["smt_dump"];relative="complete_periods/"+dump["path"];codec.safe_path(relative)
  if relative in seen:raise ValueError("duplicate result formula path")
  seen.add(relative);rows.append({"cell_id":cell["cell_id"],"path":relative,"gzip_bytes":dump["gzip_bytes"],"gzip_sha256":dump["gzip_sha256"],"raw_smt_sha256":dump["smt2_sha256"]})
 assert len(rows)==EXPECTED
 rows.sort(key=lambda x:x["path"])
 return result,rows
def collect_records(rows,smt_dir=SMT):
 smt_dir=Path(smt_dir);actual={"complete_periods/smt/"+p.name for p in smt_dir.glob("*.smt2.gz")};expected={x["path"] for x in rows};assert actual==expected
 records=[];details=[]
 for row in rows:
  path=smt_dir/Path(row["path"]).name;data=path.read_bytes();assert len(data)==row["gzip_bytes"] and sha_bytes(data)==row["gzip_sha256"]
  raw=bounded_gzip(data);assert sha_bytes(raw)==row["raw_smt_sha256"]
  records.append((row["path"],data));details.append({**row,"raw_smt_bytes":len(raw)})
 return records,details
def build_package(output_dir,gate=None,result_path=RESULT,checkpoint_path=CHECKPOINT,smt_dir=SMT,raw_limit=codec.PART_RAW_LIMIT):
 output_dir=Path(output_dir)
 if output_dir.exists():raise FileExistsError(f"refusing existing output directory: {output_dir}")
 result,rows=expected_rows(result_path,checkpoint_path);records,details=collect_records(rows,smt_dir);parts=codec.pack(records,raw_limit=raw_limit);output_dir.mkdir(parents=True)
 part_rows=[]
 for payload in parts:
  outer=json.loads(payload);name=outer["part_id"]+".json";path=output_dir/name
  with path.open("xb") as f:f.write(payload)
  part_rows.append({"file":name,"bytes":len(payload),"sha256":sha_bytes(payload),"part_id":outer["part_id"],"record_count":outer["record_count"],"original_gzip_bytes":outer["original_gzip_bytes"],"record_paths":[x["path"] for x in outer["records"]]})
 provenance={"target_result_sha256":sha(result_path),"checkpoint_sha256":sha(checkpoint_path)}
 if gate is not None:provenance.update({"pack_gate_sha256":sha(GATE),"verification_receipt_path":gate["verification_receipt_path"],"verification_receipt_sha256":gate["verification_receipt_sha256"]})
 manifest={"identity":IDENTITY,"schema":MANIFEST_SCHEMA,"record_count":EXPECTED,"part_count":len(parts),"partition_original_gzip_limit":raw_limit,"provenance":provenance,"parts":part_rows,"records":details,"record_path_list_sha256":sha_bytes(canonical([x["path"] for x in details]))}
 mp=output_dir/"manifest.json";mp.write_bytes(json.dumps(manifest,sort_keys=True,indent=2).encode()+b"\n");return manifest,mp
def verify_package(package_dir,gate=None,result_path=RESULT,checkpoint_path=CHECKPOINT):
 package_dir=Path(package_dir);mp=package_dir/"manifest.json";manifest=json.loads(mp.read_text());assert manifest["identity"]==IDENTITY and manifest["schema"]==MANIFEST_SCHEMA and manifest["record_count"]==EXPECTED
 assert isinstance(manifest["partition_original_gzip_limit"],int) and 0<manifest["partition_original_gzip_limit"]<=codec.PART_RAW_LIMIT
 result,expected=expected_rows(result_path,checkpoint_path);assert manifest["provenance"]["target_result_sha256"]==sha(result_path) and manifest["provenance"]["checkpoint_sha256"]==sha(checkpoint_path)
 if gate is not None:assert manifest["provenance"]["pack_gate_sha256"]==sha(GATE) and manifest["provenance"]["verification_receipt_sha256"]==gate["verification_receipt_sha256"]
 assert manifest["part_count"]==len(manifest["parts"])
 restored=[];part_ids=[]
 for index,part in enumerate(manifest["parts"],1):
  expected_id=f"part-{index:04d}-of-{manifest['part_count']:04d}";expected_file=expected_id+".json"
  assert part["part_id"]==expected_id and part["file"]==expected_file
  path=package_dir/expected_file;assert path.is_file() and not path.is_symlink() and path.stat().st_size<=MAX_ENVELOPE_BYTES
  payload=path.read_bytes();assert len(payload)==part["bytes"] and sha_bytes(payload)==part["sha256"]
  outer=json.loads(payload);assert outer["part_index"]==index and outer["part_count"]==manifest["part_count"] and outer["part_id"]==part["part_id"] and part["file"]==outer["part_id"]+".json" and part["record_paths"]==[x["path"] for x in outer["records"]]
  assert part["record_count"]==outer["record_count"]==len(part["record_paths"])
  assert part["original_gzip_bytes"]==outer["original_gzip_bytes"]<=manifest["partition_original_gzip_limit"]
  part_ids.append(outer["part_id"]);restored.extend(codec.unpack(payload))
 assert len(set(part_ids))==len(part_ids)==manifest["part_count"] and len(restored)==EXPECTED and len({x[0] for x in restored})==EXPECTED
 by={x["path"]:x for x in expected};assert [x[0] for x in restored]==[x["path"] for x in expected] and manifest["record_path_list_sha256"]==sha_bytes(canonical([x[0] for x in restored]))
 details=[]
 for name,data in restored:
  row=by[name];assert len(data)==row["gzip_bytes"] and sha_bytes(data)==row["gzip_sha256"];raw=bounded_gzip(data);assert sha_bytes(raw)==row["raw_smt_sha256"];details.append({**row,"raw_smt_bytes":len(raw)})
 assert manifest["records"]==details
 return {"identity":IDENTITY,"verified":True,"parts":len(part_ids),"records":len(restored),"manifest_sha256":sha(mp)}
def restore_package(package_dir,destination,gate=None,result_path=RESULT,checkpoint_path=CHECKPOINT):
 verify_package(package_dir,gate,result_path,checkpoint_path);written=identical=0
 manifest=json.loads((Path(package_dir)/"manifest.json").read_text())
 for part in manifest["parts"]:
  result=codec.restore((Path(package_dir)/part["file"]).read_bytes(),destination);written+=len(result["written"]);identical+=len(result["already_identical"])
 return {"identity":IDENTITY,"written":written,"already_identical":identical}
def main():
 ap=argparse.ArgumentParser();g=ap.add_mutually_exclusive_group(required=True);g.add_argument("--pack",type=Path);g.add_argument("--verify",type=Path);g.add_argument("--restore",nargs=2,metavar=("PACKAGE_DIR","DESTINATION"));a=ap.parse_args();gate=require_gate()
 if a.pack:
  manifest,mp=build_package(a.pack,gate);print(json.dumps({"identity":IDENTITY,"parts":manifest["part_count"],"records":manifest["record_count"],"manifest_sha256":sha(mp)}))
 elif a.verify:print(json.dumps(verify_package(a.verify,gate),sort_keys=True))
 else:print(json.dumps(restore_package(Path(a.restore[0]),Path(a.restore[1]),gate),sort_keys=True))
if __name__=="__main__":main()

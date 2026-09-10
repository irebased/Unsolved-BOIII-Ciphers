#!/usr/bin/env python3
"""Inert gated driver for valid-permutation character-AMSCO plus RFC 3629 CFB8 suffix filtering."""
from __future__ import annotations
import argparse,hashlib,importlib.util,itertools,json,math,os,platform,sys,tempfile,time
from pathlib import Path

HERE=Path(__file__).resolve().parent
PACKAGE=HERE.parent
ASTRA=PACKAGE.parent
ROOT=HERE.parents[4]
CORE_PATH=PACKAGE/"core.py"
CONTROLS_PATH=PACKAGE/"controls.py"
LEDGER_PATH=PACKAGE/"controls.json"
GEOM_PATH=ASTRA/"amsco_geometry.py"
MDX=ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
DATASET=ROOT/"lavender/src/data/ciphers/revelations.json"
GATE=HERE/"target_gate.json"
MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
DATASET_SHA="68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e"
TEXT_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
BACKENDS=("aes128","des","blowfish","bfcompat","rc2","twofish","loki97","rijndael256_key16","rijndael256_key24","rijndael256_key32")
ORIENTATIONS=("forward","full_hex_reverse","byte_reverse","nibble_swap")
WIDTHS=tuple(range(2,10))
START="21"
ARTIFACTS={
 "utf8_search/core.py":CORE_PATH,
 "utf8_search/controls.py":CONTROLS_PATH,
 "utf8_search/controls.json":LEDGER_PATH,
 "utf8_search/README.md":PACKAGE/"README.md",
 "utf8_search/REPORT.md":PACKAGE/"REPORT.md",
 "target/README.md":HERE/"README.md",
 "target/driver_controls.py":HERE/"driver_controls.py",
 "target/driver_controls.json":HERE/"driver_controls.json",
 "target/prepare_gate.py":HERE/"prepare_gate.py",
}

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;assert spec.loader;spec.loader.exec_module(module);return module

def scope():
 orders=sum(math.factorial(w) for w in WIDTHS)*len(ORIENTATIONS)
 return {
  "identity":"ASTRA","unit":"hex characters interpreted as byte pairs after inverse character AMSCO",
  "valid_php_key_model":"permutations only","widths":list(WIDTHS),"start":START,
  "orientations":list(ORIENTATIONS),"backends":list(BACKENDS),
  "column_orders":orders,"backend_contexts":orders*len(BACKENDS),
  "mode":"CFB8","keys_and_block_conventions":"exactly those pinned by utf8_search controls",
  "external_iv":"arbitrary and unsearched; tested suffix begins at each backend block size",
  "endpoint":"RFC 3629 Unicode scalar UTF-8; ASCII 00..7F accepted; initial states boundary/remain1/remain2/remain3; true terminal boundary",
  "enumeration":"every width! permutation in lexicographic order; no cap",
  "cells":len(WIDTHS)*len(ORIENTATIONS),
  "negative_storage":"complete row-stream SHA256, complete first-witness SHA256 and reason counts, first/last row",
  "survivors":"retain every order/backend/full suffix and independently gather/decrypt/re-encrypt under two IVs",
  "checkpoint":"atomic after each complete cell; existing result or checkpoint refused",
 }

def frozen_sources(controls):
 paths,_=controls.verify_sources();ledger=json.loads(LEDGER_PATH.read_text())
 assert ledger["identity"]=="ASTRA" and ledger["target_evaluated"] is False and ledger["rev7_read"] is False
 assert ledger["source_hashes"]["core.py"]==sha(CORE_PATH)
 assert ledger["source_hashes"]["controls.py"]==sha(CONTROLS_PATH)
 for label,path in paths.items():assert ledger["source_hashes"][label]==sha(path),(label,sha(path))
 return ledger

def require_gate():
 if not GATE.exists():raise RuntimeError("target gate absent; target execution is not authorized")
 gate=json.loads(GATE.read_text());assert gate["identity"]=="ASTRA" and gate["target_evaluated"] is False
 assert gate["authorization"]=="FABLE preregistration plus separate root GO required"
 assert isinstance(gate.get("fable_reference"),str) and gate["fable_reference"].strip()
 assert gate["scope"]==scope() and gate["driver_sha256"]==sha(Path(__file__))
 assert gate["mdx_sha256"]==MDX_SHA and gate["dataset_sha256"]==DATASET_SHA and gate["canonical_text_sha256"]==TEXT_SHA
 assert gate["artifact_hashes"]=={label:sha(path) for label,path in ARTIFACTS.items()}
 controls=load("astra_utf8_target_controls_dependency",CONTROLS_PATH);ledger=frozen_sources(controls)
 assert gate["controlled_source_hashes"]==ledger["source_hashes"]
 assert sha(MDX)==MDX_SHA and sha(DATASET)==DATASET_SHA
 return gate,sha(GATE),controls

def normalize_hex(value):return "".join(value.split()).upper()

def extract_canonical():
 mdx=MDX.read_text();a=mdx.index("`83 B57B2")+1;b=mdx.index("`",a);from_mdx=normalize_hex(mdx[a:b])
 records=json.loads(DATASET.read_text());row=next(x for x in records if x.get("id")=="rev7");from_dataset=normalize_hex(row["ciphertext"])
 assert from_mdx==from_dataset and len(from_mdx)==1092
 assert all(c in "0123456789ABCDEF" for c in from_mdx)
 assert hashlib.sha256(from_mdx.encode()).hexdigest()==TEXT_SHA
 return from_mdx,hashlib.sha256(row["ciphertext"].encode()).hexdigest()

def orient(geometry,text,name):return geometry.orientations(text)[name]

def iv_for(backend,suite):
 return bytes((suite*83+len(backend.name)*17+i*29)&255 for i in range(backend.block_size))

def replay_survivor(row,processed,canonical,orientation,width,objects,geometry,controls):
 order=tuple(row["order"]);natural="".join(geometry.inverse(list(processed),order,START,len(processed)))
 rebuilt="".join(geometry.forward(list(natural),order,START)[0])
 assert rebuilt==processed and orient(geometry,processed,orientation)==canonical
 cipher=bytes.fromhex(natural);out=[]
 retained={x["backend"]:x for x in row["retained"]}
 for name in sorted(retained):
  backend=objects[name];saved=retained[name];suffix=bytes.fromhex(saved["suffix_hex"])
  assert saved["suffix_offset"]==backend.block_size and len(suffix)==len(cipher)-backend.block_size
  assert controls.cut_oracle(suffix)
  suites=[]
  for suite in (1,2):
   iv=iv_for(backend,suite);plain=backend.decrypt_cfb8(cipher,iv)
   assert plain[backend.block_size:]==suffix
   assert backend.encrypt_cfb8(plain,iv)==cipher
   suites.append({"suite":suite,"iv_hex":iv.hex(),"full_plaintext_sha256":hashlib.sha256(plain).hexdigest(),"suffix_exact":True,"reencryption_exact":True})
  out.append({"backend":name,"suffix_offset":backend.block_size,"suffix_sha256":hashlib.sha256(suffix).hexdigest(),"independent_builtin_utf8_cut_oracle":True,"two_iv_replays":suites})
 assert len(out)==len(row["retained"])
 return {"order":list(order),"natural_ciphertext_sha256":hashlib.sha256(cipher).hexdigest(),"display_reconstruction_exact":True,"canonical_orientation_reconstruction_exact":True,"retained":out}

def scan_cell(core,geometry,processed,canonical,orientation,width,objects,controls,order_limit=None):
 layout=core.IndexedLayout.compile(len(processed),width,START,geometry);search=core.Search(layout,processed,objects)
 total=math.factorial(width);limit=total if order_limit is None else min(order_limit,total)
 row_digest=hashlib.sha256();witness_digest=hashlib.sha256();reasons={};survivor_rows=[];replays=[];first=last=None
 totals={"orders":0,"contexts":0,"gathered_ciphertext_bytes":0,"block_callbacks":0,"rejected":0,"retained":0}
 began=time.perf_counter()
 for order in itertools.islice(itertools.permutations(range(width)),limit):
  row=search.evaluate_order(order);encoded=json.dumps(row,sort_keys=True,separators=(",",":")).encode()+b"\n";row_digest.update(encoded)
  if first is None:first=row
  last=row;totals["orders"]+=1;totals["contexts"]+=row["contexts"];totals["gathered_ciphertext_bytes"]+=row["gathered_ciphertext_bytes"];totals["block_callbacks"]+=row["block_callbacks"];totals["rejected"]+=row["rejected"];totals["retained"]+=len(row["retained"])
  for name,witness in row["rejection_witnesses"].items():
   witness_digest.update(json.dumps([list(order),name,witness],sort_keys=True,separators=(",",":")).encode()+b"\n")
   reasons[witness["reason"]]=reasons.get(witness["reason"],0)+1
  if row["retained"]:
   survivor_rows.append(row)
   replays.append(replay_survivor(row,processed,canonical,orientation,width,objects,geometry,controls))
 elapsed=time.perf_counter()-began
 assert totals["orders"]==limit and totals["contexts"]==limit*len(objects)
 assert totals["rejected"]+totals["retained"]==totals["contexts"]
 return {
  "identity":"ASTRA","cell_id":orientation+"|w"+str(width),"orientation":orientation,"width":width,"start":START,
  "observed_sha256":hashlib.sha256(processed.encode()).hexdigest(),
  "orders_examined":limit,"expected_orders":total,"unexamined_orders":total-limit,
  "backend_contexts_examined":totals["contexts"],"expected_backend_contexts":total*len(objects),
  "unexamined_backend_contexts":(total-limit)*len(objects),"complete_uncapped":limit==total,
  "totals":totals,"order_rows_ndjson_sha256":row_digest.hexdigest(),
  "first_witness_rows_ndjson_sha256":witness_digest.hexdigest(),"rejection_reason_counts":dict(sorted(reasons.items())),
  "first_row":first,"last_row":last,"survivor_order_rows":survivor_rows,
  "independent_survivor_replays":replays,"elapsed_seconds":elapsed,
 }

def normalized_build(command,existing,rlib,temp):
 def norm(value):
  if isinstance(value,dict):return {k:norm(v) for k,v in value.items()}
  if isinstance(value,list):return [norm(v) for v in value]
  return value.replace(str(temp.resolve()),"<TEMP>").replace(str(temp),"<TEMP>") if isinstance(value,str) else value
 return {"rijndael256":{"command":norm(command),"binary_sha256":sha(rlib)}, "cascade":norm(existing)}

def atomic(path,value):
 tmp=path.with_name(path.name+".tmp")
 if tmp.exists():raise RuntimeError("refusing stale temporary "+str(tmp))
 with tmp.open("x") as handle:json.dump(value,handle,indent=2,sort_keys=True);handle.write("\n")
 os.replace(tmp,path)

def run(output,checkpoint):
 if output.exists() or checkpoint.exists():raise SystemExit("refusing existing output or checkpoint")
 gate,gate_sha,controls=require_gate();core=load("astra_utf8_target_core",CORE_PATH);geometry=load("astra_utf8_target_geometry",GEOM_PATH)
 canonical,dataset_field_sha=extract_canonical();oriented={name:orient(geometry,canonical,name) for name in ORIENTATIONS}
 with tempfile.TemporaryDirectory(prefix="astra-utf8-target-") as td:
  temp=Path(td);objects,command,existing,rlib=controls.build_registry(temp);assert tuple(objects)==BACKENDS
  result={"identity":"ASTRA","target_evaluated":True,"status":"running","configuration":{"scope":scope(),"gate_sha256":gate_sha,"driver_sha256":sha(Path(__file__)),"mdx_sha256":MDX_SHA,"dataset_sha256":DATASET_SHA,"dataset_ciphertext_field_sha256":dataset_field_sha,"canonical_text_sha256":TEXT_SHA,"artifact_hashes":gate["artifact_hashes"],"controlled_source_hashes":gate["controlled_source_hashes"],"build":normalized_build(command,existing,rlib,temp),"python":platform.python_version()},"cells":[]}
  for orientation in ORIENTATIONS:
   for width in WIDTHS:
    cell=scan_cell(core,geometry,oriented[orientation],canonical,orientation,width,objects,controls)
    assert cell["complete_uncapped"] and cell["unexamined_orders"]==cell["unexamined_backend_contexts"]==0
    result["cells"].append(cell);atomic(checkpoint,result)
    print(json.dumps({"identity":"ASTRA","cells_complete":len(result["cells"]),"cell_id":cell["cell_id"],"orders":cell["orders_examined"],"contexts":cell["backend_contexts_examined"],"retained":cell["totals"]["retained"],"elapsed_seconds":cell["elapsed_seconds"]}),flush=True)
  expected_orders=scope()["column_orders"];expected_contexts=scope()["backend_contexts"]
  assert len(result["cells"])==32 and len({x["cell_id"] for x in result["cells"]})==32
  assert sum(x["orders_examined"] for x in result["cells"])==expected_orders
  assert sum(x["backend_contexts_examined"] for x in result["cells"])==expected_contexts
  reasons={}
  for cell in result["cells"]:
   for reason,count in cell["rejection_reason_counts"].items():reasons[reason]=reasons.get(reason,0)+count
  result["status"]="complete";result["summary"]={"cells":32,"orders_examined":expected_orders,"backend_contexts_examined":expected_contexts,"unexamined_orders":0,"unexamined_backend_contexts":0,"retained_contexts":sum(x["totals"]["retained"] for x in result["cells"]),"rejected_contexts":sum(x["totals"]["rejected"] for x in result["cells"]),"block_callbacks":sum(x["totals"]["block_callbacks"] for x in result["cells"]),"gathered_ciphertext_bytes":sum(x["totals"]["gathered_ciphertext_bytes"] for x in result["cells"]),"rejection_reason_counts":dict(sorted(reasons.items())),"all_complete_uncapped":True,"all_survivors_independently_replayed":all(len(x["survivor_order_rows"])==len(x["independent_survivor_replays"]) for x in result["cells"])}
  atomic(checkpoint,result);os.replace(checkpoint,output)
  print(json.dumps({"identity":"ASTRA","output":str(output),"sha256":sha(output),"summary":result["summary"]},indent=2))

def selftest():
 assert sha(MDX)==MDX_SHA and sha(DATASET)==DATASET_SHA
 controls=load("astra_utf8_selftest_controls",CONTROLS_PATH);frozen_sources(controls)
 assert scope()["column_orders"]==1636448 and scope()["backend_contexts"]==16364480
 ids={o+"|w"+str(w) for o in ORIENTATIONS for w in WIDTHS};assert len(ids)==32
 if GATE.exists():require_gate()
 print(json.dumps({"identity":"ASTRA","target_evaluated":False,"rev7_handling":"MDX and dataset file bytes hashed only; target ciphertext not extracted, parsed, oriented, inverted, decrypted, or evaluated","driver_sha256":sha(Path(__file__)),"mdx_sha256":MDX_SHA,"dataset_sha256":DATASET_SHA,"scope":scope(),"cell_ids":len(ids),"gate_present":GATE.exists()},indent=2,sort_keys=True))

def main():
 parser=argparse.ArgumentParser();mode=parser.add_mutually_exclusive_group(required=True);mode.add_argument("--selftest",action="store_true");mode.add_argument("--run-target",action="store_true");parser.add_argument("--target-output",type=Path,default=HERE/"target_results.json");parser.add_argument("--checkpoint",type=Path,default=HERE/"target_checkpoint.json");args=parser.parse_args()
 if args.selftest:selftest()
 else:run(args.target_output,args.checkpoint)
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Portable integrity/accounting verifier for the completed UTF-8 character-AMSCO ledger.

This does not repeat the 1,636,448-order target enumeration.
"""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,math,sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
RESULT=HERE/"target_results.json"
DRIVER=HERE/"run_target.py"
EXPECTED_RESULT_SHA="2687f94d8eb669fc28ab0d1f5dbd134098bc74451e8298d7a0e991cf06ee6b54"
EXPECTED_GATE_SHA="1ca44c7c13d6aaffc16f26615cf6cff3f2aa2c5a4a802f6f8b800bace7e8fbf7"
EXPECTED_DRIVER_SHA="99bf55ea5e422bd3dce7a8cd64af484399bbcf010b2064bb9d82188ec8ada45f"
EXPECTED_MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
EXPECTED_DATASET_SHA="68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e"
EXPECTED_TEXT_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
EXPECTED_DATASET_FIELD_SHA="1256ed980e4f4c3ade5fc681bdec6002650716898ef2d00f2d69e938e9420059"
ORIENTATIONS=("forward","full_hex_reverse","byte_reverse","nibble_swap")
WIDTHS=tuple(range(2,10))
REASONS={"E0_first_continuation_outside_A0_BF","ED_first_continuation_outside_80_9F_surrogate_guard","F0_first_continuation_outside_90_BF","F4_first_continuation_outside_80_8F_max_scalar_guard","lead_above_U+10FFFF_or_invalid","missing_or_invalid_continuation","overlong_lead","stray_continuation"}

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;assert spec.loader;spec.loader.exec_module(module);return module
def normalize(value):return "".join(value.split()).upper()
def canonical(driver):
 mdx=driver.MDX.read_text();a=mdx.index("`83 B57B2")+1;b=mdx.index("`",a);left=normalize(mdx[a:b])
 rows=json.loads(driver.DATASET.read_text());row=next(x for x in rows if x.get("id")=="rev7");right=normalize(row["ciphertext"])
 assert left==right and len(left)==1092 and hashlib.sha256(left.encode()).hexdigest()==EXPECTED_TEXT_SHA
 assert hashlib.sha256(row["ciphertext"].encode()).hexdigest()==EXPECTED_DATASET_FIELD_SHA
 pairs=[left[i:i+2] for i in range(0,len(left),2)]
 return left,{"forward":left,"full_hex_reverse":left[::-1],"byte_reverse":"".join(reversed(pairs)),"nibble_swap":"".join(pair[::-1] for pair in pairs)}

def verify(path):
 assert sha(path)==EXPECTED_RESULT_SHA,(sha(path),EXPECTED_RESULT_SHA)
 assert sha(DRIVER)==EXPECTED_DRIVER_SHA
 driver=load("astra_utf8_result_driver",DRIVER);gate,gate_sha,_controls=driver.require_gate()
 assert gate_sha==EXPECTED_GATE_SHA and sha(driver.MDX)==EXPECTED_MDX_SHA and sha(driver.DATASET)==EXPECTED_DATASET_SHA
 text,oriented=canonical(driver);data=json.loads(path.read_text())
 assert data["identity"]=="ASTRA" and data["target_evaluated"] is True and data["status"]=="complete"
 config=data["configuration"];assert config["gate_sha256"]==EXPECTED_GATE_SHA and config["driver_sha256"]==EXPECTED_DRIVER_SHA
 assert config["mdx_sha256"]==EXPECTED_MDX_SHA and config["dataset_sha256"]==EXPECTED_DATASET_SHA and config["canonical_text_sha256"]==EXPECTED_TEXT_SHA and config["dataset_ciphertext_field_sha256"]==EXPECTED_DATASET_FIELD_SHA
 assert config["scope"]==driver.scope() and config["artifact_hashes"]==gate["artifact_hashes"] and config["controlled_source_hashes"]==gate["controlled_source_hashes"]
 expected_ids=[orientation+"|w"+str(width) for orientation in ORIENTATIONS for width in WIDTHS]
 assert [cell["cell_id"] for cell in data["cells"]]==expected_ids and len(data["cells"])==32
 total_orders=total_contexts=total_rejected=total_retained=total_blocks=total_gathered=0;reason_totals={}
 for cell,(orientation,width) in zip(data["cells"],((o,w) for o in ORIENTATIONS for w in WIDTHS)):
  orders=math.factorial(width);contexts=orders*10
  assert cell["identity"]=="ASTRA" and cell["orientation"]==orientation and cell["width"]==width and cell["start"]=="21"
  assert cell["observed_sha256"]==hashlib.sha256(oriented[orientation].encode()).hexdigest()
  assert cell["orders_examined"]==cell["expected_orders"]==orders and cell["unexamined_orders"]==0
  assert cell["backend_contexts_examined"]==cell["expected_backend_contexts"]==contexts and cell["unexamined_backend_contexts"]==0 and cell["complete_uncapped"] is True
  totals=cell["totals"];assert totals["orders"]==orders and totals["contexts"]==contexts and totals["rejected"]==contexts and totals["retained"]==0
  assert totals["rejected"]+totals["retained"]==contexts
  assert cell["first_row"]["order"]==list(range(width)) and cell["last_row"]["order"]==list(reversed(range(width)))
  for edge in (cell["first_row"],cell["last_row"]):
   assert edge["contexts"]==10 and edge["rejected"]==10 and not edge["retained"] and len(edge["rejection_witnesses"])==10
  assert cell["survivor_order_rows"]==[] and cell["independent_survivor_replays"]==[]
  assert len(cell["order_rows_ndjson_sha256"])==64 and len(cell["first_witness_rows_ndjson_sha256"])==64
  assert set(cell["rejection_reason_counts"])<=REASONS and sum(cell["rejection_reason_counts"].values())==contexts
  for reason,count in cell["rejection_reason_counts"].items():reason_totals[reason]=reason_totals.get(reason,0)+count
  assert cell["elapsed_seconds"]>=0
  total_orders+=orders;total_contexts+=contexts;total_rejected+=totals["rejected"];total_retained+=totals["retained"];total_blocks+=totals["block_callbacks"];total_gathered+=totals["gathered_ciphertext_bytes"]
 summary=data["summary"];assert summary["cells"]==32 and summary["orders_examined"]==total_orders==1636448 and summary["backend_contexts_examined"]==total_contexts==16364480
 assert summary["unexamined_orders"]==summary["unexamined_backend_contexts"]==0 and summary["retained_contexts"]==total_retained==0 and summary["rejected_contexts"]==total_rejected==16364480
 assert summary["block_callbacks"]==total_blocks==56740112 and summary["gathered_ciphertext_bytes"]==total_gathered==60583902
 assert summary["rejection_reason_counts"]==dict(sorted(reason_totals.items())) and set(reason_totals)==REASONS and sum(reason_totals.values())==total_contexts
 assert summary["all_complete_uncapped"] is True and summary["all_survivors_independently_replayed"] is True
 print(json.dumps({"identity":"ASTRA","verified":True,"verification":"portable source/integrity/accounting and stored boundary-row checks; not a second target enumeration","result_sha256":EXPECTED_RESULT_SHA,"gate_sha256":EXPECTED_GATE_SHA,"cells":32,"orders":total_orders,"contexts":total_contexts,"retained":0,"target_result_complete":True},indent=2))

def main():
 parser=argparse.ArgumentParser();parser.add_argument("--result",type=Path,default=RESULT);args=parser.parse_args();verify(args.result)
if __name__=="__main__":main()

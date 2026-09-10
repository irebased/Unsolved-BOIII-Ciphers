#!/usr/bin/env python3
"""Portable saved-result integrity/accounting verification; no DFS rerun."""
from __future__ import annotations
import hashlib,itertools,json,math
from pathlib import Path
HERE=Path(__file__).resolve().parent;HEX=HERE.parent;REPO=HERE.parents[3]
RESULT=HERE/"target_results.json";GATE=HERE/"target_gate.json";REV7=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
RESULT_SHA="5ee7d589b4917f53f87c4c6b503a4661604b7744f9f1b013bf49a38ddd7454fc";GATE_SHA="bb17ddfba28a84622320e1512fcc7bea157754f9b5b7820c6b8a0a70e61f45e3";DRIVER_SHA="31b5eedd01f3d05f392cc5b7e52e87ebae1f538ac1436647004ec695067fabfb";FULL=math.factorial(16)
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def oriented(value):
 pairs=[value[i:i+2] for i in range(0,len(value),2)]
 return {"forward":value,"reverse":value[::-1],"byte_reverse":"".join(reversed(pairs)),"nibble_swap":"".join(x[::-1] for x in pairs)}
def main():
 assert sha(RESULT)==RESULT_SHA and sha(GATE)==GATE_SHA and sha(HERE/"run_target.py")==DRIVER_SHA
 gate=json.loads(GATE.read_text());result=json.loads(RESULT.read_text())
 assert gate["identity"]=="ASTRA" and gate["authorized"] is True and gate["target_evaluated"] is False
 for rel,h in gate["extension_hashes"].items():assert sha(HERE/rel)==h,(rel,sha(HERE/rel),h)
 for rel,h in gate["artifact_hashes"].items():
  p=REV7 if rel=="rev7_mdx" else (HEX/"prototype.py" if rel=="prototype.py" else HEX/"native_text5"/rel)
  assert sha(p)==h,(rel,sha(p),h)
 text=REV7.read_text();tick=chr(96);start=text.index(tick+"83 B57B2")+1;end=text.index(tick,start);value="".join(text[start:end].split()).upper()
 assert len(value)==1092 and hashlib.sha256(value.encode()).hexdigest()=="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
 orient=oriented(value);expected=list(itertools.product(("rc2","loki97"),("forward","reverse","byte_reverse","nibble_swap")))
 assert result["identity"]=="ASTRA" and result["target_evaluated"] is True and result["status"]=="complete"
 assert result["configuration"]["gate_sha256"]==GATE_SHA and result["configuration"]["driver_sha256"]==DRIVER_SHA
 assert [(x["cipher"],x["orientation"]) for x in result["cells"]]==expected
 total_seconds=0.0
 for row in result["cells"]:
  assert row["identity"]=="ASTRA" and row["display_sha256"]==hashlib.sha256(orient[row["orientation"]].encode()).hexdigest()
  s=row["stats"];assert s["node_limit"]==1_000_000_000 and 0<=s["nodes"]<=s["node_limit"]
  assert not s["aborted_at_node_limit"] and s["search_status"]=="complete" and s["certificate_complete"]
  assert s["expected_factorial_weight"]==FULL and s["certificate_weight"]==FULL and s["unaccounted_mapping_weight"]==0
  assert s["certificate_weight"]==s["rejected_completion_weight"]+s["terminal_completion_weight"]
  assert s["complete"]==row["survivor_count"]==len(row["survivors"])==0 and s["terminal_completion_weight"]==0
  assert row["all_survivors_independently_verified"] is True;total_seconds+=s["elapsed_seconds"]
 summary=result["summary"];assert summary["complete_cells"]==8 and summary["capped_cells"]==0 and summary["survivors"]==0 and abs(summary["total_elapsed_seconds"]-total_seconds)<1e-9
 print(json.dumps({"ok":True,"identity":"ASTRA","verification":"saved-result source integrity and factorial accounting; no second DFS search","result_sha256":RESULT_SHA,"gate_sha256":GATE_SHA,"cells":8,"complete_cells":8,"survivors":0,"per_cell_certificate_weight":FULL,"total_nodes":sum(x["stats"]["nodes"] for x in result["cells"]),"total_elapsed_seconds":total_seconds},indent=2,sort_keys=True))
if __name__=="__main__":main()

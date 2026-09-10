#!/usr/bin/env python3
"""ASTRA inert seven-cell even-block empty-rectangle target harness."""
from __future__ import annotations
import argparse,hashlib,itertools,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;REPO=HERE.parents[3]
MODEL=PACKAGE/"even_rectangle_controls/model.py";EVEN=PACKAGE/"even_target/target_results.json";FINAL=PACKAGE/"complete_periods/target_results.json";DATA=REPO/"lavender/src/data/ciphers/revelations.json";GATE=HERE/"target_gate.json";RESULT=HERE/"target_results.json"
sys.path.insert(0,str(MODEL.parent));import model
IDENTITY="ASTRA";TEXT_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c";DATA_SHA="68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e"
CELLS=(("forward",562),("forward",972),("reverse",16),("reverse",514),("byte_reverse",16),("nibble_swap",850),("nibble_swap",972))
REQUIRED={"research/rev7-20260909-codex/bifid16_controls/even_rectangle_controls/model.py","research/rev7-20260909-codex/bifid16_controls/even_rectangle_controls/controls.py","research/rev7-20260909-codex/bifid16_controls/even_rectangle_controls/controls.json","research/rev7-20260909-codex/bifid16_controls/even_period_invariant.py","research/rev7-20260909-codex/bifid16_controls/even_target/target_results.json","research/rev7-20260909-codex/bifid16_controls/complete_periods/target_results.json","research/rev7-20260909-codex/bifid16_controls/even_rectangle_target/run_target.py","research/rev7-20260909-codex/bifid16_controls/even_rectangle_target/driver_controls.py","research/rev7-20260909-codex/bifid16_controls/even_rectangle_target/driver_controls.json"}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def orient(value,name):
 pairs=[value[i:i+2] for i in range(0,len(value),2)]
 if name=="forward":return value
 if name=="reverse":return value[::-1]
 if name=="byte_reverse":return "".join(reversed(pairs))
 if name=="nibble_swap":return "".join(x[::-1] for x in pairs)
 raise ValueError(name)
def require_gate():
 if not GATE.exists():raise SystemExit("inert: root-created target_gate.json absent")
 g=json.loads(GATE.read_text());assert g["identity"]==IDENTITY and g["target_authorized"] is True and g["cells"]==[[o,p] for o,p in CELLS]
 assert g["scope"]=="seven even Bifid16 bag213 residuals; empty arbitrary 4x4 pair rectangle"
 assert set(g["artifact_hashes"])==set(g["required_artifacts"]) and REQUIRED<=set(g["artifact_hashes"])
 for rel,digest in g["artifact_hashes"].items():assert sha(REPO/rel)==digest,rel
 assert g["dataset_sha256"]==sha(DATA)==DATA_SHA and g["canonical_hex_sha256"]==TEXT_SHA
 return g
def extract():
 rows=json.loads(DATA.read_text());row=next(x for x in rows if x.get("number")==7);assert row["id"]=="rev7";value="".join(row["ciphertext"].split()).upper();assert len(value)==1092 and hashlib.sha256(value.encode()).hexdigest()==TEXT_SHA;return value
def direct_pairs(value,period):
 pairs=[];lengths=[]
 for start in range(0,len(value),period):
  block=value[start:start+period];assert len(block)%2==0;lengths.append(len(block));half=len(block)//2;pairs.extend(zip(block[:half],block[half:]))
 assert len(pairs)==546
 stream=bytes((int(a,16)<<4)|int(b,16) for a,b in pairs);hist=[0]*256
 for x in stream:hist[x]+=1
 return pairs,lengths,stream,hist
def slow_analysis(edges):
 edge=set(edges);records=[];best=None
 for aset in itertools.combinations(range(16),4):
  missing=[b for b in range(16) if all((a,b) not in edge for a in aset)];mask=sum(1<<b for b in missing);row={"row_set":list(aset),"common_missing_columns_mask":f"{mask:04x}","common_missing_count":len(missing)};records.append(row)
  if best is None or len(missing)>best[0]:best=(len(missing),aset,missing)
 witness=None
 if best[0]>=4:witness={"row_set":list(best[1]),"column_set":best[2][:4],"all_16_directed_edges_absent":all((a,b) not in edge for a in best[1] for b in best[2][:4])}
 return {"directed_edge_count":len(edge),"adjacency_masks":[f"{sum(1<<b for x,b in edge if x==a):04x}" for a in range(16)],"row_sets_examined":len(records),"row_set_records":records,"max_common_missing_count":best[0],"empty_4x4_rectangle_exists_relaxed":best[0]>=4,"witness":witness,"excluded_bag213":best[0]<4}
def upstream_index():
 even=json.loads(EVEN.read_text());idx={("reverse" if x["orientation"]=="full_hex_reverse" else x["orientation"],x["period"]):x for x in even["cells"]};assert len(idx)==2184
 final=json.loads(FINAL.read_text());unknown={(x["orientation"],x["period"]) for x in final["cells"] if x["status"]=="unknown"};assert unknown==set(CELLS)
 assert all(idx[cell]["bound_213"]=="unresolved" for cell in CELLS);return idx
def cell(value,orientation,period,upstream=None,slow=False):
 oriented=orient(value,orientation);pairs,lengths,stream,hist=direct_pairs(oriented,period);edges={(int(a,16),int(b,16)) for a,b in pairs};analysis=slow_analysis(edges) if slow else model.analyze(edges)
 if upstream is not None:
  assert upstream["orientation_sha256"]==hashlib.sha256(oriented.encode()).hexdigest() and upstream["pair_stream_sha256"]==hashlib.sha256(stream).hexdigest() and upstream["pair_count"]==len(pairs)==546 and upstream["histogram"]==hist and upstream["distinct_pair_count"]==sum(x>0 for x in hist) and upstream["actual_block_lengths"]==lengths
 return {"cell_id":f"{orientation}_p{period}","orientation":orientation,"period":period,"orientation_sha256":hashlib.sha256(oriented.encode()).hexdigest(),"pair_count":len(pairs),"pair_stream_sha256":hashlib.sha256(stream).hexdigest(),"histogram":hist,"distinct_pair_count":sum(x>0 for x in hist),"actual_block_lengths":lengths,"upstream_even_row_exact":upstream is not None,"upstream_bound_213":upstream["bound_213"] if upstream else None,"analysis":analysis,"status":"excluded_bag213" if analysis["excluded_bag213"] else "empty_rectangle_unresolved"}
def compute(value,slow=False):
 idx=upstream_index();return [cell(value,o,p,idx[(o,p)],slow) for o,p in CELLS]
def main():
 ap=argparse.ArgumentParser();m=ap.add_mutually_exclusive_group();m.add_argument("--selftest",action="store_true");m.add_argument("--run-target",action="store_true");m.add_argument("--verify",action="store_true");a=ap.parse_args();gate=require_gate()
 if a.selftest or not(a.run_target or a.verify):print(json.dumps({"identity":IDENTITY,"target_evaluated":False,"gate":"PASS","cells":7}));return
 if a.run_target and (RESULT.exists() or RESULT.with_name(RESULT.name+".tmp").exists()):raise SystemExit("refusing existing result/tmp")
 value=extract();rows=compute(value,slow=a.verify);result={"identity":IDENTITY,"target_evaluated":True,"status":"complete","gate_sha256":sha(GATE),"driver_sha256":sha(Path(__file__)),"canonical_hex_sha256":TEXT_SHA,"cells":rows,"counts":{"total":7,"excluded_bag213":sum(x["status"]=="excluded_bag213" for x in rows),"empty_rectangle_unresolved":sum(x["status"]!="excluded_bag213" for x in rows)},"limits":"max<4 excludes the exact fixed-square/two-fixed-square constructions under bag213; max>=4 is unresolved. Seven registered even cells only."}
 if a.verify:
  assert result==json.loads(RESULT.read_text());print(json.dumps({"identity":IDENTITY,"verification_only":True,"slow_direct_all_1820":"PASS","result_sha256":sha(RESULT)}));return
 tmp=RESULT.with_name(RESULT.name+".tmp");tmp.write_text(json.dumps(result,sort_keys=True,indent=2)+"\n");os.replace(tmp,RESULT);print(json.dumps({"identity":IDENTITY,"result_sha256":sha(RESULT),"counts":result["counts"]}))
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Read-only integrity/accounting audit of captured FABLE cascade3 evidence."""
from __future__ import annotations
import argparse,hashlib,json,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent;UP=HERE/"upstream";OUT=HERE/"audit.json";CONTROLS=HERE/"controls.json"
EXPECTED={"cascade3/scan3.js":"f502c413da81a6ca8d6acd7083c657787c70f67f725d551952296b915003a6ec","cascade3/run3.js":"e4a9d224da58ccbb8d12c32f512eecb8d1c1e8acc5c2bef9f2d0d87741d2ae66","cascade3/make_plant3.js":"f4728dc92deab2024e03b93ec867c137bb798f7188bc6b34e0501c736f914516","cascade3/results.json":"4cf0f165d7659135b7b5230a15dedce880b8994a071d4adeab5ce269edfcef70","cascade/cascade_lib.js":"0318a5b86eb9b93f6cfa848ac9c58a59e6ea05acb469b2d49569a840034c3aff","dictkey2/lib.js":"ffba90a95de78bdeef64c8d2b5602c61d3271e7780914d8322cc5bb9b912ec1d","utf8gate/utf8gate.js":"23eaf0741eecf23fedbe1a9c9a241c715f5d5a9d936689d2c70d440cb6121b8d"}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,indent=2)+"\n"
def node_controls():return json.loads(subprocess.check_output(["node",str(HERE/"controls.js")],cwd=HERE))
def histogram_ok(section):
 h=section["histogram"];return h["n"]==section["chainsScored"]==sum(h["byLongestRun"].values())==sum(h["byValidCountBucket20"].values())
def build():
 assert {rel:sha(UP/rel) for rel in EXPECTED}==EXPECTED
 saved=json.loads((UP/"cascade3/results.json").read_text());controls=node_controls();assert controls==json.loads(CONTROLS.read_text())
 per=46**3*16;total=4*per
 assert saved["searchSpace"]=={"layerOptionsPerLayer":46,"totalChainsSpec":total}
 pos=saved["positiveControl"];neg=saved["negativeControl"];target=saved["rev7"]
 assert pos["chainsScored"]==per and pos["target"]["found"] and pos["target"]["rank"]==1 and pos["target"]["score"]["longestRun"]==316 and pos["target"]["score"]["validCount"]==316
 assert neg["chainsScored"]==target["chainsScored"]==total
 expected_or={"displayed","fullReversed","bytePairReversed","nibbleSwap"}
 assert set(neg["perOrientation"])==set(target["perOrientation"])==expected_or and all(x["count"]==per for x in neg["perOrientation"].values()) and all(x["count"]==per for x in target["perOrientation"].values())
 assert histogram_ok(neg) and histogram_ok(target)
 target_max=max(map(int,target["histogram"]["byLongestRun"]));negative_max=max(map(int,neg["histogram"]["byLongestRun"]));assert target_max==21 and negative_max==23 and target["top10"][0]["longestRun"]==21
 return {"identity":"ASTRA","new_target_search":False,"upstream_target_result_inspected":True,"independent_cipher_replay":False,"captured_sources":[{"path":rel,"bytes":(UP/rel).stat().st_size,"sha256":EXPECTED[rel]} for rel in sorted(EXPECTED)],"declared_model":{"options_per_layer_reported":46,"depth":3,"reverse_boundaries":4,"reverse_masks":16,"orientations":4,"per_orientation_expected":per,"full_expected":total,"mode":"CFB8 reported as integer0","iv":"ASCII 0 repeated to block size","literal_keys":["Zombies","ZOMBIES"],"loki97_key":"32-byte zero buffer with literal ASCII key copied at start"},"saved_result_accounting":{"positive_control":{"chains":pos["chainsScored"],"reported_true_chain_rank":1,"reported_max_longest_run":316,"tie_count":pos["target"]["tieCount"]},"negative":{"chains":neg["chainsScored"],"per_orientation_counts":neg["perOrientation"],"histograms_sum":True,"max_longest_run":negative_max},"rev7":{"chains":target["chainsScored"],"per_orientation_counts":target["perOrientation"],"histograms_sum":True,"max_longest_run":target_max},"full_grid_arithmetic":total},"synthetic_scoretail_controls":controls,"source_hashes":{"audit.py":sha(Path(__file__)),"controls.js":sha(HERE/"controls.js"),"controls.json":sha(CONTROLS)},"missing_for_independent_full_replay":["cascade/scan.js (defines LAYER_OPTS and blockSizeFor)","cascade3/plant3_hex.txt and plant3_plaintext.txt","cascade/negative_seed_hex.txt","pinned mcrypt.js/WASM runtime and build evidence","independently pinned exact Rev7 input used by this run"],"limits":"Counts, rankings, maxima, and cipher scope are saved-result/source consistency findings. No cipher output, target maximum, planted rank, or null-band conclusion was independently recomputed."}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--regenerate",type=Path);a=ap.parse_args();got=build()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit(f"refusing existing output: {a.regenerate}")
  a.regenerate.write_text(canonical(got));print(json.dumps({"identity":"ASTRA","output":str(a.regenerate),"sha256":sha(a.regenerate)}));return
 assert got==json.loads(OUT.read_text());print(json.dumps({"identity":"ASTRA","verified":True,"ledger_sha256":sha(OUT),"saved_grid":4*46**3*16,"independent_full_replay":False}))
if __name__=="__main__":main()

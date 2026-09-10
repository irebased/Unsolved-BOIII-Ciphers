#!/usr/bin/env python3
from pathlib import Path
import argparse,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];sys.path.insert(0,str(HERE));import run_target as d
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--fable-reference',required=True);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args()
 if a.output.exists():raise SystemExit('refusing existing gate')
 assert a.fable_reference.strip() and d.sha(d.MDX)==d.MDX_SHA and d.sha(d.DATA)==d.DATA_SHA and d.sha(d.PRIOR_RESULT)==d.PRIOR_RESULT_SHA and d.sha(d.PRIOR_GATE)==d.PRIOR_GATE_SHA
 ctl=json.loads((HERE/'controls.json').read_text());assert ctl['identity']=='ASTRA' and ctl['target_evaluated'] is False and all(ctl['assertions'].values()) and ctl['driver_sha256']==d.sha(HERE/'run_target.py') and ctl['parent_core_sha256']==d.CORE_SHA and ctl['parent_controls_source_sha256']==d.CONTROLS_SHA and ctl['parent_pack_sha256']==d.PACK_SHA and ctl['inventory_sha256']==d.INVENTORY_SHA and ctl['prior_result_sha256']==d.PRIOR_RESULT_SHA and ctl['prior_gate_sha256']==d.PRIOR_GATE_SHA
 artifacts={rel:d.sha(ROOT/rel) for rel in d.REQUIRED}
 out={'identity':'ASTRA','target_evaluated':False,'authorization':'external preregistration; separate root GO required','fable_reference':a.fable_reference,'scope':d.scope(),'driver_sha256':d.sha(HERE/'run_target.py'),'core_sha256':d.CORE_SHA,'controls_source_sha256':d.CONTROLS_SHA,'packed_controls_sha256':d.PACK_SHA,'inventory_sha256':d.INVENTORY_SHA,'prior_result_sha256':d.PRIOR_RESULT_SHA,'prior_gate_sha256':d.PRIOR_GATE_SHA,'mdx_sha256':d.MDX_SHA,'dataset_sha256':d.DATA_SHA,'canonical_text_sha256':d.TEXT_SHA,'artifact_hashes':artifacts}
 a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(d.sha(a.output))
if __name__=='__main__':main()

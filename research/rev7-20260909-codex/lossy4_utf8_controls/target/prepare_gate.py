#!/usr/bin/env python3
"""Create a frozen target gate only after external preregistration and separate review."""
from pathlib import Path
import argparse,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];sys.path.insert(0,str(HERE));import run_target as d
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--fable-reference',required=True);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args()
 if a.output.exists():raise SystemExit('refusing existing gate')
 if d.RESULT.exists() or d.RESULT.with_suffix('.json.tmp').exists():raise SystemExit('refusing while target output exists')
 assert a.fable_reference.strip() and d.sha(d.MDX)==d.MDX_SHA and d.sha(d.DATA)==d.DATA_SHA
 ctl=json.loads((HERE/'controls.json').read_text());assert ctl['identity']=='ASTRA' and ctl['target_evaluated'] is False and all(ctl['assertions'].values()) and ctl['driver_sha256']==d.sha(HERE/'run_target.py')
 assert ctl['parent']['core_sha256']==d.CORE_SHA and ctl['parent']['controls_source_sha256']==d.CONTROLS_SHA and ctl['parent']['pack_source_sha256']==d.PACK_SOURCE_SHA and ctl['parent']['packed_controls_sha256']==d.PACK_SHA
 assert ctl['parent']['full_all_roots_control']['status']=='INCOMPLETE' and ctl['parent']['full_all_roots_control']['accepted_states']==d.MAX_ACCEPTED and ctl['parent']['full_all_roots_control']['truth_retained_exactly_once'] is None
 assert ctl['seeded']['source_sha256']==d.SEEDED_SOURCE_SHA and ctl['seeded']['ledger_sha256']==d.SEEDED_LEDGER_SHA and ctl['seeded']['report_sha256']==d.SEEDED_REPORT_SHA and ctl['seeded']['initial_registers_total']==1 and ctl['seeded']['truth_retained_exactly_once'] is True
 artifacts={rel:d.sha(ROOT/rel) for rel in d.REQUIRED};assert set(artifacts)==set(d.REQUIRED)
 out={'identity':'ASTRA','target_evaluated':False,'authorization':'external preregistration; separate root GO required','fable_reference':a.fable_reference,'scope':d.scope(),'driver_sha256':d.sha(HERE/'run_target.py'),'core_sha256':d.CORE_SHA,'controls_source_sha256':d.CONTROLS_SHA,'packed_controls_sha256':d.PACK_SHA,'seeded_source_sha256':d.SEEDED_SOURCE_SHA,'seeded_ledger_sha256':d.SEEDED_LEDGER_SHA,'inventory_sha256':d.INVENTORY_SHA,'mdx_sha256':d.MDX_SHA,'dataset_sha256':d.DATA_SHA,'canonical_text_sha256':d.TEXT_SHA,'artifact_hashes':artifacts}
 a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(d.sha(a.output))
if __name__=='__main__':main()

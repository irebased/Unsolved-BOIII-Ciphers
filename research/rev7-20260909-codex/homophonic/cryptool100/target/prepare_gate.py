#!/usr/bin/env python3
"""Create a gate only after root supplies a FABLE preregistration reference."""
from pathlib import Path
import argparse,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4];sys.path.insert(0,str(HERE));import run_target as d
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--fable-reference',required=True);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args()
 if a.output.exists():raise SystemExit('refusing existing gate output')
 assert a.fable_reference.strip() and d.sha(d.MDX)==d.MDX_SHA and d.sha(d.DATA)==d.DATA_SHA
 ctl=json.loads((HERE/'controls.json').read_text());assert ctl['identity']=='ASTRA' and ctl['target_evaluated'] is False and ctl['assertions']['all_passed'] and ctl['driver_sha256']==d.sha(HERE/'run_target.py')
 artifacts={rel:d.sha(ROOT/rel) for rel in d.REQUIRED}
 out={'identity':'ASTRA','target_evaluated':False,'authorization':'FABLE preregistered; separate root GO required','fable_reference':a.fable_reference,'scope':d.scope(),'driver_sha256':d.sha(HERE/'run_target.py'),'mdx_sha256':d.MDX_SHA,'canonical_text_sha256':d.TEXT_SHA,'dataset_sha256':d.DATA_SHA,'artifact_hashes':artifacts}
 a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(d.sha(a.output))
if __name__=='__main__':main()

#!/usr/bin/env python3
from pathlib import Path
import argparse,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4];sys.path.insert(0,str(HERE));import run_target as d
def main():
 a=argparse.ArgumentParser();a.add_argument('--fable-reference',required=True);a.add_argument('--output',required=True,type=Path);x=a.parse_args()
 if x.output.exists():raise SystemExit('refusing existing gate')
 assert x.fable_reference.strip() and d.sha(d.MDX)==d.MDX_SHA and d.sha(d.DATA)==d.DATA_SHA
 ctl=json.loads((HERE/'controls.json').read_text());assert ctl['identity']=='ASTRA' and ctl['target_evaluated'] is False and ctl['driver_sha256']==d.sha(HERE/'run_target.py') and all(ctl['assertions'].values())
 artifacts={rel:d.sha(ROOT/rel) for rel in d.REQUIRED};out={'identity':'ASTRA','target_evaluated':False,'authorization':'external preregistration; separate root GO required','fable_reference':x.fable_reference,'scope':d.scope(),'driver_sha256':d.sha(HERE/'run_target.py'),'mdx_sha256':d.MDX_SHA,'canonical_text_sha256':d.TEXT_SHA,'dataset_sha256':d.DATA_SHA,'artifact_hashes':artifacts}
 x.output.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(d.sha(x.output))
if __name__=='__main__':main()
